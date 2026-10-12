#!/usr/bin/env python3
# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Record isolated delayed-GOAWAY evidence, never live acceptance.

D1--D4 may pass in process. W0--W4 still require real transport evidence,
and original E1 is never passed by this different hypothesis. Exit 2 means
blocked live acceptance; exit 1 means pure checks or evidence collection failed.
No proxy, TLS socket, origin, or IPC transport is started by this runner.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import platform
import shlex
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "components/egress/tests/fixtures"
BASE_SHA = "65f621b7bbefc5f914e76998b87973fce877cb8c"
MODE = "in-process-delayed-goaway-experiment"
PURE_REQUIRED = ("D1", "D2", "D3", "D4")
REQUIRED = ("W0", "W1", "W2", "W3", "W4")
DEPENDENCIES = ("mitmproxy", "h2", "hyperframe")
SOURCE_PATHS = (
    "components/egress/scripts/h2_delayed_goaway_probe.py",
    "components/egress/scripts/test_h2_delayed_goaway_probe.py",
    "components/egress/tests/fixtures/h2_delayed_goaway_probe.py",
    "components/egress/tests/test_h2_delayed_goaway.py",
    "docs/architecture/network/osep-0023-h2-delayed-goaway.md",
)
EVIDENCE = ["experiment-findings.json", "probe-events.jsonl"]
LIVE_REASONS = (
    "W0 real TLS negative baseline and client stream IDs were not run",
    "W1 real admission fence, REFUSED_STREAM and no post-fence origin dispatch are untested",
    "W2 client-wire END_STREAM before GOAWAY requires real TLS flush and client receipt evidence",
    "W3 revision commit/admission races through real IPC were not run",
    "W4 real reset/disconnect cleanup and the 30-second drain deadline were not run",
)
UNPROVEN_CLAIMS = (
    "original_E1_passed", "live_transport_executed", "real_wire_executed",
    "client_wire_evidence", "client_socket_evidence", "real_ipc_executed",
    "tls_transport_executed", "origin_transport_executed", "production_ready",
    "transport_feasible",
)


def dependency_versions() -> dict:
    versions = {}
    for name in DEPENDENCIES:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return versions


def git_metadata() -> tuple[dict, bytes]:
    """Record HEAD and the five-path working delta, including new files."""
    def git(*args, allowed=(0,)):
        result = subprocess.run(
            ["git", "-C", str(ROOT), *args], capture_output=True, timeout=10,
        )
        if result.returncode not in allowed:
            raise RuntimeError("git provenance collection failed")
        return result.stdout

    head = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    base = git("rev-parse", "--verify", BASE_SHA + "^{commit}").decode().strip()
    base_tree = git("rev-parse", BASE_SHA + "^{tree}").decode().strip()
    if base != BASE_SHA or any(
            len(value) != 40 or any(char not in "0123456789abcdef" for char in value)
            for value in (head, tree, base_tree)):
        raise RuntimeError("git provenance is incomplete")
    diff = git("diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD", "--", *SOURCE_PATHS)
    untracked = git("ls-files", "--others", "--exclude-standard", "-z", "--", *SOURCE_PATHS)
    for path in untracked.decode().split("\0"):
        if path:
            if path not in SOURCE_PATHS:
                raise RuntimeError("git diff escaped the task source scope")
            diff += git("diff", "--no-ext-diff", "--no-textconv", "--binary", "--no-index",
                        "--", "/dev/null", path, allowed=(0, 1))
    return {
        "base_sha": base, "base_tree_sha": base_tree,
        "head_sha": head, "tree_sha": tree, "dirty": bool(diff),
        "dirty_diff_base": head, "dirty_diff_scope": list(SOURCE_PATHS),
        "dirty_diff_file": "dirty.diff", "dirty_diff_sha256": hashlib.sha256(diff).hexdigest(),
    }, diff


def inspect_delayed_transport() -> dict:
    # The fixture intentionally shares this filename. Register a unique alias
    # while loading it so dataclasses also resolve their owning module safely.
    alias = "_h2_delayed_goaway_experiment_fixture"
    spec = importlib.util.spec_from_file_location(alias, FIXTURES / "h2_delayed_goaway_probe.py")
    module = importlib.util.module_from_spec(spec)
    old_path, old_module = sys.path[:], sys.modules.get(alias)
    try:
        sys.path.insert(0, str(FIXTURES))
        sys.modules[alias] = module
        spec.loader.exec_module(module)
        return module.inspect_delayed_transport()
    finally:
        sys.path[:] = old_path
        if old_module is None:
            sys.modules.pop(alias, None)
        else:
            sys.modules[alias] = old_module


def reject_live_claims(value) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in UNPROVEN_CLAIMS and item is not False:
                raise ValueError("in-process evidence cannot claim original E1 or live acceptance")
            if key == "provenance" and item != MODE:
                raise ValueError("evidence provenance must remain in-process")
            reject_live_claims(item)
    elif isinstance(value, list):
        for item in value:
            reject_live_claims(item)


def validate_cases(cases, required, statuses) -> None:
    if (not isinstance(cases, list) or len(cases) != len(required)
            or any(not isinstance(case, dict) for case in cases)
            or [case.get("id") for case in cases] != list(required)):
        raise ValueError("required case denominator is incomplete, duplicated or out of order")
    for case in cases:
        if (case.get("status") not in statuses or not isinstance(case.get("reason"), str)
                or not case["reason"].strip()):
            raise ValueError("case status or reason is invalid")


def validate_report(report: dict, versions: dict) -> None:
    if (not isinstance(report, dict) or type(report.get("schema_version")) is not int
            or report["schema_version"] != 1 or report.get("mode") != MODE
            or report.get("dependencies") != versions
            or report.get("original_E1_passed") is not False
            or report.get("live_transport_executed") is not False):
        raise ValueError("experiment metadata does not match this in-process run")
    validate_cases(report.get("cases"), PURE_REQUIRED, ("pass", "fail"))
    reject_live_claims(report)
    events = report.get("events")
    if not isinstance(events, list) or not events:
        raise ValueError("experiment events are missing")
    previous_ns = 0
    for sequence, event in enumerate(events, 1):
        if (not isinstance(event, dict) or type(event.get("sequence")) is not int
                or event["sequence"] != sequence or event.get("provenance") != MODE
                or type(event.get("monotonic_ns")) is not int
                or event["monotonic_ns"] <= 0 or event["monotonic_ns"] < previous_ns):
            raise ValueError("event provenance, sequence or monotonic time is invalid")
        previous_ns = event["monotonic_ns"]
    json.dumps(report, allow_nan=False)


def blocked_report(versions: dict, reason: str) -> dict:
    return {
        "schema_version": 1, "mode": MODE, "dependencies": versions,
        "original_E1_passed": False, "live_transport_executed": False,
        "cases": [{"id": case, "status": "blocked", "reason": reason} for case in PURE_REQUIRED],
        "events": [{"sequence": 1, "monotonic_ns": time.monotonic_ns(),
                    "provenance": MODE, "kind": "experiment_blocked", "reason": reason}],
    }


def make_results(report: dict, failed: bool) -> dict:
    return {
        "schema_version": 1, "mode": MODE, "status": "failed" if failed else "blocked",
        "original_E1_passed": False, "live_transport_executed": False,
        "real_wire_executed": False, "transport_feasible": False,
        "pure_required_cases": list(PURE_REQUIRED), "pure_cases": report["cases"],
        "required_cases": list(REQUIRED),
        "cases": [{
            "id": case, "status": "not-run" if index == 0 else "blocked",
            "executed": False, "reason": LIVE_REASONS[index], "evidence": EVIDENCE,
        } for index, case in enumerate(REQUIRED)],
    }


def validate_results(results: dict, artifacts: Path) -> None:
    if (type(results.get("schema_version")) is not int or results["schema_version"] != 1
            or results.get("mode") != MODE or results.get("required_cases") != list(REQUIRED)
            or results.get("pure_required_cases") != list(PURE_REQUIRED)
            or results.get("status") not in ("blocked", "failed")):
        raise ValueError("experiment result denominator or status is invalid")
    for key in ("original_E1_passed", "live_transport_executed", "real_wire_executed", "transport_feasible"):
        if results.get(key) is not False:
            raise ValueError("experiment results must disclaim live acceptance")
    reject_live_claims(results)
    validate_cases(results.get("pure_cases"), PURE_REQUIRED, ("pass", "fail", "blocked"))
    validate_cases(results.get("cases"), REQUIRED, ("not-run", "blocked"))
    if any(case["status"] == "fail" for case in results["pure_cases"]) and results["status"] != "failed":
        raise ValueError("pure failure cannot be reported as merely blocked")
    for index, case in enumerate(results["cases"]):
        if (case["status"] != ("not-run" if index == 0 else "blocked")
                or case.get("executed") is not False or case.get("evidence") != EVIDENCE):
            raise ValueError("in-process evidence cannot pass or execute a real-wire case")
    for evidence in EVIDENCE:
        if not (artifacts / evidence).is_file():
            raise ValueError("referenced experiment evidence is missing")


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def run(artifacts: Path, command: list[str]) -> int:
    artifacts.mkdir(parents=True, exist_ok=False)
    versions = dependency_versions()
    manifest = {
        "schema_version": 1, "mode": MODE, "dependencies": versions,
        "python": {"version": platform.python_version(), "executable": sys.executable,
                   "implementation": platform.python_implementation()},
        "command": command, "command_shell": shlex.join(command),
        "working_directory": str(Path.cwd()), "exit_status": 2,
    }
    try:
        manifest["git"], diff = git_metadata()
        (artifacts / "dirty.diff").write_bytes(diff)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        manifest["git"] = {"base_sha": BASE_SHA, "status": "unavailable", "error_type": type(exc).__name__}
        manifest["exit_status"] = 1
    blockers = [f"missing dependency: {name}" for name, version in versions.items() if version is None]
    if versions.get("mitmproxy") not in (None, "11.0.2"):
        blockers.append("mitmproxy version mismatch: expected 11.0.2")
    if blockers:
        report = blocked_report(versions, "; ".join(blockers))
    else:
        try:
            report = inspect_delayed_transport()
            validate_report(report, versions)
            if any(case["status"] == "fail" for case in report["cases"]):
                manifest["exit_status"] = 1
        except ImportError as exc:
            report = blocked_report(versions, "dependency import failed: " + (exc.name or "unknown module"))
        except Exception as exc:
            report = blocked_report(versions, "experiment evidence failed: " + type(exc).__name__)
            manifest["exit_status"] = 1
    write_json(artifacts / EVIDENCE[0], {key: value for key, value in report.items() if key != "events"})
    (artifacts / EVIDENCE[1]).write_text("".join(
        json.dumps(event, sort_keys=True, allow_nan=False) + "\n" for event in report["events"]
    ))
    results = make_results(report, failed=manifest["exit_status"] == 1)
    validate_results(results, artifacts)
    write_json(artifacts / "results.json", results)
    write_json(artifacts / "cleanup.json", {
        "schema_version": 1, "status": "complete", "scope": MODE,
        "probe_subprocesses": "not-created", "probe_sockets": "not-created",
        "probe_temporary_directories": "not-created", "remaining_probe_resources": [],
        "git_metadata_subprocesses": "synchronous and reaped", "artifacts_retained": True,
    })
    write_json(artifacts / "manifest.json", manifest)
    return manifest["exit_status"]


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True, help="fresh evidence directory; must not exist")
    args = parser.parse_args(argv)
    try:
        return run(args.artifacts, [sys.executable, str(Path(__file__).resolve()), *argv])
    except FileExistsError:
        parser.error("artifact directory already exists; choose a fresh path")
    except (OSError, ValueError) as exc:
        print("H2 delayed-GOAWAY evidence collection failed: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
