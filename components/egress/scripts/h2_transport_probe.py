#!/usr/bin/env python3
# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Write strict evidence for the H2 interface stop; never run a live proxy.

E0--E4 require real TLS/socket evidence. This in-process diagnostic cannot pass
any of them, even when its own assertions hold. Exit 2 means a blocked probe;
exit 1 means evidence collection failed. There is deliberately no success exit.
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
BASE_SHA = "b57f7db5a5608b396af173d29a8d873ed7fc761f"
MODE = "in-process-interface-diagnostic"
REQUIRED = ("E0", "E1", "E2", "E3", "E4")
DEPENDENCIES = ("mitmproxy", "h2", "hyperframe")
SOURCE_PATHS = (
    "components/egress/scripts/h2_transport_probe.py",
    "components/egress/scripts/test_h2_transport_probe.py",
    "components/egress/tests/fixtures/h2_transport_probe.py",
    "components/egress/tests/test_h2_transport_runtime.py",
    "docs/architecture/network/osep-0023-h2-transport-probe.md",
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
    """Capture only the named probe sources, including untracked additions."""
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
    # Disable external diff drivers: metadata must not execute user diff tools.
    diff = git("diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD", "--", *SOURCE_PATHS)
    untracked = git("ls-files", "--others", "--exclude-standard", "-z", "--", *SOURCE_PATHS)
    for path in untracked.decode().split("\0"):
        if path:
            diff += git("diff", "--no-ext-diff", "--no-textconv", "--binary", "--no-index",
                        "--", "/dev/null", path, allowed=(0, 1))
    return {
        "base_sha": base,
        "head_sha": head,
        "tree_sha": tree,
        "dirty": bool(diff),
        "dirty_diff_scope": list(SOURCE_PATHS),
        "dirty_diff_file": "dirty.diff",
        "dirty_diff_sha256": hashlib.sha256(diff).hexdigest(),
    }, diff


def inspect_transport() -> dict:
    # Use a distinct module name: the script and fixture intentionally share a
    # filename. Restore the search path even if a dependency import fails.
    spec = importlib.util.spec_from_file_location(
        "_h2_transport_interface_fixture", FIXTURES / "h2_transport_probe.py",
    )
    module = importlib.util.module_from_spec(spec)
    old_path = sys.path[:]
    try:
        sys.path.insert(0, str(FIXTURES))
        spec.loader.exec_module(module)
        return module.inspect_transport()
    finally:
        sys.path[:] = old_path


def validate_report(report: dict, versions: dict) -> None:
    """Reject mode drift or promotion of in-memory output to wire evidence."""
    if (not isinstance(report, dict) or report.get("schema_version") != 1
            or report.get("mode") != MODE or report.get("dependencies") != versions):
        raise ValueError("diagnostic metadata does not match this run")
    findings = report.get("findings")
    if (not isinstance(findings, dict) or not isinstance(findings.get("reason"), str)
            or not findings["reason"]
            or findings.get("live_transport_executed") is not False
            or findings.get("revision_cutover_executed") is not False
            or not isinstance(findings.get("normal_goaway_api_blocks_drain"), bool)):
        raise ValueError("diagnostic must explicitly disclaim live transport and cutover")
    for claims in (report, findings):
        if any(claims.get(key) is True for key in (
                "transport_feasible", "client_socket_evidence", "real_wire_executed")):
            raise ValueError("in-process findings cannot claim real-wire feasibility")
    events = report.get("events")
    if not isinstance(events, list) or not events:
        raise ValueError("diagnostic events are missing")
    for sequence, event in enumerate(events, 1):
        if (not isinstance(event, dict) or event.get("sequence") != sequence
                or event.get("provenance") != MODE):
            raise ValueError("diagnostic event provenance or sequence is invalid")
    json.dumps(report, allow_nan=False)


def blocked_report(versions: dict, reason: str) -> dict:
    return {
        "schema_version": 1, "mode": MODE, "dependencies": versions,
        "events": [{"sequence": 1, "monotonic_ns": time.monotonic_ns(),
                    "provenance": MODE, "kind": "diagnostic_blocked", "reason": reason}],
        "findings": {"normal_goaway_api_blocks_drain": None,
                     "live_transport_executed": False, "revision_cutover_executed": False,
                     "reason": reason},
    }


def make_results(reason: str) -> dict:
    return {
        "schema_version": 1, "mode": MODE, "status": "blocked",
        "required_cases": list(REQUIRED), "real_wire_executed": False,
        "transport_feasible": False,
        "cases": [{
            "id": case, "status": "not-run" if case == "E0" else "blocked",
            "executed": False,
            "reason": ("live negative baseline and stream-ID evidence were not run at the interface stop"
                       if case == "E0" else reason if case == "E1"
                       else "blocked by E1; live revision and cleanup experiments were not run"),
            "evidence": ["interface-findings.json", "probe-events.jsonl"],
        } for case in REQUIRED],
    }


def validate_results(results: dict, artifacts: Path) -> None:
    cases = results.get("cases", [])
    ids = [case.get("id") for case in cases]
    if (results.get("required_cases") != list(REQUIRED) or len(ids) != len(REQUIRED)
            or set(ids) != set(REQUIRED)):
        raise ValueError("required E0--E4 case denominator is incomplete or duplicated")
    if (results.get("real_wire_executed") is not False
            or results.get("transport_feasible") is not False
            or results.get("status") != "blocked"):
        raise ValueError("interface-only results cannot claim transport success")
    for case in cases:
        expected = "not-run" if case["id"] == "E0" else "blocked"
        if case.get("status") != expected or case.get("executed") is not False:
            raise ValueError("an in-process diagnostic cannot pass a real-wire case")
        if case.get("evidence") != ["interface-findings.json", "probe-events.jsonl"]:
            raise ValueError("results must reference actual diagnostic evidence only")
        for evidence in case["evidence"]:
            if not (artifacts / evidence).is_file():
                raise ValueError("referenced evidence file is missing")


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def run(artifacts: Path, command: list[str]) -> int:
    # A new directory is mandatory. Never overwrite or mix evidence runs.
    artifacts.mkdir(parents=True, exist_ok=False)
    versions = dependency_versions()
    manifest = {
        "schema_version": 1, "mode": MODE,
        "python": {"version": platform.python_version(), "executable": sys.executable,
                   "implementation": platform.python_implementation()},
        "dependencies": versions,
        # The only accepted option is a local artifact path. There are no
        # credential arguments, and environment values are never collected.
        "command": command, "command_shell": shlex.join(command),
        "working_directory": str(Path.cwd()), "exit_status": 2,
    }
    try:
        manifest["git"], diff = git_metadata()
        (artifacts / "dirty.diff").write_bytes(diff)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        manifest["git"] = {"base_sha": BASE_SHA, "status": "unavailable",
                           "error_type": type(exc).__name__}
        manifest["exit_status"] = 1

    blockers = [f"missing dependency: {name}" for name, version in versions.items() if version is None]
    if versions.get("mitmproxy") not in (None, "11.0.2"):
        blockers.append("mitmproxy version mismatch: expected 11.0.2")
    if blockers:
        report = blocked_report(versions, "; ".join(blockers))
    else:
        try:
            report = inspect_transport()
            validate_report(report, versions)
        except ImportError as exc:
            report = blocked_report(versions, "dependency import failed: " + (exc.name or "unknown module"))
        except Exception as exc:
            report = blocked_report(versions, "interface diagnostic failed: " + type(exc).__name__)
            manifest["exit_status"] = 1

    write_json(artifacts / "interface-findings.json", {
        key: value for key, value in report.items() if key != "events"
    })
    (artifacts / "probe-events.jsonl").write_text("".join(
        json.dumps(event, sort_keys=True, allow_nan=False) + "\n" for event in report["events"]
    ))
    results = make_results(report["findings"]["reason"])
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
    parser.add_argument("--artifacts", type=Path, required=True,
                        help="new, isolated evidence directory; must not already exist")
    args = parser.parse_args(argv)
    command = [sys.executable, str(Path(__file__).resolve()), *argv]
    try:
        return run(args.artifacts, command)
    except FileExistsError:
        parser.error("artifact directory already exists; choose a fresh path")
    except (OSError, ValueError) as exc:
        print("H2 evidence collection failed: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
