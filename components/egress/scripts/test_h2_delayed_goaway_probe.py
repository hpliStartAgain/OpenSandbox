# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Hermetic delayed-GOAWAY reporter tests; never run transport or sockets."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "h2_delayed_goaway_evidence_runner", Path(__file__).with_name("h2_delayed_goaway_probe.py"),
)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
VERSIONS = {"mitmproxy": "11.0.2", "h2": "4.1.0", "hyperframe": "6.0.1"}


def report():
    return {
        "schema_version": 1, "mode": runner.MODE, "dependencies": VERSIONS.copy(),
        "original_E1_passed": False, "live_transport_executed": False,
        "cases": [{"id": case, "status": "pass", "reason": "in-process assertion held"}
                  for case in runner.PURE_REQUIRED],
        "events": [{"sequence": 1, "monotonic_ns": 100, "provenance": runner.MODE,
                    "kind": "in_process_peer_output"}],
    }


class EvidenceRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="h2-delayed-evidence-test-")
        self.addCleanup(temporary.cleanup)
        self.artifacts = Path(temporary.name) / "evidence"
        self.command = ["python", "h2_delayed_goaway_probe.py", "--artifacts", str(self.artifacts)]
        self.versions = self.patch("dependency_versions", return_value=VERSIONS)
        self.probe = self.patch("inspect_delayed_transport", return_value=report())
        self.git = self.patch("git_metadata", return_value=({
            "base_sha": runner.BASE_SHA, "head_sha": "a" * 40, "tree_sha": "b" * 40,
            "dirty_diff_file": "dirty.diff", "dirty_diff_sha256": hashlib.sha256(b"diff").hexdigest(),
        }, b"diff"))

    def patch(self, name, **kwargs):
        patcher = mock.patch.object(runner, name, **kwargs)
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def read(self, name):
        return json.loads((self.artifacts / name).read_text())

    def test_pure_pass_cannot_pass_live_acceptance_or_original_e1(self):
        self.assertEqual(runner.run(self.artifacts, self.command), 2)
        result = self.read("results.json")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["pure_required_cases"], ["D1", "D2", "D3", "D4"])
        self.assertEqual([case["status"] for case in result["pure_cases"]], ["pass"] * 4)
        self.assertEqual(result["required_cases"], ["W0", "W1", "W2", "W3", "W4"])
        self.assertEqual([case["id"] for case in result["cases"]], result["required_cases"])
        self.assertEqual([case["status"] for case in result["cases"]], ["not-run"] + ["blocked"] * 4)
        self.assertFalse(any(case["executed"] for case in result["cases"]))
        self.assertIn("origin", result["cases"][1]["reason"])
        self.assertIn("END_STREAM before GOAWAY", result["cases"][2]["reason"])
        self.assertIn("real IPC", result["cases"][3]["reason"])
        self.assertIn("30-second", result["cases"][4]["reason"])
        for key in ("original_E1_passed", "live_transport_executed", "real_wire_executed", "transport_feasible"):
            self.assertIs(result[key], False)

    def test_manifest_and_cleanup_describe_actual_evidence(self):
        runner.run(self.artifacts, self.command)
        manifest = self.read("manifest.json")
        self.assertEqual(manifest["command"], self.command)
        self.assertEqual(manifest["dependencies"], VERSIONS)
        self.assertEqual(manifest["exit_status"], 2)
        self.assertEqual(manifest["git"]["base_sha"], "65f621b7bbefc5f914e76998b87973fce877cb8c")
        self.assertEqual(manifest["git"]["dirty_diff_sha256"],
                         hashlib.sha256((self.artifacts / "dirty.diff").read_bytes()).hexdigest())
        self.assertNotIn("environment", manifest)
        self.assertEqual(set(path.name for path in self.artifacts.iterdir()), {
            "manifest.json", "dirty.diff", "experiment-findings.json", "probe-events.jsonl",
            "results.json", "cleanup.json",
        })
        findings = self.read("experiment-findings.json")
        self.assertNotIn("events", findings)
        events = [json.loads(line) for line in (self.artifacts / "probe-events.jsonl").read_text().splitlines()]
        self.assertEqual(events, report()["events"])
        cleanup = self.read("cleanup.json")
        self.assertEqual(cleanup["probe_sockets"], "not-created")
        self.assertEqual(cleanup["probe_subprocesses"], "not-created")
        self.assertEqual(cleanup["remaining_probe_resources"], [])

    def test_pure_case_failure_is_exit_one_with_original_result_preserved(self):
        self.probe.return_value["cases"][1].update(status="fail", reason="old output was not drained")
        self.assertEqual(runner.run(self.artifacts, self.command), 1)
        result = self.read("results.json")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["pure_cases"][1]["reason"], "old output was not drained")
        self.assertEqual(self.read("manifest.json")["exit_status"], 1)

    def test_missing_dependency_blocks_without_running_fixture(self):
        self.versions.return_value = {**VERSIONS, "h2": None}
        self.assertEqual(runner.run(self.artifacts, self.command), 2)
        self.probe.assert_not_called()
        cases = self.read("results.json")["pure_cases"]
        self.assertEqual([case["status"] for case in cases], ["blocked"] * 4)
        self.assertTrue(all("missing dependency: h2" in case["reason"] for case in cases))

    def test_mismatched_actual_pin_blocks_without_running_fixture(self):
        self.versions.return_value = {**VERSIONS, "mitmproxy": "12.0.0"}
        self.assertEqual(runner.run(self.artifacts, self.command), 2)
        self.probe.assert_not_called()
        self.assertIn("expected 11.0.2", self.read("results.json")["pure_cases"][0]["reason"])

    def test_missing_transitive_import_is_structured_blocked(self):
        self.probe.side_effect = ModuleNotFoundError("missing", name="hpack")
        self.assertEqual(runner.run(self.artifacts, self.command), 2)
        self.assertIn("hpack", self.read("results.json")["pure_cases"][0]["reason"])

    def test_fixture_failure_still_records_all_cases_and_cleanup(self):
        self.probe.side_effect = RuntimeError("internal failure")
        self.assertEqual(runner.run(self.artifacts, self.command), 1)
        result = self.read("results.json")
        self.assertEqual(len(result["pure_cases"]), 4)
        self.assertEqual(len(result["cases"]), 5)
        self.assertEqual(self.read("cleanup.json")["status"], "complete")

    def test_git_metadata_failure_cannot_be_reported_as_only_blocked(self):
        self.git.side_effect = RuntimeError("git unavailable")
        self.assertEqual(runner.run(self.artifacts, self.command), 1)
        self.assertEqual(self.read("results.json")["status"], "failed")
        self.assertEqual(self.read("manifest.json")["git"]["status"], "unavailable")
        self.assertFalse((self.artifacts / "dirty.diff").exists())

    def test_existing_directory_even_empty_is_not_overwritten(self):
        self.artifacts.mkdir()
        with self.assertRaises(FileExistsError):
            runner.run(self.artifacts, self.command)
        sentinel = self.artifacts / "manifest.json"
        sentinel.write_text("retain previous evidence")
        with self.assertRaises(FileExistsError):
            runner.run(self.artifacts, self.command)
        self.probe.assert_not_called()
        self.git.assert_not_called()
        self.assertEqual(sentinel.read_text(), "retain previous evidence")

    def test_malformed_fixture_metadata_is_failed_and_not_preserved(self):
        self.probe.return_value["events"][0]["provenance"] = "client-tls-socket"
        self.assertEqual(runner.run(self.artifacts, self.command), 1)
        findings = self.read("experiment-findings.json")
        self.assertFalse(findings["original_E1_passed"])
        self.assertFalse(findings["live_transport_executed"])
        self.assertNotIn("client-tls-socket", (self.artifacts / "probe-events.jsonl").read_text())

    def test_missing_pure_case_fails_instead_of_reducing_denominator(self):
        self.probe.return_value["cases"].pop()
        self.assertEqual(runner.run(self.artifacts, self.command), 1)
        self.assertEqual([case["id"] for case in self.read("results.json")["pure_cases"]],
                         list(runner.PURE_REQUIRED))

    def test_result_mutations_cannot_invent_real_proof(self):
        runner.run(self.artifacts, self.command)
        good = self.read("results.json")
        for change in ({"mode": "client-wire"}, {"schema_version": True}, {"status": "pass"},
                       {"pure_required_cases": ["D1"]}, {"pure_cases": good["pure_cases"][:1]}):
            bad = copy.deepcopy(good)
            bad.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner.validate_results(bad, self.artifacts)
        for change in ("missing", "duplicate", "extra", "pass", "executed", "skipped", "evidence"):
            with self.subTest(change=change):
                bad = copy.deepcopy(good)
                if change == "missing":
                    bad["cases"].pop()
                elif change == "duplicate":
                    bad["cases"][-1] = copy.deepcopy(bad["cases"][0])
                elif change == "extra":
                    bad["cases"].append({"id": "W5"})
                elif change == "executed":
                    bad["cases"][1]["executed"] = True
                elif change == "evidence":
                    bad["cases"][1]["evidence"] = ["client-wire.jsonl"]
                else:
                    bad["cases"][1]["status"] = change
                with self.assertRaises(ValueError):
                    runner.validate_results(bad, self.artifacts)
        for key in runner.UNPROVEN_CLAIMS:
            bad = copy.deepcopy(good)
            bad[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.validate_results(bad, self.artifacts)
        (self.artifacts / "probe-events.jsonl").unlink()
        with self.assertRaises(ValueError):
            runner.validate_results(good, self.artifacts)


class ReportValidationTests(unittest.TestCase):
    def test_accepts_pass_and_fail_but_no_other_pure_status(self):
        good = report()
        good["cases"][0]["status"] = "fail"
        runner.validate_report(good, VERSIONS)
        for status in ("blocked", "not-run", "skip", "passed", None, True):
            bad = report()
            bad["cases"][0]["status"] = status
            with self.subTest(status=status), self.assertRaises(ValueError):
                runner.validate_report(bad, VERSIONS)

    def test_missing_duplicate_extra_or_reordered_pure_cases_are_rejected(self):
        for change in ("missing", "duplicate", "extra", "reordered"):
            bad = report()
            if change == "missing":
                bad["cases"].pop()
            elif change == "duplicate":
                bad["cases"][-1] = bad["cases"][0]
            elif change == "extra":
                bad["cases"].append({"id": "D5", "status": "pass", "reason": "in process"})
            else:
                bad["cases"].reverse()
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner.validate_report(bad, VERSIONS)

    def test_metadata_and_reasons_are_strict(self):
        for change in ({"schema_version": 2}, {"schema_version": True}, {"mode": "client-wire"},
                       {"dependencies": {**VERSIONS, "mitmproxy": "12.0.0"}},
                       {"original_E1_passed": None}, {"live_transport_executed": "false"}):
            bad = report()
            bad.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner.validate_report(bad, VERSIONS)
        for reason in ("", " ", None, 1):
            bad = report()
            bad["cases"][0]["reason"] = reason
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                runner.validate_report(bad, VERSIONS)

    def test_events_require_sequence_monotonic_time_and_in_process_provenance(self):
        for change in ({"sequence": 2}, {"sequence": True}, {"provenance": "client-wire"},
                       {"monotonic_ns": None}, {"monotonic_ns": 0}, {"monotonic_ns": True}):
            bad = report()
            bad["events"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner.validate_report(bad, VERSIONS)
        bad = report()
        bad["events"].append({**bad["events"][0], "sequence": 2, "monotonic_ns": 99})
        with self.assertRaises(ValueError):
            runner.validate_report(bad, VERSIONS)
        bad["events"] = []
        with self.assertRaises(ValueError):
            runner.validate_report(bad, VERSIONS)

    def test_nested_live_claims_cannot_hide_in_findings_cases_or_events(self):
        for key in runner.UNPROVEN_CLAIMS:
            for location in ("findings", "cases", "events"):
                bad = report()
                if location == "findings":
                    bad[location] = {key: True}
                else:
                    bad[location][0][key] = True
                with self.subTest(key=key, location=location), self.assertRaises(ValueError):
                    runner.validate_report(bad, VERSIONS)


class ProvenanceTests(unittest.TestCase):
    def test_dependency_versions_records_real_package_metadata(self):
        with mock.patch.object(runner.importlib.metadata, "version", side_effect=[
            "11.0.2", runner.importlib.metadata.PackageNotFoundError("h2"), "6.0.1",
        ]) as versions:
            self.assertEqual(runner.dependency_versions(), {**VERSIONS, "h2": None})
        self.assertEqual([call.args[0] for call in versions.call_args_list], list(runner.DEPENDENCIES))

    def test_git_delta_is_exactly_five_paths_with_untracked_additions(self):
        path = runner.SOURCE_PATHS[0]
        outputs = [b"a" * 40, b"b" * 40, runner.BASE_SHA.encode(), b"c" * 40,
                   b"tracked diff\n", path.encode() + b"\0", b"untracked diff\n"]
        completed = [subprocess.CompletedProcess([], 1 if i == 6 else 0, output, b"")
                     for i, output in enumerate(outputs)]
        with mock.patch.object(runner.subprocess, "run", side_effect=completed) as git:
            metadata, diff = runner.git_metadata()
        self.assertEqual(diff, b"tracked diff\nuntracked diff\n")
        self.assertEqual(metadata["dirty_diff_sha256"], hashlib.sha256(diff).hexdigest())
        self.assertEqual(metadata["dirty_diff_scope"], list(runner.SOURCE_PATHS))
        self.assertEqual(len(runner.SOURCE_PATHS), 5)
        self.assertTrue(all("delayed_goaway" in path or "delayed-goaway" in path
                            for path in runner.SOURCE_PATHS))
        calls = [call.args[0] for call in git.call_args_list]
        self.assertEqual(calls[4][calls[4].index("--") + 1:], list(runner.SOURCE_PATHS))
        self.assertEqual(calls[-1][-3:], ["--", "/dev/null", path])
        self.assertIn("--no-ext-diff", calls[4])
        self.assertIn("--no-textconv", calls[4])
        self.assertTrue(all(call.kwargs["timeout"] == 10 for call in git.call_args_list))

    def test_git_metadata_rejects_bad_identity_and_out_of_scope_paths(self):
        good = [b"a" * 40, b"b" * 40, runner.BASE_SHA.encode(), b"c" * 40, b"", b""]
        for index, replacement in ((0, b"z" * 40), (2, b"a" * 40), (5, b"unrelated.py\0")):
            outputs = good.copy()
            outputs[index] = replacement
            completed = [subprocess.CompletedProcess([], 0, output, b"") for output in outputs]
            with self.subTest(index=index), mock.patch.object(runner.subprocess, "run", side_effect=completed):
                with self.assertRaises(RuntimeError):
                    runner.git_metadata()

    def test_fixture_loader_uses_unique_alias_and_restores_path(self):
        with tempfile.TemporaryDirectory(prefix="h2-delayed-loader-") as directory:
            path = Path(directory)
            (path / "h2_delayed_goaway_probe.py").write_text(
                "from dataclasses import dataclass\n"
                "@dataclass\nclass Result:\n    value: int = 1\n"
                "def inspect_delayed_transport():\n    return {'module': __name__, 'value': Result().value}\n"
            )
            old_path = sys.path[:]
            with mock.patch.object(runner, "FIXTURES", path):
                actual = runner.inspect_delayed_transport()
            self.assertEqual(actual["module"], "_h2_delayed_goaway_experiment_fixture")
            self.assertEqual(actual["value"], 1)
            self.assertEqual(sys.path, old_path)
            self.assertNotIn(actual["module"], sys.modules)


if __name__ == "__main__":
    unittest.main()
