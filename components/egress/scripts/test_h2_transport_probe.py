# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Hermetic evidence-runner tests; no sockets, proxy processes, or Docker."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "h2_transport_evidence_runner", Path(__file__).with_name("h2_transport_probe.py"),
)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)

VERSIONS = {"mitmproxy": "11.0.2", "h2": "4.1.0", "hyperframe": "6.0.1"}
REASON = "normal GOAWAY closes h2 state; existing mitmproxy layer cannot continue old streams"


def report():
    return {
        "schema_version": 1, "mode": runner.MODE, "dependencies": VERSIONS,
        "events": [{"sequence": 1, "provenance": runner.MODE, "kind": "dependency_operation"}],
        "findings": {"normal_goaway_api_blocks_drain": True,
                     "peer_also_rejects_post_goaway_data": True,
                     "live_transport_executed": False, "revision_cutover_executed": False,
                     "reason": REASON},
    }


class EvidenceRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="h2-evidence-test-")
        self.addCleanup(temporary.cleanup)
        self.artifacts = Path(temporary.name) / "evidence"
        self.command = ["python", "scripts/h2_transport_probe.py", "--artifacts", str(self.artifacts)]
        self.versions = self.patch("dependency_versions", return_value=VERSIONS)
        self.probe = self.patch("inspect_transport", return_value=report())
        self.git = self.patch("git_metadata", return_value=({
            "base_sha": runner.BASE_SHA, "head_sha": "head", "tree_sha": "tree",
            "dirty_diff_file": "dirty.diff", "dirty_diff_sha256": hashlib.sha256(b"diff").hexdigest(),
        }, b"diff"))

    def patch(self, name, **kwargs):
        patcher = mock.patch.object(runner, name, **kwargs)
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def read(self, name):
        return json.loads((self.artifacts / name).read_text())

    def test_interface_stop_has_complete_unexecuted_denominator_and_failure_exit(self):
        self.assertEqual(runner.run(self.artifacts, self.command), 2)
        results = self.read("results.json")
        self.assertEqual(results["required_cases"], ["E0", "E1", "E2", "E3", "E4"])
        self.assertEqual([case["id"] for case in results["cases"]], results["required_cases"])
        self.assertEqual([case["status"] for case in results["cases"]], ["not-run"] + ["blocked"] * 4)
        self.assertFalse(any(case["executed"] for case in results["cases"]))
        self.assertEqual(results["cases"][1]["reason"], REASON)
        self.assertTrue(all("blocked by E1" in case["reason"] for case in results["cases"][2:]))
        self.assertFalse(results["real_wire_executed"])
        self.assertFalse(results["transport_feasible"])

    def test_manifest_cleanup_and_actual_evidence_files(self):
        runner.run(self.artifacts, self.command)
        manifest = self.read("manifest.json")
        self.assertEqual(manifest["command"], self.command)
        self.assertEqual(manifest["dependencies"], VERSIONS)
        self.assertEqual(manifest["exit_status"], 2)
        self.assertEqual(manifest["git"]["dirty_diff_sha256"],
                         hashlib.sha256((self.artifacts / "dirty.diff").read_bytes()).hexdigest())
        self.assertNotIn("environment", manifest)
        self.assertEqual(set(path.name for path in self.artifacts.iterdir()), {
            "manifest.json", "dirty.diff", "interface-findings.json", "probe-events.jsonl",
            "results.json", "cleanup.json",
        })
        cleanup = self.read("cleanup.json")
        self.assertEqual(cleanup["probe_sockets"], "not-created")
        self.assertEqual(cleanup["probe_subprocesses"], "not-created")
        self.assertEqual(cleanup["remaining_probe_resources"], [])
        self.assertTrue(cleanup["artifacts_retained"])

    def test_missing_dependency_is_blocked_and_does_not_invoke_probe(self):
        self.versions.return_value = {**VERSIONS, "h2": None}
        self.assertEqual(runner.run(self.artifacts, self.command), 2)
        self.probe.assert_not_called()
        self.assertIn("missing dependency: h2", self.read("results.json")["cases"][1]["reason"])

    def test_mismatched_pin_is_blocked_and_does_not_invoke_probe(self):
        self.versions.return_value = {**VERSIONS, "mitmproxy": "12.0.0"}
        self.assertEqual(runner.run(self.artifacts, self.command), 2)
        self.probe.assert_not_called()
        self.assertIn("version mismatch", self.read("results.json")["cases"][1]["reason"])

    def test_missing_transitive_import_is_structured_and_blocked(self):
        self.probe.side_effect = ModuleNotFoundError("not installed", name="hpack")
        self.assertEqual(runner.run(self.artifacts, self.command), 2)
        self.assertIn("hpack", self.read("results.json")["cases"][1]["reason"])

    def test_unexpected_probe_failure_still_writes_denominator_and_cleanup(self):
        self.probe.side_effect = RuntimeError("internal failure")
        self.assertEqual(runner.run(self.artifacts, self.command), 1)
        self.assertEqual(len(self.read("results.json")["cases"]), 5)
        self.assertEqual(self.read("cleanup.json")["status"], "complete")
        self.assertEqual(self.read("manifest.json")["exit_status"], 1)

    def test_git_failure_is_not_success_and_does_not_invent_diff(self):
        self.git.side_effect = RuntimeError("git unavailable")
        self.assertEqual(runner.run(self.artifacts, self.command), 1)
        self.assertEqual(self.read("manifest.json")["git"]["status"], "unavailable")
        self.assertFalse((self.artifacts / "dirty.diff").exists())

    def test_existing_artifact_directory_is_never_overwritten(self):
        self.artifacts.mkdir()
        sentinel = self.artifacts / "manifest.json"
        sentinel.write_text("retain")
        with self.assertRaises(FileExistsError):
            runner.run(self.artifacts, self.command)
        self.probe.assert_not_called()
        self.git.assert_not_called()
        self.assertEqual(sentinel.read_text(), "retain")

    def test_empty_existing_directory_is_also_rejected(self):
        self.artifacts.mkdir()
        with self.assertRaises(FileExistsError):
            runner.run(self.artifacts, self.command)

    def test_missing_duplicate_extra_and_pass_cases_are_rejected(self):
        runner.run(self.artifacts, self.command)
        good = self.read("results.json")
        for change in ("missing", "duplicate", "extra", "pass", "executed", "skipped"):
            with self.subTest(change=change):
                bad = copy.deepcopy(good)
                if change == "missing":
                    bad["cases"].pop()
                elif change == "duplicate":
                    bad["cases"][-1] = copy.deepcopy(bad["cases"][0])
                elif change == "extra":
                    bad["cases"].append({"id": "E5"})
                elif change == "executed":
                    bad["cases"][1]["executed"] = True
                else:
                    bad["cases"][1]["status"] = change
                with self.assertRaises(ValueError):
                    runner.validate_results(bad, self.artifacts)

    def test_missing_or_fabricated_wire_evidence_is_rejected(self):
        runner.run(self.artifacts, self.command)
        results = self.read("results.json")
        results["cases"][0]["evidence"] = ["client-frames.jsonl"]
        with self.assertRaises(ValueError):
            runner.validate_results(results, self.artifacts)
        (self.artifacts / "probe-events.jsonl").unlink()
        with self.assertRaises(ValueError):
            runner.validate_results(self.read("results.json"), self.artifacts)

    def test_report_claims_and_wrong_event_provenance_are_rejected(self):
        for key in ("live_transport_executed", "revision_cutover_executed", "transport_feasible",
                    "client_socket_evidence", "real_wire_executed"):
            with self.subTest(key=key):
                bad = report()
                bad["findings"][key] = True
                with self.assertRaises(ValueError):
                    runner.validate_report(bad, VERSIONS)
        for event_change in ({"sequence": 2}, {"provenance": "client-tls-socket"}):
            bad = report()
            bad["events"][0].update(event_change)
            with self.assertRaises(ValueError):
                runner.validate_report(bad, VERSIONS)

    def test_invalid_report_becomes_failure_without_preserving_false_claim(self):
        self.probe.return_value["findings"]["live_transport_executed"] = True
        self.assertEqual(runner.run(self.artifacts, self.command), 1)
        self.assertFalse(self.read("interface-findings.json")["findings"]["live_transport_executed"])

    def test_dependency_metadata_marks_only_missing_packages(self):
        with mock.patch.object(runner.importlib.metadata, "version", side_effect=[
            "11.0.2", runner.importlib.metadata.PackageNotFoundError("h2"), "6.0.1",
        ]):
            actual = EvidenceRunnerTests.real_dependency_versions()
        self.assertEqual(actual, {**VERSIONS, "h2": None})

    real_dependency_versions = staticmethod(runner.dependency_versions)


class GitProvenanceTests(unittest.TestCase):
    def test_dirty_diff_is_path_scoped_and_includes_untracked_files(self):
        path = runner.SOURCE_PATHS[0]
        outputs = [b"head\n", b"tree\n", runner.BASE_SHA.encode() + b"\n",
                   b"tracked diff\n", path.encode() + b"\0", b"untracked diff\n"]
        completed = [subprocess.CompletedProcess([], 1 if i == 5 else 0, output, b"")
                     for i, output in enumerate(outputs)]
        with mock.patch.object(runner.subprocess, "run", side_effect=completed) as git:
            metadata, diff = runner.git_metadata()
        self.assertEqual(diff, b"tracked diff\nuntracked diff\n")
        self.assertEqual(metadata["dirty_diff_sha256"], hashlib.sha256(diff).hexdigest())
        self.assertEqual(metadata["dirty_diff_scope"], list(runner.SOURCE_PATHS))
        self.assertTrue(metadata["dirty"])
        calls = [call.args[0] for call in git.call_args_list]
        self.assertTrue(all(call[:3] == ["git", "-C", str(runner.ROOT)] for call in calls))
        self.assertEqual(calls[3][calls[3].index("--") + 1:], list(runner.SOURCE_PATHS))
        self.assertEqual(calls[-1][-3:], ["--", "/dev/null", path])
        self.assertTrue(all(call.kwargs["timeout"] == 10 for call in git.call_args_list))


if __name__ == "__main__":
    unittest.main()
