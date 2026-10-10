# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Hermetic harness checks only; no test here is real Docker runtime evidence."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("quarantine_image", Path(__file__).with_name("test_quarantine_image.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def fence():
    result = [{"metainfo": {"json_schema_version": 1}}, {"table": {
        "family": "inet", "name": "opensandbox_quarantine", "handle": 1,
        "comment": "opensandbox quarantine v1"}}]
    for name in ("input", "output", "forward"):
        result += [{"chain": {"family": "inet", "table": "opensandbox_quarantine", "name": name,
                              "type": "filter", "hook": name, "prio": -450, "policy": "drop"}},
                   {"rule": {"family": "inet", "table": "opensandbox_quarantine", "chain": name,
                             "expr": [{"drop": None}]}}]
    return {"nftables": result}

class FenceReadbackTests(unittest.TestCase):
    def test_exact_fence_and_positive_absence(self):
        self.assertTrue(runner.fence_present(fence()))
        self.assertFalse(runner.fence_present({"nftables": [{"metainfo": {}}]}))
        unrelated = fence()
        unrelated["nftables"].append({"table": {"family": "inet", "name": "opensandbox"}})
        self.assertTrue(runner.fence_present(unrelated))

    def test_partial_fence_is_not_absence(self):
        for index in range(1, 8):
            with self.subTest(index=index):
                value = fence()
                del value["nftables"][index]
                with self.assertRaises(runner.Failure):
                    runner.fence_present(value)

    def test_unsafe_table_chain_rule_and_extra_objects_rejected(self):
        cases = []
        for key, value in (("flags", ["dormant"]), ("comment", "wrong owner"), ("future", True)):
            data = fence()
            data["nftables"][1]["table"][key] = value
            cases.append(data)
        for key, value in (("policy", "accept"), ("prio", 0), ("hook", "prerouting"), ("name", "extra")):
            data = fence()
            data["nftables"][2]["chain"][key] = value
            cases.append(data)
        for expressions in ([{"accept": None}], [{"match": {}}, {"drop": None}], []):
            data = fence()
            data["nftables"][3]["rule"]["expr"] = expressions
            cases.append(data)
        data = fence()
        data["nftables"].append({"set": {"family": "inet", "table": "opensandbox_quarantine", "name": "extra"}})
        cases.append(data)
        cases += [{}, {"nftables": None}, {"nftables": [{}]}, {"nftables": [{"chain": None}]}]
        for data in cases:
            with self.subTest(data=data):
                with self.assertRaises(runner.Failure):
                    runner.fence_present(data)


class RunnerTests(unittest.TestCase):
    def test_runtime_only_required_cases_and_embedded_scripts(self):
        self.assertEqual(runner.REQUIRED, ["TestRuntimeImagePrerequisites", "TestRuntimeMitmFaultOwnerContainment"])
        for name in ("SNAPSHOT", "WORKLOAD", "WORKLOAD_CLIENT", "FENCE_OBSERVER"):
            compile(getattr(runner, name), name, "exec")
        source = Path(runner.__file__).read_text()
        for deleted in ("--provision-quarantine", "--guard-quarantine", "egress_quarantine_faults",
                        "OPENSANDBOX_EGRESS_QUARANTINE_ID", "journal.json", "restart_and_refuse"):
            self.assertNotIn(deleted, source)
        workflow = (runner.ROOT / ".github/workflows/egress-test.yml").read_text()
        for retained in ("TestQuarantineFenceKernelTraffic", "TestQuarantineFenceKernelFaults",
                         "TestAtomicPolicyDirectoryBindMount", "TestRevisionAtomicPolicyDirectoryBindMount"):
            self.assertIn(retained, workflow)
        for deleted in ("TestJournalPrivilegedMounts", "TestWaitOwnedListenContextExactChild", "egress_quarantine_faults"):
            self.assertNotIn(deleted, workflow)

    def test_exact_process_ancestry_required(self):
        snapshot = {"processes": [
            {"role": "supervisor", "pid": 1, "ppid": 0, "uid": 0},
            {"role": "worker", "pid": 15, "ppid": 1, "uid": 0},
            {"role": "mitmdump", "pid": 20, "ppid": 15, "uid": 10042}]}
        runner.assert_process_chain(snapshot, True)
        for field, value in (("ppid", 1), ("uid", 0)):
            wrong = copy.deepcopy(snapshot)
            wrong["processes"][2][field] = value
            with self.assertRaises(runner.Failure):
                runner.assert_process_chain(wrong, True)
        snapshot["processes"].pop()
        with self.assertRaises(runner.Failure):
            runner.assert_process_chain(snapshot, True)

    def test_missing_docker_fails_without_runtime_pass_or_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            with patch.object(runner.shutil, "which", return_value=None), redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                result = runner.main(["--image", "not-executed", "--artifacts", tmp])
            self.assertEqual(result, 1)
            self.assertIn("=== RUN   TestRuntimeImagePrerequisites", stdout.getvalue())
            self.assertIn("--- FAIL:", stdout.getvalue())
            self.assertNotIn("--- PASS:", stdout.getvalue())
            self.assertNotIn("SKIP", stdout.getvalue())
            evidence = json.loads((Path(tmp) / "results.json").read_text())
            self.assertFalse(evidence["passed"])
            self.assertEqual(evidence["results"][0]["status"], "FAIL")
            self.assertEqual(evidence["required"], runner.REQUIRED)

    def test_docker_failure_and_timeout_cannot_become_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            docker = runner.Docker(Path(tmp))
            failed = subprocess.CompletedProcess(["docker", "info"], 125, "", "daemon unavailable")
            with patch.object(runner.subprocess, "run", return_value=failed):
                with self.assertRaisesRegex(runner.Failure, "daemon unavailable"):
                    docker.run("info")
                self.assertEqual(docker.run("info", check=False).returncode, 125)
            with patch.object(runner.subprocess, "run", side_effect=subprocess.TimeoutExpired(["docker"], 1)):
                with self.assertRaisesRegex(runner.Failure, "prerequisite/command failed"):
                    docker.run("info")

    def test_real_entrypoint_without_lifecycle_volume_or_fault_tag(self):
        with tempfile.TemporaryDirectory() as tmp:
            docker = runner.Docker(Path(tmp))
            runtime = runner.Runtime(docker, "ordinary-image")
            info = {"HostConfig": {"Privileged": False, "NetworkMode": "none", "PidMode": "",
                                   "CapAdd": ["NET_ADMIN"], "CapDrop": ["NET_RAW"]},
                    "Config": {"Entrypoint": runner.ENTRYPOINT}, "Mounts": []}
            with patch.object(docker, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run, \
                    patch.object(docker, "json", return_value=[info]), patch.object(runtime, "wait"):
                runtime.__enter__()
                create = run.call_args_list[0].args
            self.assertEqual(create[0], "create")
            self.assertEqual(create[-1], "ordinary-image")
            self.assertIn("OPENSANDBOX_EGRESS_EXPERIMENTAL_REVISION_RUNTIME=true", create)
            for flag in ("--entrypoint", "--privileged", "--mount", "--volume", "--pid"):
                self.assertNotIn(flag, create)

    def test_observer_must_prove_actual_namespace_before_fence(self):
        self.assertTrue(runner.validate_observer({"netns": "net:[100]", "ruleset": fence()}, "net:[100]"))
        with patch.object(runner, "fence_present") as validate:
            with self.assertRaisesRegex(runner.Failure, "observer ran in wrong namespace"):
                runner.validate_observer({"netns": "net:[200]", "ruleset": fence()}, "net:[100]")
            validate.assert_not_called()

    def test_observer_is_read_only_and_has_no_private_mounts(self):
        with tempfile.TemporaryDirectory() as tmp:
            docker = runner.Docker(Path(tmp))
            runtime = runner.Runtime(docker, "ordinary-image")
            runtime.original = {"netns": "net:[100]"}
            observed = {"netns": "net:[100]", "ruleset": fence()}
            with patch.object(runtime, "record") as record, patch.object(runtime, "control", return_value={}), \
                    patch.object(docker, "json", return_value=observed) as query:
                self.assertTrue(runtime.observe("unit")["fenced"])
                self.assertEqual(record.call_args_list[0].args, ("unit-observer", observed))
            args = query.call_args.args
            self.assertEqual(args[:8], ("run", "--rm", "--network", "container:" + runtime.workload,
                                       "--cap-drop", "ALL", "--cap-add", "NET_ADMIN"))
            self.assertIn("--read-only", args)
            self.assertNotIn("--mount", args)
            self.assertEqual(args[-5:], ("--entrypoint", "python3", "ordinary-image", "-c", runner.FENCE_OBSERVER))

    def test_real_owner_and_blocked_packets_required_not_just_fence(self):
        worker = {"role": "worker", "pid": 15, "start": "123"}
        before = {"netns": "net:[100]", "processes": [worker, {"role": "mitmdump", "pid": 20}]}
        after = {"netns": "net:[100]", "processes": [worker]}
        observed = {"fenced": True, "probe": {"new_tcp": False, "established_tcp": False}}
        logs = runner.WORKER_STARTED + "pid=15)\n" + runner.CONFIRMED
        runner.validate_fault(before, after, observed, "000", logs)
        cases = [({**after, "netns": "net:[200]"}, observed, "000", logs),
                 ({**after, "processes": []}, observed, "000", logs),
                 (before, observed, "000", logs),
                 (after, {**observed, "fenced": False}, "000", logs),
                 (after, {**observed, "probe": {"new_tcp": True, "established_tcp": False}}, "000", logs),
                 (after, {**observed, "probe": {"new_tcp": False, "established_tcp": None}}, "000", logs),
                 (after, observed, "200", logs),
                 (after, observed, "000", runner.WORKER_STARTED + "packet isolation=QuarantineUnknown"),
                 (after, observed, "000", logs + "\nmitmdump restarted"),
                 (after, observed, "000", logs + runner.WORKER_STARTED)]
        for current, packets, health, output in cases:
            with self.subTest(current=current, packets=packets, health=health, output=output), self.assertRaises(runner.Failure):
                runner.validate_fault(before, current, packets, health, output)

    def test_original_workload_process_namespace_and_credentials_cannot_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            docker = runner.Docker(Path(tmp))
            runtime = runner.Runtime(docker, "ordinary-image")
            runtime.original = {"netns": "net:[100]", "boot": "original", "uid": 1000, "cap_eff": "0"}
            for key, value in (("netns", "net:[200]"), ("boot", "replacement"), ("uid", 0), ("cap_eff", "1")):
                result = subprocess.CompletedProcess([], 0, json.dumps({**runtime.original, key: value}), "")
                with self.subTest(key=key), patch.object(docker, "run", return_value=result), \
                        self.assertRaisesRegex(runner.Failure, "original workload process or namespace was replaced"):
                    runtime.control("status")


if __name__ == "__main__":
    unittest.main()
