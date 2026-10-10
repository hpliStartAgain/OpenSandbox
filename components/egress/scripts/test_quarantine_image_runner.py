# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Hermetic harness checks only; these never count as real Docker image proof."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
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


def bound_snapshot(inode=100, record=None):
    if record is None:
        record = {"version": 2, "incarnation": "test", "phase": "running", "operation": "",
                  "bootID": "10000000-0000-0000-0000-000000000001", "netnsDev": 4,
                  "netnsInode": inode, "reason": ""}
    return {"netns": f"net:[{inode}]", "host_boot_id": "10000000-0000-0000-0000-000000000001",
            "netns_dev": 4, "netns_inode": inode, "processes": [], "files": {
                "journal.json": {"hex": json.dumps(record).encode().hex()}, "journal.lock": {"hex": ""},
                "checkpoint": None}}


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
    def test_every_required_crash_boundary_is_accounted_for(self):
        self.assertEqual(set(runner.STAGES), {"before-intent", "after-intent", "after-effects", "before-commit",
            "after-commit", "before-unfence", "after-unfence", "before-ready"})
        self.assertEqual(len(runner.required_cases()), 16)
        self.assertIn("TestSidecarRunningContainerSIGKILLRebuildBoundary", runner.required_cases())
        self.assertEqual(len(set(runner.required_cases())), len(runner.required_cases()))
        self.assertEqual(runner.STAGES["before-intent"], ("guarded", False, True))
        self.assertEqual(runner.STAGES["after-effects"], ("intent", True, True))
        self.assertEqual(runner.STAGES["after-unfence"], ("running", True, False))
        self.assertTrue((runner.ROOT / "components/egress/Dockerfile").is_file())
        compile(runner.SNAPSHOT, "container_snapshot", "exec")
        compile(runner.WORKLOAD, "container_workload", "exec")
        compile(runner.WORKLOAD_CLIENT, "container_workload_client", "exec")
        compile(runner.FENCE_OBSERVER, "container_fence_observer", "exec")

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
        with self.assertRaises(runner.Failure):
            runner.assert_process_chain(snapshot, False)
        snapshot["processes"].pop()
        runner.assert_process_chain(snapshot, False)
        with self.assertRaises(runner.Failure):
            runner.assert_process_chain(snapshot, True)

    def test_missing_docker_is_failure_with_no_pass_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            with patch.object(runner.shutil, "which", return_value=None), redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                result = runner.main(["--image", "not-executed", "--artifacts", tmp])
            self.assertEqual(result, 1)
            self.assertIn("=== RUN   TestSidecarImagePrerequisites", stdout.getvalue())
            self.assertIn("--- FAIL:", stdout.getvalue())
            self.assertNotIn("--- PASS:", stdout.getvalue())
            self.assertNotIn("SKIP", stdout.getvalue())
            evidence = json.loads((Path(tmp) / "results.json").read_text())
            self.assertFalse(evidence["passed"])
            self.assertEqual(evidence["results"][0]["status"], "FAIL")
            self.assertEqual(evidence["required"], runner.required_cases())

    def test_docker_command_failure_and_timeout_are_not_success(self):
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

    def test_provision_helper_is_isolated_and_has_no_capabilities(self):
        with tempfile.TemporaryDirectory() as tmp:
            docker = runner.Docker(Path(tmp))
            s = runner.Sidecar(docker, "test-image", "unit-helper")
            with patch.object(docker, "run") as run:
                s.helper("--provision-quarantine")
            args = run.call_args.args
            self.assertEqual(args[:8], ("run", "--rm", "--network", "none", "--cap-drop", "ALL", "--read-only", "--mount"))
            self.assertIn(f"type=volume,src={s.volume},dst={runner.STATE}", args)
            self.assertIn("OPENSANDBOX_EGRESS_QUARANTINE_ID=" + s.identity, args)
            self.assertEqual(args[-4:], ("--entrypoint", runner.EGRESS, "test-image", "--provision-quarantine"))
            self.assertNotIn("--privileged", args)

    def test_real_entrypoint_and_mount_contract_in_create(self):
        for invalid in (None, "readonly", "identity-mismatch"):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as tmp:
                docker = runner.Docker(Path(tmp))
                s = runner.Sidecar(docker, "test-image", "unit-start")
                calls = []

                def run(*args, **kwargs):
                    calls.append(args)
                    output = "container-id\n" if args[0] == "create" else "{}"
                    return subprocess.CompletedProcess(args, 0, output, "")

                info = {"HostConfig": {"Privileged": False, "NetworkMode": "none", "PidMode": "",
                                       "CapAdd": ["NET_ADMIN"], "CapDrop": ["NET_RAW"]},
                        "Config": {"Entrypoint": runner.ENTRYPOINT},
                        "Mounts": [{"Destination": runner.STATE, "Type": "volume", "Name": s.volume,
                                    "RW": invalid != "readonly"}]}
                with patch.object(docker, "run", side_effect=run), patch.object(docker, "json", return_value=[info]):
                    s.start(stage="before-ready", invalid=invalid)
                create = next(args for args in calls if args[0] == "create")
                self.assertNotIn("--entrypoint", create)
                self.assertNotIn("--privileged", create)
                self.assertNotIn("--pid", create)
                self.assertEqual(create[-1], "test-image")
                self.assertIn("OPENSANDBOX_EGRESS_TEST_QUARANTINE_PAUSE=before-ready", create)
                mount = create[create.index("--mount") + 1]
                self.assertEqual(mount.endswith(",readonly"), invalid == "readonly")
                identity = next(v for v in create if v.startswith("OPENSANDBOX_EGRESS_QUARANTINE_ID="))
                self.assertEqual(identity == "OPENSANDBOX_EGRESS_QUARANTINE_ID=" + s.identity,
                                 invalid != "identity-mismatch")

    def test_surviving_workload_requires_original_fence_and_blocked_packets(self):
        sidecar = SimpleNamespace(name="unit-sidecar", docker=None, snapshot=lambda: {"netns": "net:[100]"},
                                  fence=lambda: True)
        workload = runner.Workload(sidecar)
        workload.had_existing = True
        safe = {"netns": "net:[100]", "new_tcp": False, "established_tcp": False}
        with patch.object(workload, "record"), patch.object(workload, "call", return_value=safe), \
                patch.object(workload, "fence", return_value=True):
            workload.assert_contained("unit")
        # A DIFFERENT current sidecar netns does not invalidate confirmed
        # quarantine of the unchanged ORIGINAL workload netns.
        diagnostic = io.StringIO()
        with patch.object(workload, "record") as record, \
                patch.object(workload, "call", return_value={**safe, "netns": "net:[200]"}), \
                patch.object(workload, "fence", return_value=True), redirect_stdout(diagnostic):
            workload.assert_contained("divergent-but-contained")
            self.assertTrue(record.call_args.args[1]["namespace_diverged"])
        self.assertIn("DIAGNOSTIC: namespace divergence", diagnostic.getvalue())
        cases = [({**safe, "netns": "net:[200]"}, False, "no confirmed fence"),
                 (safe, False, "no confirmed fence"),
                 ({**safe, "new_tcp": True}, True, "still delivers"),
                 ({**safe, "established_tcp": True}, True, "still delivers"),
                 ({**safe, "established_tcp": None}, True, "still delivers"),
                 ({**safe, "netns": "net:[200]", "new_tcp": True}, True, "still delivers")]
        for probe, fenced, error in cases:
            with self.subTest(probe=probe, fenced=fenced), patch.object(workload, "record"), \
                    patch.object(workload, "call", return_value=probe), patch.object(workload, "fence", return_value=fenced), \
                    redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(runner.Failure, error):
                    workload.assert_contained("unit")

    def test_workload_fence_observer_is_read_only_and_has_no_journal_mount(self):
        with tempfile.TemporaryDirectory() as tmp:
            docker = runner.Docker(Path(tmp))
            sidecar = SimpleNamespace(name="unit-sidecar", docker=docker, image="test-image")
            workload = runner.Workload(sidecar)
            workload.original = {"netns": "net:[100]"}
            observed = {"netns": "net:[100]", "ruleset": fence()}
            with patch.object(workload, "record") as record, patch.object(docker, "json", return_value=observed) as query:
                self.assertTrue(workload.fence())
                self.assertEqual(record.call_args_list[0].args, ("workload-fence-observer", observed))
            args = query.call_args.args
            self.assertEqual(args[:8], ("run", "--rm", "--network", "container:unit-sidecar-workload",
                                       "--cap-drop", "ALL", "--cap-add", "NET_ADMIN"))
            self.assertIn("--read-only", args)
            self.assertNotIn("--mount", args)
            self.assertNotIn("--privileged", args)
            self.assertEqual(args[-5:], ("--entrypoint", "python3", "test-image", "-c", runner.FENCE_OBSERVER))

    def test_fence_observer_wrong_actual_namespace_cannot_supply_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            docker = runner.Docker(Path(tmp))
            workload = runner.Workload(SimpleNamespace(name="unit-sidecar", docker=docker, image="test-image"))
            workload.original = {"netns": "net:[100]"}
            observed = {"netns": "net:[200]", "ruleset": fence()}
            with patch.object(workload, "record") as record, patch.object(docker, "json", return_value=observed), \
                    patch.object(runner, "fence_present") as validate:
                with self.assertRaisesRegex(runner.Failure, "observer ran in the wrong namespace"):
                    workload.fence()
                validate.assert_not_called()
                record.assert_called_once_with("workload-fence-observer", observed)

    def test_original_workload_namespace_and_process_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            docker = runner.Docker(Path(tmp))
            workload = runner.Workload(SimpleNamespace(name="unit-sidecar", docker=docker))
            workload.original = {"netns": "net:[100]", "boot": "original", "uid": 1000, "cap_eff": "0"}
            workload.container_id = "workload-id"
            with patch.object(docker, "json", side_effect=[workload.original, [{"Id": "workload-id"}]]):
                self.assertEqual(workload.call("status"), workload.original)
            for key, changed in (("netns", "net:[200]"), ("boot", "replacement"), ("uid", 0), ("cap_eff", "1")):
                with self.subTest(key=key), patch.object(docker, "json", return_value={**workload.original, key: changed}):
                    with self.assertRaisesRegex(runner.Failure, "process or its original namespace was replaced"):
                        workload.call("status")

    def test_v2_journal_binds_actual_namespace_and_never_rebinds_on_restart(self):
        before = bound_snapshot()
        runner.assert_bound_journal(before)
        self.assertFalse(runner.assert_restart_journal(before, copy.deepcopy(before)))
        record = runner.journal(before)
        quarantined = {**record, "phase": "quarantine", "reason": "namespace-mismatch/rebuild-required"}
        after = bound_snapshot(200, quarantined)
        self.assertTrue(runner.assert_restart_journal(before, after))
        with self.assertRaisesRegex(runner.Failure, "not bound to the actual original"):
            runner.assert_bound_journal(after)
        for change in ({"version": 1}, {"netnsInode": 200}, {"bootID": "replacement"},
                       {"phase": "running"}, {"reason": ""}, {"operation": "replay"}):
            with self.subTest(change=change), self.assertRaises(runner.Failure):
                runner.assert_restart_journal(before, bound_snapshot(200, {**quarantined, **change}))
        with self.assertRaisesRegex(runner.Failure, "same-namespace restart modified"):
            runner.assert_restart_journal(before, bound_snapshot(100, quarantined))

    def test_split_namespace_requires_unknown_rebuild_refusal_not_old_fence(self):
        before = bound_snapshot()
        after = bound_snapshot(200, {**runner.journal(before), "phase": "quarantine",
                                     "reason": "namespace-mismatch/rebuild-required"})
        sidecar = SimpleNamespace(name="unit-sidecar", docker=None, health=lambda: "503",
                                  logs=lambda: "experimental lifecycle guard: QuarantineUnknown: rebuild-required")
        workload = runner.Workload(sidecar)
        workload.had_existing = True
        # The old namespace can still deliver loopback TCP. This is recorded,
        # never presented as containment; the supported outcome is rebuild.
        evidence = {"namespace_diverged": True, "fenced": False, "current_namespace_fenced": True,
                    "workload": {"new_tcp": True, "established_tcp": True}}
        with patch.object(workload, "observe", return_value=copy.deepcopy(evidence)), \
                patch.object(workload, "record") as record, redirect_stdout(io.StringIO()):
            workload.assert_rebuild_boundary(before, after, "split")
            self.assertIn("old workload isolation not established", record.call_args.args[1]["outcome"])
            self.assertTrue(record.call_args.args[1]["workload"]["new_tcp"])
        for message in ("QuarantineConfirmed: rebuild-required", "QuarantineUnknown", "rebuild-required"):
            with self.subTest(message=message), patch.object(workload, "observe", return_value=copy.deepcopy(evidence)), \
                    patch.object(sidecar, "logs", return_value=message), self.assertRaisesRegex(runner.Failure, "explicitly report"):
                workload.assert_rebuild_boundary(before, after, "split")
        with patch.object(workload, "observe", return_value=copy.deepcopy(evidence)), \
                patch.object(sidecar, "health", return_value="200"), self.assertRaisesRegex(runner.Failure, "published readiness"):
            workload.assert_rebuild_boundary(before, after, "split")
        worker_after = copy.deepcopy(after)
        worker_after["processes"] = [{"role": "worker"}]
        with patch.object(workload, "observe", return_value=copy.deepcopy(evidence)), \
                self.assertRaisesRegex(runner.Failure, "relaunched a worker"):
            workload.assert_rebuild_boundary(before, worker_after, "split")

    def test_same_namespace_container_restart_still_requires_real_packet_blocking(self):
        before = bound_snapshot()
        sidecar = SimpleNamespace(name="unit-sidecar", docker=None, health=lambda: "503", logs=lambda: "")
        workload = runner.Workload(sidecar)
        workload.had_existing = True
        evidence = {"namespace_diverged": False, "fenced": True, "current_namespace_fenced": True,
                    "workload": {"new_tcp": False, "established_tcp": False}}
        with patch.object(workload, "observe", return_value=copy.deepcopy(evidence)), patch.object(workload, "record"):
            workload.assert_rebuild_boundary(before, before, "same")
        for changed in ({**evidence, "fenced": False},
                        {**evidence, "workload": {"new_tcp": True, "established_tcp": True}}):
            with self.subTest(changed=changed), patch.object(workload, "observe", return_value=changed), \
                    self.assertRaises(runner.Failure):
                workload.assert_rebuild_boundary(before, before, "same")


if __name__ == "__main__":
    unittest.main()
