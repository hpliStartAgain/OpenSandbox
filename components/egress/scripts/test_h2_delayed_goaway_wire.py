# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Pure W2 parser/acceptance/status tests. Never start sockets or mitmdump."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "_w2_wire_runner", Path(__file__).with_name("h2_delayed_goaway_wire.py"),
)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def rows(provenance, values):
    return [{"sequence": index, "monotonic_ns": when, "provenance": provenance, **value}
            for index, (when, value) in enumerate(values, 1)]


def valid_evidence():
    """Synthetic unit input only; not a recorded real-wire artifact."""
    evidence = runner.empty_evidence()
    evidence["observations"].update(
        tls_alpn="h2", tls_verified=True, upstream_tls_verification=True,
        body_length=len(runner.BODY), body_sha256=runner.BODY_SHA256,
        hpack_inserted_on_stream_3=True, hpack_reused_on_stream_5=True,
    )
    ending = {"type": "DataFrame", "stream_id": 1, "end_stream": True}
    goaway = {"type": "GoAwayFrame", "stream_id": 0, "end_stream": False,
              "last_stream_id": 1, "error_code": 0}
    evidence["proxy_events"] = rows(runner.PROXY, [
        (10, {"kind": "admitted", "stream_id": 1}),
        (20, {"kind": "commit_return", "frozen": 1}),
        (30, {"kind": "admission_refused", "stream_id": 3}),
        (40, {"kind": "admission_refused", "stream_id": 5}),
        (60, {"kind": "response_handle_finished", "stream_id": 1, "buffered_streams": 1}),
        (80, {"kind": "protocol_output", "frames": [ending.copy()]}),
        (90, {"kind": "final_goaway_queued", "last_stream_id": 1}),
        (91, {"kind": "protocol_output", "frames": [goaway.copy()]}),
        (92, {"kind": "close_requested"}),
        (95, {"kind": "actual_disconnect"}),
    ])
    evidence["client_frames"] = rows(runner.CLIENT, [
        (31, {"kind": "frame", "type": "RstStreamFrame", "stream_id": 3, "end_stream": False, "error_code": 7}),
        (41, {"kind": "frame", "type": "RstStreamFrame", "stream_id": 5, "end_stream": False, "error_code": 7}),
        (85, {"kind": "frame", **ending, "data_length": len(runner.BODY)}),
        (96, {"kind": "frame", **goaway}),
    ])
    evidence["client_events"] = rows(runner.CLIENT, [
        (31, {"kind": "stream_reset", "stream_id": 3, "error_code": 7}),
        (41, {"kind": "stream_reset", "stream_id": 5, "error_code": 7}),
        (50, {"kind": "credit_paused", "initial_window": 1024}),
        (61, {"kind": "response_headers", "stream_id": 1, "status": "200"}),
        (70, {"kind": "credit_resumed", "body_length": 1024}),
        (86, {"kind": "stream_ended", "stream_id": 1}),
        (97, {"kind": "connection_terminated", "last_stream_id": 1, "error_code": 0}),
        (98, {"kind": "eof"}),
    ])
    evidence["origin_requests"] = rows(runner.ORIGIN, [(15, {"kind": "request", "method": "GET", "path": "/v1/old"})])
    evidence["cleanup"] = {"status": "complete", "remaining_probe_resources": []}
    return evidence


def renumber(items):
    for index, item in enumerate(items, 1):
        item["sequence"] = index


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.evidence = valid_evidence()

    def rejected(self):
        with self.assertRaises(runner.EvidenceFailure):
            runner.validate_evidence(self.evidence)

    def test_complete_w2_evidence(self):
        runner.validate_evidence(self.evidence)

    def test_every_required_event_is_mandatory(self):
        for key in ("client_events", "client_frames", "proxy_events", "origin_requests"):
            for index in range(len(self.evidence[key])):
                with self.subTest(key=key, index=index):
                    modified = valid_evidence()
                    del modified[key][index]
                    renumber(modified[key])
                    with self.assertRaises(runner.EvidenceFailure):
                        runner.validate_evidence(modified)

    def test_model_provenance_cannot_pass_as_real_wire(self):
        self.evidence["client_frames"][0]["provenance"] = "in-process-delayed-goaway-experiment"
        self.rejected()

    def test_missing_or_changed_body_rejected(self):
        for key, value in (("body_length", 1024), ("body_sha256", "0" * 64)):
            with self.subTest(key=key):
                self.evidence = valid_evidence()
                self.evidence["observations"][key] = value
                self.rejected()

    def test_non_h2_or_unverified_tls_rejected(self):
        for key, value in (("tls_alpn", "http/1.1"), ("tls_verified", False), ("upstream_tls_verification", False)):
            self.evidence = valid_evidence()
            self.evidence["observations"][key] = value
            self.rejected()

    def test_extra_origin_request_rejected(self):
        self.evidence["origin_requests"].append({**self.evidence["origin_requests"][0], "sequence": 2, "path": "/v1/refused"})
        self.rejected()

    def test_higher_goaway_bound_rejected(self):
        self.evidence["client_frames"][-1]["last_stream_id"] = 5
        self.rejected()

    def test_duplicate_goaway_rejected(self):
        frames = self.evidence["client_frames"]
        frames.append({**frames[-1], "sequence": len(frames) + 1})
        self.rejected()

    def test_truncated_wire_length_rejected(self):
        self.evidence["client_frames"][-2]["data_length"] -= 1
        self.rejected()

    def test_wrong_reset_code_rejected(self):
        self.evidence["client_frames"][0]["error_code"] = 8
        self.rejected()

    def test_independent_parser_disagreement_rejected(self):
        self.evidence["client_events"][0]["error_code"] = 8
        self.rejected()

    def test_non_200_response_rejected(self):
        self.evidence["client_events"][3]["status"] = "502"
        self.rejected()

    def test_absent_hpack_reuse_rejected(self):
        self.evidence["observations"]["hpack_reused_on_stream_5"] = False
        self.rejected()

    def test_automatic_retries_rejected(self):
        self.evidence["observations"]["automatic_retry"] = True
        self.rejected()

    def test_no_buffered_body_at_response_hook_rejected(self):
        self.evidence["proxy_events"][4]["buffered_streams"] = 0
        self.rejected()

    def test_no_post_hook_credit_pause_rejected(self):
        self.evidence["client_events"][4]["monotonic_ns"] = 59
        self.rejected()

    def test_false_backpressure_with_full_body_rejected(self):
        self.evidence["client_events"][4]["body_length"] = len(runner.BODY)
        self.rejected()

    def test_eof_before_h2_goaway_rejected(self):
        items = self.evidence["client_events"]
        items[-1]["kind"], items[-2]["kind"] = items[-2]["kind"], items[-1]["kind"]
        self.rejected()

    def test_deadline_fallback_and_flow_errors_rejected(self):
        for kind in ("deadline_forced_close", "actual_flow_error"):
            self.evidence = valid_evidence()
            items = self.evidence["proxy_events"]
            items.append({"kind": kind, "sequence": len(items) + 1, "monotonic_ns": 100, "provenance": runner.PROXY})
            self.rejected()


class FrameDecoderTests(unittest.TestCase):
    def test_fragmented_header_payload_and_multiple_frames(self):
        from hyperframe.frame import DataFrame, GoAwayFrame, RstStreamFrame

        reset = RstStreamFrame(3)
        reset.error_code = 7
        body = DataFrame(1)
        body.data = b"synthetic-body"
        body.flags.add("END_STREAM")
        goaway = GoAwayFrame(0)
        goaway.last_stream_id = 1
        wire = reset.serialize() + body.serialize() + goaway.serialize()
        for width in (1, 2, 8, 9, 10, 13, len(wire)):
            with self.subTest(width=width):
                decoder = runner.FrameDecoder()
                for offset in range(0, len(wire), width):
                    decoder.feed(wire[offset:offset + width])
                decoder.finish()
                self.assertEqual([f["type"] for f in decoder.frames], ["RstStreamFrame", "DataFrame", "GoAwayFrame"])
                self.assertEqual(decoder.frames[0]["error_code"], 7)
                self.assertEqual(decoder.frames[1]["data_length"], 14)
                self.assertTrue(decoder.frames[1]["end_stream"])
                self.assertEqual(decoder.frames[2]["last_stream_id"], 1)
                self.assertNotIn("synthetic-body", json.dumps(decoder.frames))

    def test_partial_frame_at_eof_rejected(self):
        from hyperframe.frame import DataFrame
        frame = DataFrame(1)
        frame.data = b"body"
        for length in (1, 8, 9, 12):
            decoder = runner.FrameDecoder()
            decoder.feed(frame.serialize()[:length])
            with self.assertRaises(runner.EvidenceFailure):
                decoder.finish()

    def test_padded_data_reports_unpadded_body_length(self):
        from hyperframe.frame import DataFrame
        frame = DataFrame(1)
        frame.data = b"body"
        frame.pad_length = 4
        frame.flags.add("PADDED")
        decoder = runner.FrameDecoder()
        decoder.feed(frame.serialize())
        self.assertEqual(decoder.frames[0]["data_length"], 4)
        self.assertEqual(decoder.frames[0]["length"], 9)

    def test_oversized_frame_header_rejected_without_buffering_body(self):
        decoder = runner.FrameDecoder()
        with self.assertRaises(runner.EvidenceFailure):
            decoder.feed(b"\x00\x40\x01\x00\x00\x00\x00\x00\x01")

    def test_hpack_reuse_is_real_indexed_representation(self):
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        peer = H2Connection(config=H2Configuration(client_side=True))
        peer.initiate_connection()
        peer.data_to_send()
        marker = (b"x-w2-repeated", b"synthetic-refused-stream-index")
        headers = [(":method", "GET"), (":scheme", "https"), (":authority", "bound.example.com"), (":path", "/v1/refused"), marker]
        peer.send_headers(3, headers, end_stream=True)
        first = runner.header_block(peer.data_to_send(), 3)
        index = peer.encoder.header_table.search(*marker)[0]
        peer.send_headers(5, headers, end_stream=True)
        repeated = runner.header_block(peer.data_to_send(), 5)
        self.assertNotIn(index, runner.indexed_header_fields(first))
        self.assertIn(index, runner.indexed_header_fields(repeated))

    def test_read_events_ignores_partial_concurrent_append(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events"
            path.write_bytes(b'{"sequence":1}\n{"seq')
            self.assertEqual(runner.read_events(path), [{"sequence": 1}])


class StatusTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="w2-pure-status-")
        self.addCleanup(temporary.cleanup)
        self.artifacts = Path(temporary.name) / "artifacts"
        self.command = ["python", "h2_delayed_goaway_wire.py", "--artifacts", str(self.artifacts)]
        self.versions = self.patch("dependency_versions", return_value=runner.PINS.copy())
        self.execute = self.patch("execute_wire", side_effect=lambda evidence: evidence.update(valid_evidence()))
        self.git = self.patch("git_metadata", return_value=({"head_sha": "a" * 40, "tree_sha": "b" * 40,
                                                           "dirty": True}, b"synthetic diff"))

    def patch(self, name, **kwargs):
        patcher = mock.patch.object(runner, name, **kwargs)
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def read(self, name):
        return json.loads((self.artifacts / name).read_text())

    def test_pass_is_only_w2_and_preserves_other_denominators(self):
        self.assertEqual(runner.run(self.artifacts, self.command), 0)
        results = self.read("results.json")
        self.assertEqual(results["required_cases"], ["W0", "W1", "W2", "W3", "W4"])
        self.assertEqual([case["status"] for case in results["cases"]], ["not-run", "not-run", "pass", "not-run", "not-run"])
        self.assertEqual([case["executed"] for case in results["cases"]], [False, False, True, False, False])
        for key in ("original_E1_passed", "production_ready", "transport_feasible", "real_ipc_executed", "client_library_retry_tested"):
            self.assertIs(results[key], False)

    def test_every_pin_mismatch_blocks_before_execution(self):
        for name in runner.PINS:
            for version in (None, "wrong"):
                with self.subTest(name=name, version=version):
                    self.artifacts = self.artifacts.parent / (name + str(version))
                    self.versions.return_value = {**runner.PINS, name: version}
                    self.assertEqual(runner.run(self.artifacts, self.command), 2)
                    self.execute.assert_not_called()
                    self.assertEqual(self.read("results.json")["cases"][2]["status"], "blocked")

    def test_missing_import_is_blocked_not_passed(self):
        self.execute.side_effect = ModuleNotFoundError("missing")
        self.assertEqual(runner.run(self.artifacts, self.command), 2)
        self.assertFalse(self.read("results.json")["real_wire_executed"])

    def test_permission_denial_is_blocked_not_skip_pass(self):
        self.execute.side_effect = PermissionError(1, "operation not permitted")
        self.assertEqual(runner.run(self.artifacts, self.command), 2)
        self.assertEqual(self.read("results.json")["status"], "blocked")

    def test_protocol_failure_is_exit_one(self):
        self.execute.side_effect = runner.EvidenceFailure("15-second W2 deadline expired")
        self.assertEqual(runner.run(self.artifacts, self.command), 1)
        self.assertEqual(self.read("results.json")["status"], "fail")

    def test_incomplete_evidence_cannot_pass(self):
        self.execute.side_effect = lambda evidence: None
        self.assertEqual(runner.run(self.artifacts, self.command), 1)

    def test_cleanup_failure_cannot_pass(self):
        def broken(evidence):
            evidence.update(valid_evidence())
            evidence["cleanup"]["status"] = "failed"
        self.execute.side_effect = broken
        self.assertEqual(runner.run(self.artifacts, self.command), 1)

    def test_git_failure_stops_execution_and_returns_failure(self):
        self.git.side_effect = runner.EvidenceFailure("git source provenance unavailable")
        self.assertEqual(runner.run(self.artifacts, self.command), 1)
        self.execute.assert_not_called()

    def test_partial_wire_failure_preserves_actual_frames(self):
        def broken(evidence):
            evidence.update(valid_evidence())
            raise runner.EvidenceFailure("actual mismatch")
        self.execute.side_effect = broken
        self.assertEqual(runner.run(self.artifacts, self.command), 1)
        self.assertTrue(self.read("results.json")["real_wire_executed"])
        self.assertTrue((self.artifacts / "client-frames.jsonl").read_text())

    def test_manifest_hashes_only_saved_sanitized_artifacts(self):
        self.assertEqual(runner.run(self.artifacts, self.command), 0)
        manifest = self.read("manifest.json")
        self.assertEqual(manifest["command"], self.command)
        self.assertTrue(manifest["git"]["dirty"])
        self.assertEqual(manifest["dependencies"], runner.PINS)
        self.assertNotIn("environment", manifest)
        for filename, digest in manifest["artifact_sha256"].items():
            self.assertEqual(hashlib.sha256((self.artifacts / filename).read_bytes()).hexdigest(), digest)
        self.assertEqual(set(path.name for path in self.artifacts.iterdir()), {
            "manifest.json", "dirty.diff", "client-frames.jsonl", "client-events.jsonl",
            "origin-requests.jsonl", "proxy-events.jsonl", "wire-findings.json",
            "results.json", "cleanup.json", "proxy.log",
        })

    def test_existing_artifacts_never_overwritten(self):
        self.artifacts.mkdir()
        sentinel = self.artifacts / "manifest.json"
        sentinel.write_text("keep")
        with self.assertRaises(FileExistsError):
            runner.run(self.artifacts, self.command)
        self.assertEqual(sentinel.read_text(), "keep")
        self.execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
