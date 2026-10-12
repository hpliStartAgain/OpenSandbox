# Copyright 2026 The OpenSandbox Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Regression checks of the H2 interface diagnostic, not E0--E4 wire tests.

A green unittest result means the negative reproduction and evidence labels
are intact. The separate strict runner remains nonzero because no live
transport feasibility case has passed. Missing dependencies fail, not skip.
"""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "h2_transport_fixture", Path(__file__).parent / "fixtures" / "h2_transport_probe.py",
)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class H2TransportInterfaceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.observed = probe.inspect_transport()

    def test_exact_version_and_evidence_boundary(self):
        self.assertEqual(self.observed["dependencies"]["mitmproxy"], "11.0.2")
        self.assertEqual(self.observed["mode"], "in-process-interface-diagnostic")
        self.assertFalse(self.observed["findings"]["live_transport_executed"])
        self.assertFalse(self.observed["findings"]["revision_cutover_executed"])
        self.assertTrue(self.observed["findings"]["normal_goaway_api_blocks_drain"])
        self.assertEqual(len(self.observed["events"]), 8)
        self.assertEqual([e["sequence"] for e in self.observed["events"]], list(range(1, 9)))
        times = [e["monotonic_ns"] for e in self.observed["events"]]
        self.assertEqual(times, sorted(times))
        for event in self.observed["events"]:
            self.assertEqual(event["provenance"], "in-process-interface-diagnostic")

    def test_ordinary_goaway_is_correct_but_closes_state(self):
        for event in self.observed["events"]:
            if "goaway_frames" not in event:
                continue
            with self.subTest(operation=event["operation"]):
                self.assertEqual(event["goaway_frames"], [{
                    "type": "GoAwayFrame", "stream_id": 0, "end_stream": False,
                    "last_stream_id": 3, "error_code": 0,
                }])
                self.assertEqual(event["state_after"], "CLOSED")
                self.assertIn({"type": "DataFrame", "stream_id": 1, "end_stream": False},
                              event["before_frames"])

    def test_dependency_rejects_each_old_stream_operation(self):
        cases = [event for event in self.observed["events"] if event["kind"] == "dependency_operation"]
        self.assertEqual({e["operation"] for e in cases}, {
            "send_data", "end_stream", "send_window_update", "receive_data", "receive_window_update",
        })
        for event in cases:
            with self.subTest(operation=event["operation"]):
                self.assertEqual(event["state_before"], "SERVER_OPEN")
                self.assertTrue(event["protocol_error"])
                self.assertFalse(any(f["type"] == "DataFrame" for f in event["after_frames"]))

    def test_mitmproxy_layer_suppresses_data_and_end_stream(self):
        cases = [event for event in self.observed["events"] if event["kind"] == "mitmproxy_layer_operation"]
        self.assertEqual({e["operation"] for e in cases}, {"response_data", "response_end_stream"})
        for event in cases:
            self.assertFalse(event["is_open_for_us"])
            self.assertEqual(event["after_frames"], [])

    def test_peer_limitation_is_reported_separately(self):
        self.assertTrue(self.observed["findings"]["peer_also_rejects_post_goaway_data"])
        peers = [event for event in self.observed["events"] if event["kind"] == "peer_limitation"]
        self.assertEqual(len(peers), 1)
        self.assertTrue(peers[0]["rejects_old_stream_data"])

    def test_frame_metadata_does_not_capture_payloads(self):
        server, _peer, _before = probe._open_pair()
        server.close_connection(last_stream_id=3, additional_data=b"synthetic-debug-not-for-evidence")
        serialized = json.dumps(probe.frame_metadata(server.data_to_send()))
        self.assertNotIn("synthetic-debug", serialized)
        self.assertNotIn("additional_data", serialized)
        with self.assertRaisesRegex(ValueError, "incomplete frame header"):
            probe.frame_metadata(b"\x00")
        with self.assertRaisesRegex(ValueError, "incomplete frame payload"):
            probe.frame_metadata(b"\x00\x00\x08\x07\x00\x00\x00\x00\x00")

    def test_wrong_mitmproxy_version_fails_closed(self):
        with patch.object(probe.importlib.metadata, "version", return_value="99.0"):
            with self.assertRaisesRegex(RuntimeError, "requires mitmproxy 11.0.2"):
                probe.inspect_transport()


if __name__ == "__main__":
    unittest.main()
