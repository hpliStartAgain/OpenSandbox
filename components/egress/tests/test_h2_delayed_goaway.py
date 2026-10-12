# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Candidate protocol-model tests, never live transport acceptance."""

import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "_delayed_goaway_fixture", Path(__file__).parent / "fixtures" / "h2_delayed_goaway_probe.py",
)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class DelayedGoawayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = probe.inspect_delayed_transport()

    def session(self, window=65535):
        session = probe.Session(probe.Trace(), window=window)
        self.addCleanup(session.confirm_disconnect)
        return session

    def test_four_candidate_cases_pass_without_promoting_live_claims(self):
        self.assertEqual([case["id"] for case in self.report["cases"]], ["D1", "D2", "D3", "D4"])
        self.assertTrue(all(case["status"] == "pass" for case in self.report["cases"]), self.report["cases"])
        self.assertFalse(self.report["original_E1_passed"])
        self.assertFalse(self.report["live_transport_executed"])
        self.assertEqual(self.report["mode"], probe.MODE)
        self.assertEqual([e["sequence"] for e in self.report["events"]],
                         list(range(1, len(self.report["events"]) + 1)))

    def test_only_old_admitted_streams_dispatch(self):
        session = self.session()
        session.request(1)
        session.gate.commit(2)
        session.request(3, "refused-only-header")
        session.request(5, "refused-only-header")
        session.flush()
        self.assertEqual(session.dispatches, [1])
        self.assertEqual(set(session.gate.handles), {1})
        self.assertEqual(session.gate.frozen, 1)
        resets = [(e["stream_id"], e["error_code"]) for e in session.trace.events
                  if e["kind"] == "peer_observed_reset"]
        self.assertEqual(resets, [(3, 7), (5, 7)])
        self.assertIn((b"x-synthetic-repeated", b"refused-only-header"),
                      session.layer.h2_conn.decoder.header_table.dynamic_entries)

    def test_frozen_bound_includes_already_completed_higher_stream(self):
        session = self.session()
        session.request(1)
        session.request(3)
        session.respond(3)
        session.flush()
        self.assertEqual(set(session.gate.handles), {1})
        session.gate.commit(2)
        self.assertEqual(session.gate.frozen, 3)
        session.request(5)
        session.respond(1)
        session.flush()
        self.assertTrue(session.try_finish_drain())
        session.flush()
        final = [e for e in session.trace.events if e["kind"] == "peer_observed_goaway"]
        self.assertEqual(final[-1]["last_stream_id"], 3)

    def test_queued_end_stream_and_finished_handle_are_not_writer_completion(self):
        session = self.session()
        session.request(1)
        session.gate.commit(2)
        session.respond(1)
        self.assertEqual(session.gate.handles, {})
        self.assertTrue(session.output)
        self.assertFalse(session.try_finish_drain())
        self.assertFalse(session.goaway_sent)
        session.flush()
        self.assertTrue(session.try_finish_drain())

    def test_written_response_does_not_close_an_admitted_upload(self):
        session = self.session()
        session.peer.send_headers(1, [(":method", "GET"), (":scheme", "https"),
                                    (":authority", "bound.example.com"), (":path", "/v1/upload")])
        session.peer.send_data(1, b"partial", end_stream=False)
        session.receive(session.peer.data_to_send())
        session.gate.commit(2)
        session.respond(1)
        session.flush()
        self.assertEqual(session.layer.h2_conn.streams[1].state_machine.state.name, "HALF_CLOSED_LOCAL")
        self.assertFalse(session.try_finish_drain())
        self.assertFalse(session.close_requested)
        session.peer.send_data(1, b"remaining", end_stream=True)
        session.receive(session.peer.data_to_send())
        self.assertEqual(session.body_dispatches, [1, 1])
        session.flush()
        self.assertTrue(session.try_finish_drain())

    def test_zero_stream_window_keeps_connection_open(self):
        session = self.session(window=0)
        session.request(1)
        session.gate.commit(2)
        session.respond(1)
        session.flush()
        self.assertTrue(session.layer.h2_conn.stream_buffers)
        self.assertFalse(session.try_finish_drain())
        self.assertEqual(session.layer.h2_conn.state_machine.state.name, "SERVER_OPEN")
        session.peer.increment_flow_control_window(1024, stream_id=1)
        session.receive(session.peer.data_to_send())
        self.assertFalse(session.try_finish_drain())
        session.flush()
        self.assertTrue(session.try_finish_drain())

    def test_exact_window_exhaustion_keeps_empty_end_marker_pending(self):
        session = self.session(window=8)
        session.request(1)
        session.gate.commit(2)
        session.respond(1, b"x" * 16)
        session.flush()
        session.acknowledge_data()
        session.flush()
        pending = session.layer.h2_conn.stream_buffers[1]
        self.assertEqual([(chunk.data, chunk.end_stream) for chunk in pending], [(b"", True)])
        self.assertFalse(session.try_finish_drain())
        session.acknowledge_data()
        self.assertFalse(session.try_finish_drain())
        session.flush()
        self.assertTrue(session.try_finish_drain())

    def test_connection_window_backpressure_is_not_stream_completion(self):
        session = self.session(window=200_000)
        session.request(1)
        session.gate.commit(2)
        session.respond(1, b"x" * 70_000)
        session.flush()
        self.assertEqual(session.layer.h2_conn.outbound_flow_control_window, 0)
        self.assertGreater(session.layer.h2_conn.streams[1].outbound_flow_control_window, 0)
        self.assertFalse(session.try_finish_drain())
        session.acknowledge_data()
        session.flush()
        self.assertTrue(session.try_finish_drain())

    def test_large_body_has_actual_end_stream_after_chunking(self):
        from h2.events import DataReceived, StreamEnded
        session = self.session(window=200_000)
        session.peer.increment_flow_control_window(200_000)
        session.receive(session.peer.data_to_send())
        session.request(1)
        session.gate.commit(2)
        session.respond(1, b"x" * 40_000)
        session.flush()
        self.assertEqual(b"".join(e.data for e in session.peer_events if isinstance(e, DataReceived)), b"x" * 40_000)
        self.assertTrue(any(isinstance(e, StreamEnded) and e.stream_id == 1 for e in session.peer_events))
        self.assertTrue(session.try_finish_drain())

    def test_fragmented_headers_completed_after_fence_are_refused(self):
        from h2.settings import SettingCodes
        from hyperframe.frame import Frame
        session = self.session()
        session.request(1)
        # Negotiate a smaller legal frame size through ordinary SETTINGS.
        session.layer.h2_conn.update_settings({SettingCodes.MAX_FRAME_SIZE: 16384})
        session.queue(session.layer.h2_conn.data_to_send())
        session.flush()
        session.receive(session.peer.data_to_send())
        session.peer.send_headers(3, [(":method", "GET"), (":scheme", "https"),
                                    (":authority", "bound.example.com"), (":path", "/v1/partial"),
                                    ("x-large-synthetic", "0123456789" * 4500)], end_stream=True)
        encoded = session.peer.data_to_send()
        first, length = Frame.parse_frame_header(memoryview(encoded[:9]))
        self.assertNotIn("END_HEADERS", first.flags)
        session.receive(encoded[:9 + length])
        self.assertEqual(session.dispatches, [1])
        session.gate.commit(2)
        session.receive(encoded[9 + length:])
        session.flush()
        self.assertEqual(session.dispatches, [1])
        self.assertTrue(any(e["kind"] == "peer_observed_reset" and e["stream_id"] == 3
                            for e in session.trace.events))

    def test_same_packet_refused_headers_padded_data_and_end_do_not_dispatch(self):
        session = self.session()
        session.request(1)
        session.gate.commit(2)
        window = session.layer.h2_conn._inbound_flow_control_window_manager
        before = window._bytes_processed
        session.peer.send_headers(3, [(":method", "GET"), (":scheme", "https"),
                                    (":authority", "bound.example.com"), (":path", "/v1/refused")])
        session.peer.send_data(3, b"synthetic", pad_length=7, end_stream=True)
        session.receive(session.peer.data_to_send())
        session.flush()
        self.assertEqual(session.dispatches, [1])
        self.assertEqual(session.body_dispatches, [])
        self.assertEqual(window._bytes_processed - before, len(b"synthetic") + 8)

    def test_refused_headers_and_peer_reset_in_same_packet_are_already_terminal(self):
        for end_stream in (False, True):
            with self.subTest(end_stream=end_stream):
                session = self.session()
                session.request(1)
                session.gate.commit(2)
                session.peer.send_headers(3, [(":method", "GET"), (":scheme", "https"),
                                            (":authority", "bound.example.com"), (":path", "/v1/refused")],
                                          end_stream=end_stream)
                session.peer.reset_stream(3, error_code=8)
                session.receive(session.peer.data_to_send())
                self.assertEqual(session.dispatches, [1])
                self.assertEqual(set(session.gate.handles), {1})
                self.assertTrue(any(e["kind"] == "refused_already_terminal" and e["stream_id"] == 3
                                    for e in session.trace.events))

    def test_refused_headers_and_peer_goaway_in_same_packet_close_normally(self):
        for end_stream in (False, True):
            with self.subTest(end_stream=end_stream):
                session = self.session()
                session.request(1)
                session.gate.commit(2)
                session.peer.send_headers(3, [(":method", "GET"), (":scheme", "https"),
                                            (":authority", "bound.example.com"), (":path", "/v1/refused")],
                                          end_stream=end_stream)
                session.peer.close_connection(error_code=0, last_stream_id=0)
                session.receive(session.peer.data_to_send())
                self.assertEqual(session.dispatches, [1])
                self.assertTrue(session.close_requested)
                self.assertFalse(session.goaway_sent)
                self.assertEqual(session.gate.handles, {})

    def test_old_reset_and_new_headers_in_same_packet_filter_before_final_goaway(self):
        session = self.session()
        session.request(1)
        session.gate.commit(2)
        session.peer.reset_stream(1, error_code=8)
        session.peer.send_headers(3, [(":method", "GET"), (":scheme", "https"),
                                    (":authority", "bound.example.com"), (":path", "/v1/refused")], end_stream=True)
        session.receive(session.peer.data_to_send())
        self.assertFalse(session.try_finish_drain())  # REFUSED output is still queued.
        session.flush()
        self.assertTrue(session.try_finish_drain())
        session.flush()
        self.assertEqual(session.dispatches, [1])

    def test_reset_one_stream_keeps_other_handle(self):
        session = self.session()
        session.request(1)
        session.request(3)
        session.peer.reset_stream(1, error_code=8)
        session.receive(session.peer.data_to_send())
        self.assertEqual(set(session.gate.handles), {3})
        self.assertEqual(len(session.gate.registry.pending_requests()), 1)

    def test_trailers_end_stream_must_reach_modeled_writer(self):
        from mitmproxy import http
        from mitmproxy.proxy.layers.http import ResponseData, ResponseEndOfMessage, ResponseHeaders, ResponseTrailers
        session = self.session(window=8)
        session.request(1)
        session.gate.commit(2)
        session.gate.finish(1)
        response = http.Response.make(200)
        response.headers.pop("content-length", None)
        for event in (ResponseHeaders(1, response), ResponseData(1, b"x" * 16),
                      ResponseTrailers(1, http.Headers([(b"x-synthetic-tail", b"yes")])),
                      ResponseEndOfMessage(1)):
            session.consume(session.layer.handle_event(event))
        session.flush()
        self.assertTrue(session.layer.h2_conn.stream_trailers)
        self.assertFalse(session.try_finish_drain())
        session.acknowledge_data()
        self.assertFalse(session.try_finish_drain())
        session.flush()
        self.assertFalse(session.layer.h2_conn.stream_trailers)
        self.assertTrue(session.try_finish_drain())

    def test_reset_with_buffered_trailers_is_conservative_not_false_graceful(self):
        from mitmproxy import http
        from mitmproxy.proxy.layers.http import ResponseData, ResponseEndOfMessage, ResponseHeaders, ResponseTrailers
        session = self.session(window=0)
        session.request(1)
        session.gate.commit(2)
        session.gate.finish(1)
        response = http.Response.make(200)
        response.headers.pop("content-length", None)
        for event in (ResponseHeaders(1, response), ResponseData(1, b"body"),
                      ResponseTrailers(1, http.Headers([(b"x-tail", b"yes")])), ResponseEndOfMessage(1)):
            session.consume(session.layer.handle_event(event))
        session.flush()
        session.peer.reset_stream(1, error_code=8)
        session.receive(session.peer.data_to_send())
        self.assertFalse(session.layer.h2_conn.stream_buffers)
        self.assertIn(1, session.layer.h2_conn.stream_trailers)
        self.assertFalse(session.try_finish_drain())  # Existing dependency residue; no patch or fake cleanup.
        self.assertFalse(session.goaway_sent)

    def test_late_input_after_final_goaway_does_not_increase_last_id(self):
        session = self.session()
        session.request(1)
        session.gate.commit(2)
        session.request(3)
        session.flush()
        session.respond(1)
        session.flush()
        self.assertTrue(session.try_finish_drain())
        session.peer.increment_flow_control_window(1)
        queued = len(session.output)
        session.receive(session.peer.data_to_send())
        self.assertEqual(len(session.output), queued)
        session.flush()
        final = [e for e in session.trace.events if e["kind"] == "peer_observed_goaway"]
        self.assertEqual([(e["last_stream_id"], e["error_code"]) for e in final], [(1, 0)])

    def test_negative_control_normal_closed_h2_can_increase_second_bound(self):
        from h2.exceptions import ProtocolError
        server, peer, _frames = probe.original._open_pair()
        server.reset_stream(3, error_code=7)
        server.data_to_send()
        server.close_connection(error_code=0, last_stream_id=1)
        first = probe.original.frame_metadata(server.data_to_send())
        peer.increment_flow_control_window(1)
        with self.assertRaises(ProtocolError):
            server.receive_data(peer.data_to_send())
        second = probe.original.frame_metadata(server.data_to_send())
        self.assertEqual(first[-1]["last_stream_id"], 1)
        self.assertEqual(second[-1]["last_stream_id"], 3)

    def test_disconnect_is_idempotent_and_clears_all_handles(self):
        session = self.session()
        session.request(1)
        session.request(3)
        session.confirm_disconnect()
        session.confirm_disconnect()
        self.assertTrue(session.disconnected)
        self.assertEqual(session.gate.handles, {})
        self.assertEqual(session.gate.registry.pending_requests(), ())
        self.assertEqual(session.gate.registry.acquire_request(session.gate.token).reason, "invalid_token")


if __name__ == "__main__":
    unittest.main()
