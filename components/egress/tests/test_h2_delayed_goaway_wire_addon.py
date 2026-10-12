# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Pure checks of the W2 adapter. These do not supply W2 real-TLS evidence."""

import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import ConnectionTerminated, DataReceived, StreamEnded, StreamReset
from h2.settings import SettingCodes
from mitmproxy import connection, http
from mitmproxy.proxy import commands, events
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers.http import HTTPMode, HttpLayer, RequestHeaders, ResponseData, ResponseEndOfMessage, ResponseHeaders
from mitmproxy.proxy.layers.http._base import ReceiveHttp

SPEC = importlib.util.spec_from_file_location("wire_addon", Path(__file__).parent / "fixtures/h2_delayed_goaway_wire_addon.py")
wire = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wire)


class AdapterTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.client = connection.Client(peername=("127.0.0.1", 1234), sockname=("127.0.0.1", 1235))
        self.client.alpn = b"h2"
        self.context = Context(self.client, SimpleNamespace(proxy_debug=False, validate_inbound_headers=True))
        self.trace = wire.WireTrace(self.directory)
        self.layer = wire.ProbeH2Server(self.context, self.directory, self.trace)
        self.peer = H2Connection(H2Configuration(client_side=True))
        self.peer_events = []
        self.requests = {}
        self.closes = 0
        self.wakeup = None
        self.peer.initiate_connection()
        self.peer.update_settings({SettingCodes.INITIAL_WINDOW_SIZE: 8})
        self.consume(events.Start())
        self.receive()
        self.receive()

    def records(self):
        return [json.loads(line) for line in self.trace.path.read_text().splitlines()]

    def consume(self, event):
        for command in self.layer.handle_event(event):
            if isinstance(command, commands.SendData):
                self.peer_events.extend(self.peer.receive_data(command.data))
            elif isinstance(command, commands.RequestWakeup):
                self.wakeup = command
            elif isinstance(command, commands.CloseConnection):
                self.closes += 1
            elif isinstance(command, ReceiveHttp) and isinstance(command.event, RequestHeaders):
                self.requests[command.event.stream_id] = command.event.request

    def receive(self):
        data = self.peer.data_to_send()
        if data:
            self.consume(events.DataReceived(self.client, data))

    def request(self, sid, end_stream=True, marker="old"):
        self.peer.send_headers(sid, [(":method", "GET"), (":scheme", "https"),
                                    (":authority", "bound.example.com"), (":path", f"/v1/{sid}"),
                                    ("x-synthetic", marker)], end_stream=end_stream)
        self.receive()

    def fence(self):
        (self.directory / "fence.json").write_text('{"action":"fence"}')
        self.consume(events.Wakeup(self.wakeup))

    def response_hook(self, sid):
        addon = wire.W2Addon()
        addon.layers[self.client.id] = self.layer
        addon.trace = self.trace
        flow = SimpleNamespace(client_conn=self.client, request=self.requests[sid], metadata={})
        addon.requestheaders(flow)
        addon.response(flow)
        return flow

    def test_refusal_backpressure_and_terminal_order(self):
        self.request(1)
        self.fence()
        self.request(3, marker="refused-hpack")
        self.request(5, marker="refused-hpack")
        self.assertEqual([1], list(self.requests))
        self.assertIn((b"x-synthetic", b"refused-hpack"), self.layer.h2_conn.decoder.header_table.dynamic_entries)
        self.assertEqual([(3, 7), (5, 7)], [(e.stream_id, int(e.error_code)) for e in self.peer_events if isinstance(e, StreamReset)])
        self.consume(ResponseHeaders(1, http.Response.make(200, b"x" * 33)))
        self.consume(ResponseData(1, b"x" * 33))
        flow = self.response_hook(1)
        self.assertEqual(1, flow.metadata["w2_client_stream_id"])
        self.consume(ResponseEndOfMessage(1))
        self.assertTrue(self.layer.h2_conn.stream_buffers)
        self.assertFalse(self.closes)
        self.assertFalse(any(isinstance(e, ConnectionTerminated) for e in self.peer_events))
        pending = 0
        for _ in range(20):
            if self.closes:
                break
            new = self.peer_events[pending:]
            pending = len(self.peer_events)
            for event in new:
                if isinstance(event, DataReceived):
                    self.peer.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            self.receive()
        self.assertEqual(1, self.closes)
        kinds = [type(e) for e in self.peer_events]
        self.assertLess(kinds.index(StreamEnded), kinds.index(ConnectionTerminated))
        final = [e for e in self.peer_events if isinstance(e, ConnectionTerminated)]
        self.assertEqual([(1, 0)], [(e.last_stream_id, int(e.error_code)) for e in final])
        records = self.records()
        self.assertLess(next(r['sequence'] for r in records if r['kind'] == 'response_handle_finished'),
                        next(r['sequence'] for r in records if r['kind'] == 'final_goaway_queued'))

    def test_upload_not_finished_blocks_final(self):
        self.request(1, end_stream=False)
        self.fence()
        self.response_hook(1)
        self.consume(ResponseHeaders(1, http.Response.make(200), end_stream=True))
        self.assertFalse(self.closes)
        self.assertEqual("HALF_CLOSED_LOCAL", self.layer.h2_conn.streams[1].state_machine.state.name)
        self.peer.end_stream(1)
        self.receive()
        self.assertEqual(1, self.closes)

    def test_peer_goaway_does_not_emit_candidate_goaway(self):
        self.request(1)
        self.fence()
        self.peer.close_connection()
        self.receive()
        self.assertEqual(1, self.closes)
        self.assertFalse(any(r['kind'] == 'final_goaway_queued' for r in self.records()))

    def test_fenced_same_batch_reset_is_safe(self):
        self.request(1)
        self.fence()
        self.peer.send_headers(3, [(":method", "GET"), (":scheme", "https"),
                                  (":authority", "bound.example.com"), (":path", "/v1/refused")])
        self.peer.reset_stream(3)
        self.receive()
        self.assertEqual([1], list(self.requests))
        self.assertFalse(self.closes)
        self.assertTrue(any(r['kind'] == 'refused_already_terminal' for r in self.records()))

    def test_disconnect_cleanup_is_idempotent(self):
        self.request(1)
        self.layer.on_disconnect()
        self.layer.on_disconnect()
        self.assertFalse(self.layer.gate.handles)
        self.assertFalse(self.layer.gate.registry.pending_requests())
        self.assertEqual(1, sum(r['kind'] == 'actual_disconnect' for r in self.records()))

    def test_instance_seam_preserves_unrelated_layer(self):
        addon = wire.W2Addon()
        addon.directory, addon.trace = self.directory, self.trace
        selected = HttpLayer(self.context.fork(), HTTPMode.transparent)
        addon.next_layer(SimpleNamespace(layer=selected, context=selected.context))
        self.assertIsInstance(selected.connections[self.client], wire.ProbeH2Server)
        with self.assertRaisesRegex(RuntimeError, "already started"):
            addon.next_layer(SimpleNamespace(layer=selected, context=selected.context))
        self.assertIsNot(wire.Http2Server, wire.ProbeH2Server)

    def test_normal_selector_runs_once_before_instance_injection(self):
        addon = wire.W2Addon()
        addon.directory, addon.trace = self.directory, self.trace
        data = SimpleNamespace(layer=None, context=self.context.fork())
        from mitmproxy.addons.next_layer import NextLayer
        selector = NextLayer()
        data.data_client = lambda: b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        data.data_server = lambda: b""
        master = SimpleNamespace(addons=SimpleNamespace(get=lambda name: selector if name == "nextlayer" else None))
        with patch.object(wire.ctx, "master", master, create=True), patch.object(
                wire.ctx, "options", SimpleNamespace(ignore_hosts=[], allow_hosts=[]), create=True):
            addon.next_layer(data)
            # The selector's later normal hook must retain the chosen layer.
            chosen = data.layer
            selector.next_layer(data)
            self.assertIs(chosen, data.layer)
        selected = data.layer.connections[self.client]
        self.assertIsInstance(selected, wire.ProbeH2Server)
        produced = list(data.layer.handle_event(events.Start()))
        self.assertIs(selected, data.layer.connections[self.client])
        wakeups = [c for c in produced if isinstance(c, commands.RequestWakeup)]
        self.assertEqual(1, len(wakeups))
        self.assertIs(selected, data.layer.command_sources[wakeups[0]])

    def test_invalid_control_fails_without_cutover(self):
        (self.directory / "fence.json").write_text('{"action":"reopen"}')
        with self.assertRaisesRegex(ValueError, "invalid W2"):
            self.consume(events.Wakeup(self.wakeup))
        self.assertIsNone(self.layer.gate.frozen)


if __name__ == "__main__":
    unittest.main()
