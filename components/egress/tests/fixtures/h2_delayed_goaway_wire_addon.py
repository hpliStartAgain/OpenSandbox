# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Pinned, test-only W2 adapter. Never load alongside the production addon.

Only the receiving Http2Server instance is adapted. It uses normal h2 APIs;
SendData yield completion is deliberately NOT called TLS write completion.
The independent runner must decide whether bytes actually reached its client.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import threading
import time

from h2.errors import ErrorCodes
from h2.events import RequestReceived, StreamReset
from h2.exceptions import StreamClosedError
from mitmproxy import ctx
from mitmproxy.proxy import commands, events
from mitmproxy.proxy.layers.http import HttpLayer, RequestHeaders, ResponseProtocolError
from mitmproxy.proxy.layers.http._base import ReceiveHttp
from mitmproxy.proxy.layers.http._http2 import Http2Server

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("_w2_delayed_model", HERE / "h2_delayed_goaway_probe.py")
model = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(model)
PINS = {"mitmproxy": "11.0.2", "h2": "4.1.0", "hyperframe": "6.0.1"}


class WireTrace:
    """Metadata only; no headers, bodies, TLS keys, or exception text."""

    def __init__(self, directory: Path):
        self.path = directory / "proxy-events.jsonl"
        self.sequence = 0
        self.lock = threading.Lock()

    def add(self, kind, **values):
        with self.lock:
            self.sequence += 1
            item = {"sequence": self.sequence, "monotonic_ns": time.monotonic_ns(),
                    "provenance": "real-mitmproxy-command-boundary", "kind": kind, **values}
            with self.path.open("a", encoding="utf-8") as output:
                output.write(json.dumps(item, sort_keys=True) + "\n")


def frame_metadata(data):
    from hyperframe.frame import Frame, GoAwayFrame, RstStreamFrame
    result = []
    while data:
        if len(data) < 9:
            raise ValueError("incomplete protocol output header")
        frame, length = Frame.parse_frame_header(memoryview(data[:9]))
        if len(data) < 9 + length:
            raise ValueError("incomplete protocol output body")
        frame.parse_body(memoryview(data[9:9 + length]))
        item = {"type": type(frame).__name__, "stream_id": frame.stream_id,
                "end_stream": "END_STREAM" in frame.flags, "length": length}
        if isinstance(frame, (GoAwayFrame, RstStreamFrame)):
            item["error_code"] = int(frame.error_code)
        if isinstance(frame, GoAwayFrame):
            item["last_stream_id"] = frame.last_stream_id
        result.append(item)
        data = data[9 + length:]
    return result


class ProbeH2Server(Http2Server):
    def __init__(self, context, directory, trace):
        super().__init__(context)
        self.directory = directory
        self.trace = trace
        self.gate = model.AdmissionBridge(trace, drain_seconds=15)
        self.accepted = set()
        self.requests = {}
        self.ended_yielded = set()
        self.terminal = False
        self.disconnected = False

    def observe_commands(self, produced):
        for command in produced:
            metadata = None
            if isinstance(command, commands.SendData):
                metadata = frame_metadata(command.data)
                self.trace.add("protocol_output", frames=metadata)
            elif isinstance(command, commands.CloseConnection):
                self.terminal = True
                self.trace.add("close_requested")
            yield command
            if metadata is not None:
                # The parent generator consumed this command. This is neither a
                # StreamWriter.drain callback nor a TLS/client receipt assertion.
                self.ended_yielded.update(f["stream_id"] for f in metadata if f["end_stream"])
                self.trace.add("send_command_consumed", frames=metadata)

    def handle_h2_event(self, event):
        if isinstance(event, RequestReceived):
            if not self.gate.admit(event.stream_id):
                if not self.is_closed(event.stream_id):
                    try:
                        self.h2_conn.reset_stream(event.stream_id, ErrorCodes.REFUSED_STREAM)
                    except StreamClosedError:
                        self.trace.add("refused_already_terminal", stream_id=event.stream_id)
                else:
                    self.trace.add("refused_already_terminal", stream_id=event.stream_id)
                # Do not create an HttpStream or upstream request. receive_data
                # already updated HPACK, and base processing still credits DATA.
                return False
            self.accepted.add(event.stream_id)
            for command in super().handle_h2_event(event):
                if isinstance(command, ReceiveHttp) and isinstance(command.event, RequestHeaders):
                    self.requests[id(command.event.request)] = event.stream_id
                yield command
            return False
        if isinstance(event, StreamReset):
            self.gate.finish(event.stream_id)
            self.ended_yielded.add(event.stream_id)
        return (yield from super().handle_h2_event(event))

    def _handle_event(self, event):
        if isinstance(event, events.Wakeup):
            fence = self.directory / "fence.json"
            if self.gate.frozen is None and fence.exists():
                if json.loads(fence.read_text()) != {"action": "fence"}:
                    raise ValueError("invalid W2 fence instruction")
                self.gate.commit(2)
            if self.gate.token in self.gate.registry.expired_connections():
                self.trace.add("deadline_forced_close")
                self.terminal = True
                yield from self.observe_commands(self.close_connection("W2 deadline"))
                return
        else:
            if isinstance(event, ResponseProtocolError):
                self.gate.finish(event.stream_id)
                self.ended_yielded.add(event.stream_id)
            yield from self.observe_commands(super()._handle_event(event))
        if isinstance(event, events.ConnectionClosed):
            self.on_disconnect()
            return
        yield from self.maybe_finish()
        if not self.terminal and isinstance(event, (events.Start, events.Wakeup)):
            yield commands.RequestWakeup(0.02)

    def maybe_finish(self):
        if self.terminal or self.gate.frozen is None:
            return
        if (self.gate.handles or self.h2_conn.stream_buffers or self.h2_conn.stream_trailers
                or not self.accepted <= self.ended_yielded
                or any(not self.is_closed(sid) for sid in self.accepted)):
            return
        self.terminal = True
        self.h2_conn.close_connection(error_code=0, last_stream_id=self.gate.frozen)
        self.trace.add("final_goaway_queued", last_stream_id=self.gate.frozen)
        yield from self.observe_commands((commands.SendData(self.conn, self.h2_conn.data_to_send()),))
        # Normal terminal layer path ignores in-flight post-GOAWAY bytes, avoiding
        # a second GOAWAY with highest_inbound_stream_id including refused streams.
        yield from self.observe_commands(self.close_connection("W2 old streams complete"))

    def on_disconnect(self):
        if not self.disconnected:
            self.disconnected = True
            self.terminal = True
            self.gate.disconnect()
            self.trace.add("actual_disconnect")


class W2Addon:
    def __init__(self):
        self.directory = None
        self.trace = None
        self.layers = {}

    def load(self, _loader):
        if model.original.dependency_versions() != PINS:
            raise RuntimeError("W2 requires exact pinned dependencies")
        self.directory = Path(os.environ["OSEP_W2_DIRECTORY"]).resolve(strict=True)
        self.trace = WireTrace(self.directory)
        self.trace.add("adapter_loaded", dependencies=PINS)

    def next_layer(self, data):
        if data.context.client.alpn != b"h2":
            return
        if data.layer is None:
            # ScriptLoader precedes NextLayer in this version. Invoke the same
            # configured selector once; its later normal hook is an explicit
            # no-op when data.layer is already set. No addon-order mutation.
            selector = ctx.master.addons.get("nextlayer")
            if selector is None:
                raise RuntimeError("W2 requires the normal NextLayer addon")
            selector.next_layer(data)
        selected = data.layer
        if not isinstance(selected, HttpLayer) or selected.context.client.alpn != b"h2":
            return
        client = selected.context.client
        if client in selected.connections:
            raise RuntimeError("W2 cannot replace an already started HTTP connection")
        if client.id in self.layers:
            raise RuntimeError("W2 expects only one inner H2 layer per client")
        layer = ProbeH2Server(selected.context.fork(), self.directory, self.trace)
        # HttpLayer.Start explicitly preserves a pre-set client connection for
        # playback. Reuse that fixed-version instance seam, not a class patch.
        selected.connections[client] = layer
        self.layers[client.id] = layer
        self.trace.add("adapter_attached")

    def requestheaders(self, flow):
        layer = self.layers.get(flow.client_conn.id)
        if layer is not None:
            sid = layer.requests[id(flow.request)]
            flow.metadata["w2_client_stream_id"] = sid
            self.trace.add("actual_requestheaders", stream_id=sid)

    def responseheaders(self, flow):
        if flow.client_conn.id in self.layers:
            flow.response.stream = True

    def response(self, flow):
        layer = self.layers.get(flow.client_conn.id)
        if layer is not None:
            sid = flow.metadata["w2_client_stream_id"]
            # The real response hook occurs after origin EOM, before flow_done's
            # final client EOM. A finished handle is intentionally insufficient.
            layer.gate.finish(sid)
            self.trace.add("response_handle_finished", stream_id=sid,
                           buffered_streams=len(layer.h2_conn.stream_buffers))

    def error(self, flow):
        layer = self.layers.get(flow.client_conn.id)
        if layer is not None and "w2_client_stream_id" in flow.metadata:
            layer.gate.finish(flow.metadata["w2_client_stream_id"])
            self.trace.add("actual_flow_error", stream_id=flow.metadata["w2_client_stream_id"])

    def client_disconnected(self, client):
        layer = self.layers.pop(client.id, None)
        if layer is not None:
            layer.on_disconnect()


addons = [W2Addon()]
