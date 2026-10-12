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

"""Fixed-version, in-process H2 interface diagnostic, NOT a live addon.

This is the stopping-point reproduction for the OSEP-0023 transport probe.
It exercises real mitmproxy/hyper-h2 objects but starts no proxy, TLS socket,
origin, revision IPC, or request-admission bridge. Serialized frames here are
in-memory protocol output, never client-wire evidence for E0--E4.

All GOAWAY bytes come from BufferedH2Connection.close_connection(). We never
write raw frames, replace a protocol state machine, restore CLOSED to OPEN,
or patch dependency classes. Each rejected operation uses a fresh connection.
"""

from __future__ import annotations

import importlib.metadata
import time
from types import SimpleNamespace


def dependency_versions() -> dict[str, str]:
    versions = {
        name: importlib.metadata.version(name)
        for name in ("mitmproxy", "h2", "hyperframe")
    }
    if versions["mitmproxy"] != "11.0.2":
        raise RuntimeError("this diagnostic requires mitmproxy 11.0.2")
    return versions


def frame_metadata(data: bytes) -> list[dict]:
    """Parse complete in-memory frames, retaining no header/body/debug bytes."""
    from hyperframe.frame import Frame, GoAwayFrame

    result = []
    while data:
        if len(data) < 9:
            raise ValueError("incomplete frame header")
        frame, length = Frame.parse_frame_header(memoryview(data[:9]))
        if len(data) < 9 + length:
            raise ValueError("incomplete frame payload")
        frame.parse_body(memoryview(data[9:9 + length]))
        item = {
            "type": type(frame).__name__,
            "stream_id": frame.stream_id,
            "end_stream": "END_STREAM" in frame.flags,
        }
        if isinstance(frame, GoAwayFrame):
            item.update(last_stream_id=frame.last_stream_id, error_code=frame.error_code)
        result.append(item)
        data = data[9 + length:]
    return result


def _peer():
    from h2.config import H2Configuration
    from h2.connection import H2Connection

    return H2Connection(config=H2Configuration(client_side=True))


def _requests(peer) -> bytes:
    for stream_id in (1, 3):
        peer.send_headers(stream_id, [
            (":method", "GET"), (":scheme", "https"),
            (":authority", "bound.example.com"), (":path", f"/v1/probe-{stream_id}"),
        ], end_stream=False)
    return peer.data_to_send()


def _open_pair():
    from h2.config import H2Configuration
    from mitmproxy.proxy.layers.http._http_h2 import BufferedH2Connection

    server = BufferedH2Connection(H2Configuration(client_side=False))
    peer = _peer()
    peer.initiate_connection()
    server.initiate_connection()
    server.receive_data(peer.data_to_send())
    peer.receive_data(server.data_to_send())
    server.receive_data(peer.data_to_send())
    server.receive_data(_requests(peer))
    for stream_id in (1, 3):
        server.send_headers(stream_id, [(":status", "200")])
    server.send_data(1, b"before")
    before = server.data_to_send()
    peer.receive_data(before)
    return server, peer, frame_metadata(before)


def _dependency_operation(operation: str) -> dict:
    from h2.exceptions import ProtocolError

    server, peer, before = _open_pair()
    # Generate input using the still-open peer, before it receives GOAWAY.
    # No raw-frame write or peer/proxy state restoration is involved.
    if operation == "receive_data":
        peer.send_data(1, b"request-body")
    elif operation == "receive_window_update":
        peer.increment_flow_control_window(1, stream_id=1)
    inbound = peer.data_to_send()
    state_before = server.state_machine.state.name
    server.close_connection(error_code=0, last_stream_id=3)
    goaway = frame_metadata(server.data_to_send())
    actions = {
        "send_data": lambda: server.send_data(1, b"after"),
        "end_stream": lambda: server.end_stream(1),
        "send_window_update": lambda: server.increment_flow_control_window(1, stream_id=1),
        "receive_data": lambda: server.receive_data(inbound),
        "receive_window_update": lambda: server.receive_data(inbound),
    }
    rejected = False
    try:
        actions[operation]()
    except ProtocolError:
        rejected = True
    return {
        "operation": operation,
        "state_before": state_before,
        "state_after": server.state_machine.state.name,
        "before_frames": before,
        "goaway_frames": goaway,
        "protocol_error": rejected,
        "after_frames": frame_metadata(server.data_to_send()),
    }


def _layer_operation(operation: str) -> dict:
    from mitmproxy import connection, http
    from mitmproxy.proxy import commands, events
    from mitmproxy.proxy.context import Context
    from mitmproxy.proxy.layers.http import ResponseData, ResponseEndOfMessage, ResponseHeaders
    from mitmproxy.proxy.layers.http._http2 import Http2Server

    client = connection.Client(peername=("127.0.0.1", 10000), sockname=("127.0.0.1", 10001))
    context = Context(client, SimpleNamespace(proxy_debug=False, validate_inbound_headers=True))
    layer = Http2Server(context)
    peer = _peer()

    def send(event):
        return b"".join(command.data for command in layer.handle_event(event)
                        if isinstance(command, commands.SendData))

    peer.initiate_connection()
    initial = send(events.Start())
    reply = send(events.DataReceived(client, peer.data_to_send()))
    peer.receive_data(initial + reply)
    send(events.DataReceived(client, peer.data_to_send()))
    send(events.DataReceived(client, _requests(peer)))
    response = http.Response.make(200)
    response.headers.pop("content-length", None)
    send(ResponseHeaders(1, response))
    before = frame_metadata(send(ResponseData(1, b"before")))
    layer.h2_conn.close_connection(error_code=0, last_stream_id=3)
    goaway = frame_metadata(layer.h2_conn.data_to_send())
    event = ResponseData(1, b"after") if operation == "response_data" else ResponseEndOfMessage(1)
    after = frame_metadata(send(event))
    return {
        "operation": operation,
        "before_frames": before,
        "goaway_frames": goaway,
        "after_frames": after,
        "state_after": layer.h2_conn.state_machine.state.name,
        "is_open_for_us": layer.is_open_for_us(1),
    }


def _peer_limitation() -> dict:
    from h2.exceptions import ProtocolError

    server, peer, _ = _open_pair()
    # Save legitimate DATA serialized before closing, solely to inspect the
    # peer's receive contract. These bytes are never sent to a socket.
    server.send_data(1, b"held-data", end_stream=True)
    held = server.data_to_send()
    server.close_connection(error_code=0, last_stream_id=3)
    peer.receive_data(server.data_to_send())
    rejected = False
    try:
        peer.receive_data(held)
    except ProtocolError:
        rejected = True
    return {"state_after": peer.state_machine.state.name, "rejects_old_stream_data": rejected}


def inspect_transport() -> dict:
    """Return reproducible observations without claiming any live case ran."""
    versions = dependency_versions()
    events = []

    def record(kind, values):
        events.append({
            "sequence": len(events) + 1,
            "monotonic_ns": time.monotonic_ns(),
            "provenance": "in-process-interface-diagnostic",
            "kind": kind,
            **values,
        })

    dependency = []
    for operation in ("send_data", "end_stream", "send_window_update", "receive_data", "receive_window_update"):
        result = _dependency_operation(operation)
        dependency.append(result)
        record("dependency_operation", result)
    layer = []
    for operation in ("response_data", "response_end_stream"):
        result = _layer_operation(operation)
        layer.append(result)
        record("mitmproxy_layer_operation", result)
    peer = _peer_limitation()
    record("peer_limitation", peer)
    blocked = all(result["protocol_error"] for result in dependency) and all(
        result["state_after"] == "CLOSED" and not result["after_frames"] for result in layer
    )
    return {
        "schema_version": 1,
        "mode": "in-process-interface-diagnostic",
        "dependencies": versions,
        "events": events,
        "findings": {
            "normal_goaway_api_blocks_drain": blocked,
            "peer_also_rejects_post_goaway_data": peer["rejects_old_stream_data"],
            "live_transport_executed": False,
            "revision_cutover_executed": False,
            "reason": "normal GOAWAY closes h2 state; existing mitmproxy layer cannot continue old streams"
            if blocked else "interface observations changed; review before attempting live transport",
        },
    }
