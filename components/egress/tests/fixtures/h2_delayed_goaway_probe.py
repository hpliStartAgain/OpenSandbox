# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Isolated delayed-GOAWAY candidate; not a production addon or socket test.

The explicit test bridge orders admission/mapping with receiver publication.
It does not replace the revision owner. The modeled writer completion callback
is an assumption to verify in real mitmdump/TLS, not an existing addon API.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace

MODE = "in-process-delayed-goaway-experiment"
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("_h2_original_interface_probe", HERE / "h2_transport_probe.py")
original = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(original)


def _owners():
    old_path = sys.path[:]
    try:
        sys.path.insert(0, str(HERE.parents[1] / "mitmscripts"))
        from revision_publication import LiveReceiver
        from revision_receiver import Revision
        return LiveReceiver, Revision
    finally:
        sys.path[:] = old_path


def snapshot(epoch: int, covered: bool = True):
    _receiver, Revision = _owners()
    payload = json.dumps({
        "version": 1, "vaultRevision": epoch, "effectivePolicyEpoch": 0,
        "interceptionMode": "credential-bound", "state": "active" if covered else "active-empty",
        "tlsBindingHostSelectors": ["bound.example.com"] if covered else [],
        "fullRenderedBindings": [{"name": "synthetic", "match": {
            "schemes": ["https"], "hosts": ["bound.example.com"],
            "methods": ["GET"], "paths": ["/v1/*"],
        }, "headers": []}] if covered else [], "redactions": [],
    }, separators=(",", ":")).encode()
    return Revision("delayed-control", "delayed-subject", epoch, epoch, 0,
                    hashlib.sha256(payload).hexdigest()), payload


class Trace:
    def __init__(self):
        self.events = []
        self.lock = threading.Lock()

    def add(self, kind, **values):
        with self.lock:
            self.events.append({"sequence": len(self.events) + 1,
                                "monotonic_ns": time.monotonic_ns(),
                                "provenance": MODE, "kind": kind, **values})


class AdmissionBridge:
    """Test-only ordering lock, outside the existing Registry -> Receiver lock.

Every candidate admission and commit must enter this boundary. Test barriers
observe points inside the boundary; they do not provide its mutual exclusion.
The real IPC and requestheaders wiring is deliberately not claimed here.
"""

    def __init__(self, trace: Trace, drain_seconds: int = 1):
        LiveReceiver, _revision = _owners()
        self.trace = trace
        self.lock = threading.Lock()
        self.receiver = LiveReceiver("delayed-control", "delayed-subject",
                                     max_snapshot_bytes=100_000, capacity=4,
                                     request_capacity=16, drain_timeout_seconds=drain_seconds)
        self.registry = self.receiver.registry
        self.receiver.prepare(*snapshot(1))
        self.receiver.commit(snapshot(1)[0])
        self.token = self.registry.admit(identity=("delayed-control", "delayed-subject"),
                                         sni="bound.example.com", ech_hidden=False,
                                         static_passthrough=()).token
        assert self.token is not None
        self.handles = {}
        self.largest_admitted = 0
        self.frozen = None
        self.before_map = None
        self.before_freeze = None

    def admit(self, stream_id: int) -> bool:
        with self.lock:
            if self.frozen is not None:
                self.trace.add("admission_refused", stream_id=stream_id)
                return False
            result = self.registry.acquire_request(self.token)
            if result.action != "allow":
                self.trace.add("admission_refused", stream_id=stream_id)
                return False
            if self.before_map:
                self.before_map()
            self.handles[stream_id] = result.handle
            self.largest_admitted = max(self.largest_admitted, stream_id)
            self.trace.add("admitted", stream_id=stream_id, handle=result.handle.serial,
                           revision=result.handle.revision.decision_epoch)
            return True

    def commit(self, epoch: int, covered: bool = False):
        with self.lock:
            revision, payload = snapshot(epoch, covered)
            self.receiver.prepare(revision, payload)
            self.receiver.commit(revision)
            if self.before_freeze:
                self.before_freeze()
            # Fixed-version read-only observation of the existing fence owner.
            with self.registry._lock:
                removed = self.token.serial in self.registry._request_fenced
                deadline = self.registry._connection_deadlines.get(self.token.serial)
            if removed and self.frozen is None:
                self.frozen = self.largest_admitted
            self.trace.add("commit_return", revision=epoch, frozen=self.frozen,
                           first_deadline=deadline)
            return revision

    def finish(self, stream_id: int):
        with self.lock:
            handle = self.handles.pop(stream_id, None)
            if handle is not None:
                self.registry.finish_request(handle)
                self.trace.add("handle_finished", stream_id=stream_id)

    def deadline(self):
        with self.lock, self.registry._lock:
            return self.registry._connection_deadlines.get(self.token.serial)

    def disconnect(self):
        with self.lock:
            self.registry.release(self.token)
            self.handles.clear()
            self.trace.add("modeled_disconnect")


class Session:
    """Real Http2Server and h2 peer joined by an explicit in-memory writer.

No HttpFlow, real requestheaders hook, TLS, origin, or IPC server is involved.
Only the receiving thread touches H2; commit may run on a different thread.
"""

    def __init__(self, trace: Trace, window: int = 65535):
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.settings import SettingCodes
        from mitmproxy import connection
        from mitmproxy.proxy.context import Context
        from mitmproxy.proxy.layers.http._http2 import Http2Server

        self.trace = trace
        self.gate = AdmissionBridge(trace)
        self.client = connection.Client(peername=("127.0.0.1", 11000), sockname=("127.0.0.1", 11001))
        options = SimpleNamespace(proxy_debug=False, validate_inbound_headers=True)
        self.layer = Http2Server(Context(self.client, options))
        self.peer = H2Connection(config=H2Configuration(client_side=True))
        self.output = []
        self.pending_data = []
        self.peer_events = []
        self.dispatches = []
        self.body_dispatches = []
        self.accepted = set()
        self.ended_written = set()
        self.close_requested = False
        self.goaway_sent = False
        self.disconnected = False
        self.owner_thread = threading.get_ident()
        from mitmproxy.proxy import events
        self.consume(self.layer.handle_event(events.Start()))
        self.peer.initiate_connection()
        self.peer.update_settings({SettingCodes.INITIAL_WINDOW_SIZE: window})
        self.receive(self.peer.data_to_send())
        self.flush()
        self.receive(self.peer.data_to_send())
        self.flush()

    def queue(self, data):
        if data:
            frames = original.frame_metadata(data)
            self.output.append((data, frames))
            self.trace.add("protocol_output_queued", frames=frames)

    def consume(self, commands):
        from h2.errors import ErrorCodes
        from h2.exceptions import StreamClosedError
        from mitmproxy.proxy import commands as cmd
        from mitmproxy.proxy.layers.http import RequestData, RequestHeaders, RequestProtocolError
        from mitmproxy.proxy.layers.http._base import ReceiveHttp

        for command in commands:
            if isinstance(command, cmd.SendData):
                self.queue(command.data)
            elif isinstance(command, cmd.CloseConnection):
                self.close_requested = True
                self.trace.add("close_requested")
            elif isinstance(command, ReceiveHttp):
                event = command.event
                if isinstance(event, RequestHeaders):
                    if self.gate.admit(event.stream_id):
                        self.accepted.add(event.stream_id)
                        self.dispatches.append(event.stream_id)
                        self.trace.add("simulated_upstream_dispatch", stream_id=event.stream_id)
                    else:
                        # Normal protocol reset; no fabricated frame or state reset.
                        if self.layer.is_closed(event.stream_id):
                            # receive_data parses the entire batch first. A peer
                            # RST or GOAWAY later in it may already be terminal.
                            self.trace.add("refused_already_terminal", stream_id=event.stream_id)
                        else:
                            try:
                                self.layer.h2_conn.reset_stream(event.stream_id, ErrorCodes.REFUSED_STREAM)
                            except StreamClosedError:
                                self.trace.add("refused_already_terminal", stream_id=event.stream_id)
                            else:
                                self.queue(self.layer.h2_conn.data_to_send())
                        # Mirror terminal cleanup in the fixed-version layer table.
                        self.layer.streams.pop(event.stream_id, None)
                elif isinstance(event, RequestProtocolError):
                    self.gate.finish(event.stream_id)
                    self.ended_written.add(event.stream_id)
                    self.trace.add("stream_terminal_error", stream_id=event.stream_id)
                elif isinstance(event, RequestData) and event.stream_id in self.accepted:
                    self.body_dispatches.append(event.stream_id)
                    self.trace.add("simulated_upstream_body", stream_id=event.stream_id,
                                   length=len(event.data))

    def receive(self, data):
        from mitmproxy.proxy import events
        assert threading.get_ident() == self.owner_thread
        if data:
            self.consume(self.layer.handle_event(events.DataReceived(self.client, data)))

    def request(self, stream_id: int, marker: str = "same-indexed-value"):
        self.peer.send_headers(stream_id, [
            (":method", "GET"), (":scheme", "https"),
            (":authority", "bound.example.com"), (":path", "/v1/shared"),
            ("x-synthetic-repeated", marker),
        ], end_stream=True)
        self.receive(self.peer.data_to_send())

    def respond(self, stream_id: int, body: bytes = b"complete"):
        from mitmproxy import http
        from mitmproxy.proxy.layers.http import ResponseData, ResponseEndOfMessage, ResponseHeaders

        # Models why a completed response hook is not writer completion.
        self.gate.finish(stream_id)
        response = http.Response.make(200)
        response.headers.pop("content-length", None)
        for event in (ResponseHeaders(stream_id, response), ResponseData(stream_id, body),
                      ResponseEndOfMessage(stream_id)):
            self.consume(self.layer.handle_event(event))

    def flush(self):
        from h2.events import ConnectionTerminated, DataReceived, StreamEnded, StreamReset

        while self.output:
            data, frames = self.output.pop(0)
            # Independent peer observations do not drive readiness. The explicit
            # modeled writer callback below does; a real implementation needs its
            # own reviewed transport boundary and real-wire verification.
            for event in self.peer.receive_data(data):
                self.peer_events.append(event)
                if isinstance(event, DataReceived):
                    self.pending_data.append(event)
                elif isinstance(event, StreamEnded):
                    self.trace.add("peer_observed_end_stream", stream_id=event.stream_id)
                elif isinstance(event, StreamReset):
                    self.trace.add("peer_observed_reset", stream_id=event.stream_id,
                                   error_code=int(event.error_code))
                elif isinstance(event, ConnectionTerminated):
                    self.trace.add("peer_observed_goaway", last_stream_id=event.last_stream_id,
                                   error_code=int(event.error_code))
            for frame in frames:
                if frame["end_stream"]:
                    self.ended_written.add(frame["stream_id"])
            self.trace.add("modeled_writer_completed", frames=frames)

    def acknowledge_data(self):
        for event in self.pending_data:
            self.peer.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
        self.pending_data.clear()
        self.receive(self.peer.data_to_send())

    def try_finish_drain(self) -> bool:
        with self.gate.lock:
            if self.goaway_sent or self.close_requested or self.gate.frozen is None:
                return False
            if (self.gate.handles or self.output or self.layer.h2_conn.stream_buffers
                    or self.layer.h2_conn.stream_trailers or not self.accepted <= self.ended_written
                    or any(not self.layer.is_closed(stream_id) for stream_id in self.accepted)):
                return False
            frozen = self.gate.frozen
        # The fence and frozen bound cannot be reversed by a later commit.
        self.layer.h2_conn.close_connection(error_code=0, last_stream_id=frozen)
        self.queue(self.layer.h2_conn.data_to_send())
        self.goaway_sent = True
        self.trace.add("final_goaway_queued", last_stream_id=frozen)
        # Normal terminal layer path prevents a second GOAWAY from late input
        # using highest_inbound_stream_id and increasing the frozen bound.
        self.consume(self.layer.close_connection("delayed probe drained"))
        return True

    def deadline_sweep(self):
        if self.gate.token in self.gate.registry.expired_connections():
            self.consume(self.layer.close_connection("delayed probe deadline"))

    def confirm_disconnect(self):
        from mitmproxy.proxy import events
        if self.disconnected:
            return
        self.consume(self.layer.handle_event(events.ConnectionClosed(self.client)))
        self.disconnected = True
        if self.output:
            self.trace.add("modeled_disconnect_discards_output", chunks=len(self.output))
            self.output.clear()
        self.gate.disconnect()


def _require(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)


def _d1(trace):
    session = Session(trace)
    session.request(1)
    session.gate.commit(2)
    session.request(3, marker="refused-table-entry")
    session.request(5, marker="refused-table-entry")
    session.flush()
    resets = [(e["stream_id"], e["error_code"]) for e in trace.events if e["kind"] == "peer_observed_reset"]
    _require(resets == [(3, 7), (5, 7)], "higher streams were not explicitly refused")
    _require(session.dispatches == [1], "refused stream reached simulated upstream")
    _require((b"x-synthetic-repeated", b"refused-table-entry") in
             session.layer.h2_conn.decoder.header_table.dynamic_entries, "HPACK state not retained")
    session.respond(1)
    _require(not session.try_finish_drain(), "queued END_STREAM mistaken for write completion")
    session.flush()
    _require(session.try_finish_drain(), "completed old stream did not permit final GOAWAY")
    # An already prepared in-flight request arrives after final GOAWAY but
    # before peer receipt. The normal done handler must ignore it, not produce
    # a second GOAWAY with the larger highest_inbound_stream_id.
    session.peer.send_headers(7, [(":method", "GET"), (":scheme", "https"),
                                 (":authority", "bound.example.com"), (":path", "/v1/late")], end_stream=True)
    queued = len(session.output)
    session.receive(session.peer.data_to_send())
    _require(len(session.output) == queued, "late frame generated a second GOAWAY")
    session.flush()
    goaway = [e for e in trace.events if e["kind"] == "peer_observed_goaway"]
    _require(len(goaway) == 1 and goaway[0]["last_stream_id"] == 1, "frozen GOAWAY bound changed")
    _require(session.close_requested, "empty transport was not terminal")
    session.confirm_disconnect()


def _d2(trace):
    start = len(trace.events)
    session = Session(trace, window=8)
    session.request(1)
    session.gate.commit(2)
    session.respond(1, b"x" * 33)
    _require(not session.gate.handles, "response hook did not finish handle")
    session.flush()
    _require(session.layer.h2_conn.stream_buffers and not session.try_finish_drain(),
             "flow-control backlog was mistaken for completed drain")
    for _ in range(16):
        if not session.layer.h2_conn.stream_buffers:
            break
        _require(session.layer.h2_conn.state_machine.state.name != "CLOSED", "GOAWAY sent before old flow control")
        session.acknowledge_data()
        _require(not session.try_finish_drain(), "queued final bytes were treated as written")
        session.flush()
    _require(not session.layer.h2_conn.stream_buffers, "flow-control progress exceeded bounded rounds")
    _require(session.try_finish_drain(), "drained output did not permit GOAWAY")
    session.flush()
    ends = [e["sequence"] for e in trace.events[start:] if e["kind"] == "peer_observed_end_stream"]
    final = [e["sequence"] for e in trace.events[start:] if e["kind"] == "peer_observed_goaway"]
    _require(ends and final and max(ends) < min(final), "peer did not observe END_STREAM before GOAWAY")
    session.confirm_disconnect()


def _d3(trace):
    for admission_first in (True, False):
        gate = AdmissionBridge(trace)
        entered, release, attempted = threading.Event(), threading.Event(), threading.Event()

        def pause():
            entered.set()
            _require(release.wait(5), "race barrier timed out")

        def second():
            attempted.set()
            return gate.commit(2) if admission_first else gate.admit(1)

        if admission_first:
            gate.before_map = pause
        else:
            gate.before_freeze = pause
        results, errors = {}, []
        second_done = threading.Event()

        def invoke(name, operation):
            try:
                results[name] = operation()
            except Exception as exc:
                errors.append(exc)
            finally:
                if name == "second":
                    second_done.set()

        first_operation = (lambda: gate.admit(1)) if admission_first else (lambda: gate.commit(2))
        first = threading.Thread(target=invoke, args=("first", first_operation), daemon=True)
        later = threading.Thread(target=invoke, args=("second", second), daemon=True)
        first.start()
        try:
            _require(entered.wait(5), "race barrier not reached")
            later.start()
            _require(attempted.wait(5) and not second_done.is_set(), "ordering boundary did not hold competitor")
        finally:
            release.set()
            first.join(5)
            if later.ident is not None:
                later.join(5)
        _require(not first.is_alive() and not later.is_alive(), "race worker did not terminate")
        if errors:
            raise errors[0]
        first_result, second_result = results["first"], results["second"]
        _require(gate.frozen == (1 if admission_first else 0), "cutover upper bound raced with mapping")
        _require(first_result is True if admission_first else second_result is False, "race admission outcome wrong")
        _require(not gate.admit(3), "post-return admission passed fence")
        gate.disconnect()


def _d4(trace):
    session = Session(trace)
    session.request(1)
    session.request(3)
    session.peer.reset_stream(1, error_code=8)
    session.receive(session.peer.data_to_send())
    _require(set(session.gate.handles) == {3}, "one reset released another stream")
    session.gate.commit(2)
    deadline = session.gate.deadline()
    session.gate.commit(2)
    session.gate.commit(3, covered=True)
    _require(session.gate.deadline() == deadline and session.gate.frozen == 3,
             "retry/re-add extended deadline or changed frozen boundary")
    session.request(5)
    session.flush()
    _require(session.dispatches == [1, 3], "re-add revived old connection")
    time.sleep(max(0, deadline - time.monotonic()) + 0.01)
    session.deadline_sweep()
    _require(session.close_requested and not session.goaway_sent, "deadline mislabeled as graceful completion")
    session.confirm_disconnect()
    session.confirm_disconnect()
    _require(not session.gate.registry.pending_requests() and not session.gate.handles, "disconnect leaked handles")


def inspect_delayed_transport() -> dict:
    versions = original.dependency_versions()
    trace = Trace()
    cases = []
    for name, run in (("D1", _d1), ("D2", _d2), ("D3", _d3), ("D4", _d4)):
        trace.add("case_started", case=name)
        try:
            run(trace)
        except Exception as exc:
            cases.append({"id": name, "status": "fail", "reason": type(exc).__name__ + ": " + str(exc)})
        else:
            cases.append({"id": name, "status": "pass", "reason": "isolated in-process candidate checks passed"})
        trace.add("case_finished", case=name, status=cases[-1]["status"])
    return {"schema_version": 1, "mode": MODE, "dependencies": versions,
            "original_E1_passed": False, "live_transport_executed": False,
            "cases": cases, "events": trace.events}
