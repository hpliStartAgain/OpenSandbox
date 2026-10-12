#!/usr/bin/env python3
# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Test-only real TLS W2 experiment, never production/E1 acceptance.

Run with the pinned mitmproxy Python environment and a new --artifacts path.
Only loopback sockets are used. Exit 0 means this W2 evidence passed; 2 means
the environment/dependencies blocked execution; 1 means protocol/evidence
failure. No other W case, authenticated IPC, or client retry is exercised.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import http.server
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[3]
EGRESS = ROOT / "components/egress"
ADDON = EGRESS / "tests/fixtures/h2_delayed_goaway_wire_addon.py"
BASE_SHA = "65f621b7bbefc5f914e76998b87973fce877cb8c"
BASE_TREE = "a31af9fa886dee43bcdfc1047ba7e740e310afb9"
MODEL_CHECKPOINT_TREE = "a4cd58ed39b05f088a6bfcae1178ebb074ce5cd8"
MODE = "real-tls-delayed-goaway-w2"
CLIENT = "real-client-tls-read"
PROXY = "real-mitmproxy-command-boundary"
ORIGIN = "real-loopback-https-origin"
PINS = {"mitmproxy": "11.0.2", "h2": "4.1.0", "hyperframe": "6.0.1"}
REQUIRED = ("W0", "W1", "W2", "W3", "W4")
DEADLINE_SECONDS = 15
BODY = (b"synthetic-w2-response-" * 7000)[:131072 + 17]
BODY_SHA256 = hashlib.sha256(BODY).hexdigest()
MAX_LOG_BYTES = 65536
SOURCE_PATHS = (
    "components/egress/scripts/h2_delayed_goaway_wire.py",
    "components/egress/scripts/test_h2_delayed_goaway_wire.py",
    "components/egress/tests/fixtures/h2_delayed_goaway_wire_addon.py",
    "components/egress/tests/fixtures/h2_delayed_goaway_probe.py",
    "components/egress/tests/fixtures/h2_transport_probe.py",
    "components/egress/tests/test_credential_bound_runtime.py",
    "components/egress/mitmscripts/revision_publication.py",
    "components/egress/mitmscripts/revision_receiver.py",
    "components/egress/mitmscripts/tls_registry.py",
)


class Blocked(RuntimeError):
    """A missing capability, never a skipped passing case."""


class EvidenceFailure(RuntimeError):
    """Fixed, synthetic-only diagnostics suitable for saved evidence."""


def add_event(items: list, provenance: str, kind: str, **values) -> dict:
    event = {"sequence": len(items) + 1, "monotonic_ns": time.monotonic_ns(),
             "provenance": provenance, "kind": kind, **values}
    items.append(event)
    return event


class FrameDecoder:
    """Incremental hyperframe decoding of bytes actually read from TLS.

    TLS records and recv calls need not align with H2 frames. Retain metadata
    only; a separate h2 connection independently validates protocol semantics.
    """

    def __init__(self):
        self.pending = bytearray()
        self.frames = []

    def feed(self, data: bytes) -> list[dict]:
        from hyperframe.frame import DataFrame, Frame, GoAwayFrame, RstStreamFrame

        self.pending.extend(data)
        parsed = []
        while len(self.pending) >= 9:
            frame, length = Frame.parse_frame_header(memoryview(bytes(self.pending[:9])))
            if length > 16384:
                raise EvidenceFailure("peer exceeded the advertised maximum frame size")
            if len(self.pending) < 9 + length:
                break
            frame.parse_body(memoryview(bytes(self.pending[9:9 + length])))
            del self.pending[:9 + length]
            fields = {"type": type(frame).__name__, "stream_id": frame.stream_id,
                      "length": length, "end_stream": "END_STREAM" in frame.flags}
            if isinstance(frame, DataFrame):
                fields.update(data_length=len(frame.data),
                              data_sha256=hashlib.sha256(frame.data).hexdigest())
            if isinstance(frame, (GoAwayFrame, RstStreamFrame)):
                fields["error_code"] = int(frame.error_code)
            if isinstance(frame, GoAwayFrame):
                fields["last_stream_id"] = frame.last_stream_id
            parsed.append(add_event(self.frames, CLIENT, "frame", **fields))
        return parsed

    def finish(self) -> None:
        if self.pending:
            raise EvidenceFailure("EOF interrupted an HTTP/2 frame")


def indexed_header_fields(block: bytes) -> list[int]:
    """Read representation boundaries, including Huffman strings, without logging headers."""
    from hpack.hpack import decode_integer

    indexes = []
    offset = 0

    def integer(bits):
        nonlocal offset
        value, consumed = decode_integer(block[offset:], bits)
        offset += consumed
        return value

    def string():
        nonlocal offset
        length = integer(7)
        offset += length
        if offset > len(block):
            raise EvidenceFailure("truncated outgoing HPACK string")

    while offset < len(block):
        first = block[offset]
        if first & 0x80:
            indexes.append(integer(7))
        elif first & 0x20 and not first & 0x40:
            integer(5)
        else:
            name_index = integer(6 if first & 0x40 else 4)
            if not name_index:
                string()
            string()
    return indexes


def header_block(data: bytes, stream_id: int) -> bytes:
    from hyperframe.frame import ContinuationFrame, Frame, HeadersFrame

    block = b""
    while data:
        if len(data) < 9:
            raise EvidenceFailure("truncated locally encoded header frame")
        frame, length = Frame.parse_frame_header(memoryview(data[:9]))
        if len(data) < length + 9:
            raise EvidenceFailure("truncated locally encoded header payload")
        frame.parse_body(memoryview(data[9:9 + length]))
        if frame.stream_id == stream_id and isinstance(frame, (HeadersFrame, ContinuationFrame)):
            block += frame.data
        data = data[9 + length:]
    return block


def dependency_versions() -> dict:
    result = {}
    for name in PINS:
        try:
            result[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            result[name] = None
    return result


def git_metadata() -> tuple[dict, bytes]:
    def git(*args, allowed=(0,)):
        value = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, timeout=5)
        if value.returncode not in allowed:
            raise EvidenceFailure("git source provenance unavailable")
        return value.stdout

    head = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    base = git("rev-parse", "--verify", BASE_SHA + "^{commit}").decode().strip()
    base_tree = git("rev-parse", BASE_SHA + "^{tree}").decode().strip()
    git("merge-base", "--is-ancestor", BASE_SHA, "HEAD")
    if base != BASE_SHA or base_tree != BASE_TREE:
        raise EvidenceFailure("preserved negative baseline identity changed")
    diff = git("diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD", "--", *SOURCE_PATHS)
    untracked = git("ls-files", "--others", "--exclude-standard", "-z", "--", *SOURCE_PATHS)
    for path in untracked.decode().split("\0"):
        if path:
            diff += git("diff", "--no-ext-diff", "--no-textconv", "--binary", "--no-index",
                        "--", "/dev/null", path, allowed=(0, 1))
    return {
        "base_sha": base, "base_tree_sha": base_tree, "base_is_ancestor": True,
        "model_checkpoint_tree": MODEL_CHECKPOINT_TREE, "head_sha": head, "tree_sha": tree,
        "dirty": bool(git("status", "--porcelain", "--untracked-files=normal")),
        "task_sources_dirty": bool(diff), "dirty_diff_scope": list(SOURCE_PATHS),
        "dirty_diff_sha256": hashlib.sha256(diff).hexdigest(), "dirty_diff_file": "dirty.diff",
        "source_sha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                          for path in SOURCE_PATHS},
    }, diff


def read_events(path: Path) -> list:
    if not path.exists():
        return []
    data = path.read_bytes()
    if len(data) > 2 * 1024 * 1024:
        raise EvidenceFailure("proxy event log exceeded the fixture limit")
    # A concurrent append can leave a partial final line until the next poll.
    complete = data[:data.rfind(b"\n") + 1]
    return [json.loads(line) for line in complete.splitlines() if line]


def validate_sequence(events: list, provenance: str) -> None:
    previous = 0
    for sequence, event in enumerate(events, 1):
        if (event.get("sequence") != sequence or event.get("provenance") != provenance
                or type(event.get("monotonic_ns")) is not int
                or event["monotonic_ns"] < previous or event["monotonic_ns"] <= 0):
            raise EvidenceFailure("evidence sequence/provenance is invalid")
        previous = event["monotonic_ns"]


def validate_evidence(evidence: dict) -> None:
    """Fail closed on missing wire, origin, hook, backpressure, or close evidence."""
    frames, events = evidence["client_frames"], evidence["client_events"]
    proxy, origins = evidence["proxy_events"], evidence["origin_requests"]
    for items, provenance in ((frames, CLIENT), (events, CLIENT), (proxy, PROXY), (origins, ORIGIN)):
        validate_sequence(items, provenance)

    def require(condition, reason):
        if not condition:
            raise EvidenceFailure(reason)

    def one(items, kind):
        matching = [event for event in items if event["kind"] == kind]
        require(len(matching) == 1, "missing or duplicated " + kind)
        return matching[0]

    observations = evidence["observations"]
    require(not any(item["kind"] in ("deadline_forced_close", "actual_flow_error") for item in proxy)
            and not observations.get("origin_handler_error"), "forced close or actual flow error cannot pass W2")
    require(observations.get("tls_alpn") == "h2" and observations.get("tls_verified") is True
            and observations.get("upstream_tls_verification") is True,
            "verified client/origin TLS and ALPN evidence missing")
    require(observations.get("body_length") == len(BODY)
            and observations.get("body_sha256") == BODY_SHA256, "old response body was truncated or changed")
    require(observations.get("hpack_inserted_on_stream_3") is True
            and observations.get("hpack_reused_on_stream_5") is True,
            "refused-stream HPACK insertion/reuse was not established")
    require(observations.get("automatic_retry") is False, "fixture must not automatically retry refusals")
    require(len(origins) == 1 and origins[0].get("method") == "GET"
            and origins[0].get("path") == "/v1/old", "origin observed a missing or post-fence request")
    admitted = [item for item in proxy if item["kind"] == "admitted"]
    refused = [item for item in proxy if item["kind"] == "admission_refused"]
    require([item.get("stream_id") for item in admitted] == [1], "admitted stream set is not exactly stream 1")
    require([item.get("stream_id") for item in refused] == [3, 5], "post-fence refusal set is not exactly streams 3 and 5")
    commit = one(proxy, "commit_return")
    require(commit.get("frozen") == 1 and admitted[0]["sequence"] < commit["sequence"]
            < refused[0]["sequence"], "frozen admission bound/order is invalid")
    finished = one(proxy, "response_handle_finished")
    queued = one(proxy, "final_goaway_queued")
    close = one(proxy, "close_requested")
    disconnected = one(proxy, "actual_disconnect")
    require(finished.get("stream_id") == 1 and finished.get("buffered_streams", 0) > 0
            and queued.get("last_stream_id") == 1
            and finished["sequence"] < queued["sequence"] < close["sequence"] < disconnected["sequence"],
            "proxy completion, GOAWAY and actual disconnect ordering is invalid")
    output = [(item, frame) for item in proxy if item["kind"] == "protocol_output"
              for frame in item.get("frames", [])]
    queued_ends = [item for item, frame in output if frame.get("stream_id") == 1 and frame.get("end_stream")]
    queued_goaways = [(item, frame) for item, frame in output if frame.get("type") == "GoAwayFrame"]
    require(len(queued_ends) == 1 and len(queued_goaways) == 1
            and queued_ends[0]["sequence"] < queued["sequence"] < queued_goaways[0][0]["sequence"]
            and queued_goaways[0][1].get("last_stream_id") == 1,
            "protocol-command END_STREAM/GOAWAY metadata is missing or out of order")
    pause, resume = one(events, "credit_paused"), one(events, "credit_resumed")
    require(pause["monotonic_ns"] < finished["monotonic_ns"] < resume["monotonic_ns"]
            < queued["monotonic_ns"] and 0 < resume.get("body_length", 0) <= 1024,
            "no post-response-hook withheld-credit interval was established")
    resets = [item for item in frames if item["type"] == "RstStreamFrame"]
    require([(item["stream_id"], item.get("error_code")) for item in resets] == [(3, 7), (5, 7)],
            "wire refusals are not exactly RST_STREAM(REFUSED_STREAM) for 3 and 5")
    goaways = [item for item in frames if item["type"] == "GoAwayFrame"]
    require(len(goaways) == 1, "wire must contain exactly one GOAWAY")
    goaway = goaways[0]
    require(goaway.get("last_stream_id") == 1 and goaway.get("error_code") == 0,
            "wire GOAWAY bound/error is invalid")
    endings = [item for item in frames if item["stream_id"] == 1 and item["end_stream"]]
    require(len(endings) == 1 and endings[0]["sequence"] < goaway["sequence"]
            and goaway["sequence"] == len(frames), "END_STREAM did not precede final GOAWAY")
    data_frames = [item for item in frames if item["type"] == "DataFrame"]
    require(all(item["stream_id"] == 1 for item in data_frames)
            and sum(item["data_length"] for item in data_frames) == len(BODY),
            "wire DATA length/stream differs from the complete old response")
    require(all(item["sequence"] < goaway["sequence"] for item in resets)
            and goaway["monotonic_ns"] > resume["monotonic_ns"], "premature GOAWAY under withheld credit")
    response = one(events, "response_headers")
    require(response.get("stream_id") == 1 and response.get("status") == "200", "old response status was not 200")
    ended, terminated, eof = one(events, "stream_ended"), one(events, "connection_terminated"), one(events, "eof")
    require(ended.get("stream_id") == 1 and terminated.get("last_stream_id") == 1
            and terminated.get("error_code") == 0
            and ended["sequence"] < terminated["sequence"] < eof["sequence"],
            "independent h2 END_STREAM/GOAWAY/EOF evidence is invalid")
    require([(item.get("stream_id"), item.get("error_code")) for item in events
             if item["kind"] == "stream_reset"] == [(3, 7), (5, 7)],
            "independent h2 reset evidence differs from actual frames")


def empty_evidence() -> dict:
    return {"client_frames": [], "client_events": [], "proxy_events": [],
            "origin_requests": [], "observations": {"automatic_retry": False},
            "cleanup": {"status": "not-started", "remaining_probe_resources": []}, "proxy_log": ""}


def execute_wire(evidence: dict) -> None:
    """Own all subprocess/socket resources; preserve partial evidence on failure."""
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import ConnectionTerminated, DataReceived, ResponseReceived, StreamEnded, StreamReset
    from h2.settings import SettingCodes

    spec = importlib.util.spec_from_file_location("_w2_origin_fixture", EGRESS / "tests/test_credential_bound_runtime.py")
    origin_fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(origin_fixture)
    deadline = time.monotonic() + DEADLINE_SECONDS
    process = origin = origin_thread = log_thread = tls = raw = None
    release = threading.Event()
    log = bytearray()
    log_total = 0
    decoder = FrameDecoder()
    evidence["client_frames"] = decoder.frames
    events, observations = evidence["client_events"], evidence["observations"]
    pending_credit = []
    body_hash = hashlib.sha256()
    body_length = 0
    eof = False
    credit_enabled = False
    cleanup_errors = []

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise EvidenceFailure("15-second W2 deadline expired")
        return value

    def pump():
        nonlocal body_length, eof
        remaining()
        if eof:
            return
        tls.settimeout(min(0.05, remaining()))
        try:
            data = tls.recv(65536)
        except socket.timeout:
            return
        if not data:
            decoder.finish()
            eof = True
            add_event(events, CLIENT, "eof")
            return
        decoder.feed(data)
        for event in peer.receive_data(data):
            if isinstance(event, DataReceived):
                if event.stream_id != 1:
                    raise EvidenceFailure("unexpected response DATA stream")
                body_hash.update(event.data)
                body_length += len(event.data)
                if body_length > len(BODY):
                    raise EvidenceFailure("response body exceeded the synthetic fixture")
                pending_credit.append((event.flow_controlled_length, event.stream_id))
            elif isinstance(event, ResponseReceived):
                status = dict(event.headers).get(":status")
                add_event(events, CLIENT, "response_headers", stream_id=event.stream_id, status=status)
            elif isinstance(event, StreamReset):
                add_event(events, CLIENT, "stream_reset", stream_id=event.stream_id, error_code=int(event.error_code))
            elif isinstance(event, StreamEnded):
                add_event(events, CLIENT, "stream_ended", stream_id=event.stream_id)
            elif isinstance(event, ConnectionTerminated):
                add_event(events, CLIENT, "connection_terminated", last_stream_id=event.last_stream_id,
                          error_code=int(event.error_code))
        observations.update(body_length=body_length, body_sha256=body_hash.hexdigest())
        if credit_enabled and not any(item["kind"] == "connection_terminated" for item in events):
            for length, stream_id in pending_credit:
                peer.acknowledge_received_data(length, stream_id)
            pending_credit.clear()
        outgoing = peer.data_to_send()
        if outgoing:
            tls.sendall(outgoing)

    with tempfile.TemporaryDirectory(prefix="osep-w2-") as temporary:
        directory = Path(temporary)
        proxy_path = directory / "proxy-events.jsonl"

        def refresh():
            evidence["proxy_events"] = read_events(proxy_path)
            return evidence["proxy_events"]

        def wait(predicate, *, receive=False):
            while not predicate():
                remaining()
                if process is not None and process.poll() is not None:
                    raise EvidenceFailure("mitmdump exited before W2 completed")
                if receive:
                    pump()
                    if eof and not predicate():
                        raise EvidenceFailure("client EOF before required W2 observation")
                else:
                    time.sleep(min(0.02, remaining()))

        def proxy_has(kind, **values):
            return any(item.get("kind") == kind and all(item.get(key) == value for key, value in values.items())
                       for item in refresh())

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format, *_args):
                pass

            def do_GET(self):
                add_event(evidence["origin_requests"], ORIGIN, "request", method="GET", path=self.path)
                if not release.wait(max(0, deadline - time.monotonic())):
                    return
                try:
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(BODY)))
                    self.send_header("Content-Type", "application/octet-stream")
                    self.end_headers()
                    self.wfile.write(BODY)
                    self.wfile.flush()
                except OSError:
                    pass

        class Origin(origin_fixture.TLSOriginServer):
            # The shared helper's 60-second handshake/read waits are too long
            # for this bounded fixture; keep the same verified TLS server API.
            def __init__(self, *args):
                self.accepted = []
                self.handlers = []
                super().__init__(*args)

            def process_request_thread(self, request, client_address):
                self.handlers.append(threading.current_thread())
                super().process_request_thread(request, client_address)

            def get_request(self):
                sock, address = self.socket.accept()
                sock.settimeout(max(0.01, deadline - time.monotonic()))
                self.accepted.append(sock)
                try:
                    wrapped = self.tls_context.wrap_socket(sock, server_side=True)
                except Exception:
                    sock.close()
                    raise
                self.accepted.append(wrapped)
                wrapped.settimeout(max(0.01, deadline - time.monotonic()))
                return wrapped, address

            def handle_error(self, _request, _client_address):
                # No uncontrolled traceback can copy request data into logs.
                observations["origin_handler_error"] = True

        try:
            origin_fixture.generate_origin_certificate(directory)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(directory / "origin.pem"))
            context.set_alpn_protocols(["http/1.1"])
            origin = Origin(("127.0.0.1", 0), Handler, context)
            origin_thread = threading.Thread(target=origin.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            origin_thread.start()
            origin_port = origin.server_address[1]
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                proxy_port = reservation.getsockname()[1]
            # The interpreter owns the dependency check and subprocess. Do not
            # accidentally invoke a different global mitmdump installation.
            executable = Path(sys.executable).parent / "mitmdump"
            command = ([str(executable)] if executable.is_file() else
                       [sys.executable, "-c", "from mitmproxy.tools.main import mitmdump; mitmdump()"])
            command += ["--listen-host", "127.0.0.1", "--listen-port", str(proxy_port),
                        "--set", "confdir=" + str(directory / "ca"),
                        "--set", "connection_strategy=lazy", "--set", "flow_detail=0",
                        "--set", "ssl_verify_upstream_trusted_ca=" + str(directory / "origin-ca.pem"),
                        "-s", str(ADDON)]
            # No inherited credentials, existing proxy configuration, or TLS
            # keylog environment is passed into the synthetic subprocess.
            environment = {"PATH": os.defpath, "HOME": str(directory), "LC_ALL": "C",
                           "PYTHONNOUSERSITE": "1", "OSEP_W2_DIRECTORY": str(directory)}
            process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=True)

            def read_log():
                nonlocal log_total
                while True:
                    chunk = process.stdout.read(4096)
                    if not chunk:
                        return
                    log_total += len(chunk)
                    log.extend(chunk)
                    if len(log) > MAX_LOG_BYTES:
                        del log[:-MAX_LOG_BYTES]

            log_thread = threading.Thread(target=read_log, daemon=True)
            log_thread.start()
            ca = directory / "ca/mitmproxy-ca-cert.pem"
            wait(lambda: ca.is_file())
            while raw is None:
                remaining()
                try:
                    raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=min(0.1, remaining()))
                except ConnectionRefusedError:
                    if process.poll() is not None:
                        raise EvidenceFailure("mitmdump exited before listening")
                    time.sleep(min(0.02, remaining()))
            raw.settimeout(remaining())
            raw.sendall((f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n"
                         f"Host: 127.0.0.1:{origin_port}\r\n\r\n").encode())
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = raw.recv(4096)
                if not chunk or len(head) + len(chunk) > 16384:
                    raise EvidenceFailure("invalid CONNECT response")
                head += chunk
            header, surplus = head.split(b"\r\n\r\n", 1)
            if not header.startswith(b"HTTP/1.1 200 ") or surplus:
                raise EvidenceFailure("CONNECT did not establish a clean tunnel")
            # Construct directly: create_default_context would consult the
            # parent process's SSLKEYLOGFILE environment variable.
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_context.load_verify_locations(cafile=str(ca))
            client_context.set_alpn_protocols(["h2"])
            tls = client_context.wrap_socket(raw, server_hostname="bound.example.com")
            observations.update(tls_alpn=tls.selected_alpn_protocol(), tls_verified=True,
                                upstream_tls_verification=True)
            if observations["tls_alpn"] != "h2":
                raise EvidenceFailure("proxy did not negotiate h2")
            peer = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
            peer.initiate_connection()
            peer.update_settings({SettingCodes.INITIAL_WINDOW_SIZE: 1024})
            tls.sendall(peer.data_to_send())

            def request(stream_id, path, extra=()):
                peer.send_headers(stream_id, [(":method", "GET"), (":scheme", "https"),
                                  (":authority", f"bound.example.com:{origin_port}"), (":path", path), *extra],
                                  end_stream=True)
                data = peer.data_to_send()
                tls.sendall(data)
                return data

            request(1, "/v1/old")
            wait(lambda: proxy_has("admitted", stream_id=1) and bool(evidence["origin_requests"]), receive=True)
            pending_fence = directory / "fence.pending"
            pending_fence.write_text('{"action":"fence"}\n')
            os.replace(pending_fence, directory / "fence.json")
            wait(lambda: proxy_has("commit_return", frozen=1), receive=True)
            repeated = (b"x-w2-repeated", b"synthetic-refused-stream-index")
            if peer.encoder.header_table.search(*repeated) is not None:
                raise EvidenceFailure("HPACK marker existed before refused stream 3")
            request(3, "/v1/refused", (repeated,))
            entry = peer.encoder.header_table.search(*repeated)
            observations["hpack_inserted_on_stream_3"] = entry is not None and entry[2] == repeated[1]
            wait(lambda: any(item["kind"] == "stream_reset" and item["stream_id"] == 3 for item in events), receive=True)
            data = request(5, "/v1/refused", (repeated,))
            observations["hpack_reused_on_stream_5"] = bool(entry and entry[0] in indexed_header_fields(header_block(data, 5)))
            observations["hpack_dynamic_index"] = entry[0] if entry else None
            wait(lambda: any(item["kind"] == "stream_reset" and item["stream_id"] == 5 for item in events), receive=True)
            add_event(events, CLIENT, "credit_paused", initial_window=1024)
            release.set()
            wait(lambda: proxy_has("response_handle_finished", stream_id=1) and body_length > 0, receive=True)
            # Observe after the response hook while the stream window stays
            # exhausted. Neither h2 ack nor manual WINDOW_UPDATE runs here.
            pause_until = time.monotonic() + 0.15
            wait(lambda: time.monotonic() >= pause_until, receive=True)
            if any(item["type"] == "GoAwayFrame" for item in decoder.frames) or proxy_has("final_goaway_queued"):
                raise EvidenceFailure("GOAWAY arrived before old output credit resumed")
            add_event(events, CLIENT, "credit_resumed", body_length=body_length)
            credit_enabled = True
            for length, stream_id in pending_credit:
                peer.acknowledge_received_data(length, stream_id)
            pending_credit.clear()
            tls.sendall(peer.data_to_send())
            wait(lambda: eof, receive=True)
            wait(lambda: proxy_has("actual_disconnect"))
        finally:
            release.set()
            for stream in (tls, raw):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        cleanup_errors.append("client-close")
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        try:
                            process.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            cleanup_errors.append("mitmdump-process")
                if log_thread is not None:
                    log_thread.join(timeout=1)
                    if log_thread.is_alive():
                        cleanup_errors.append("proxy-log-thread")
                if log_thread is None or not log_thread.is_alive():
                    process.stdout.close()
            if origin is not None:
                shutdown_thread = threading.Thread(target=origin.shutdown, daemon=True)
                shutdown_thread.start()
                for stream in origin.accepted:
                    try:
                        stream.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    stream.close()
                origin.server_close()
                origin_thread.join(timeout=1)
                if origin_thread.is_alive():
                    cleanup_errors.append("origin-thread")
                shutdown_thread.join(timeout=1)
                if shutdown_thread.is_alive():
                    cleanup_errors.append("origin-shutdown-thread")
                join_deadline = time.monotonic() + 1
                for handler in origin.handlers:
                    handler.join(timeout=max(0, join_deadline - time.monotonic()))
                    if handler.is_alive():
                        cleanup_errors.append("origin-handler-thread")
            refresh()
            observations["proxy_log_bytes_total"] = log_total
            # All subprocess input is synthetic. Redact temporary locations;
            # never retain TLS private keys, raw headers, bodies or keylogs.
            evidence["proxy_log"] = log.decode("utf-8", "replace").replace(str(directory), "<temporary-fixture>")
            evidence["cleanup"] = {"status": "complete" if not cleanup_errors else "failed",
                                   "remaining_probe_resources": cleanup_errors,
                                   "temporary_tls_material": "deleted-on-context-exit",
                                   "sslkeylogfile": "not-inherited", "loopback_only": True}
    if cleanup_errors:
        raise EvidenceFailure("fixture resource cleanup was incomplete")


def make_results(status: str, reason: str, executed: bool) -> dict:
    return {
        "schema_version": 1, "mode": MODE, "status": status,
        "original_E1_passed": False, "production_ready": False, "transport_feasible": False,
        "real_ipc_executed": False, "client_library_retry_tested": False,
        "live_transport_executed": executed, "real_wire_executed": executed,
        "required_cases": list(REQUIRED),
        "cases": [{"id": case, "status": status if case == "W2" else "not-run",
                   "executed": executed if case == "W2" else False,
                   "reason": reason if case == "W2" else "outside this W2-only experiment"}
                  for case in REQUIRED],
    }


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def run(artifacts: Path, command: list[str]) -> int:
    artifacts.mkdir(parents=True, exist_ok=False)
    evidence = empty_evidence()
    versions = dependency_versions()
    manifest = {"schema_version": 1, "mode": MODE, "dependencies": versions,
                "python": {"version": platform.python_version(), "executable": sys.executable},
                "command": command, "deadline_seconds": DEADLINE_SECONDS,
                "expected_body": {"length": len(BODY), "sha256": BODY_SHA256}}
    code, status, reason = 1, "fail", "evidence collection did not complete"
    try:
        manifest["git"], diff = git_metadata()
        (artifacts / "dirty.diff").write_bytes(diff)
        mismatched = [f"{name}: expected {expected}, observed {versions.get(name) or 'missing'}"
                      for name, expected in PINS.items() if versions.get(name) != expected]
        if mismatched:
            raise Blocked("dependency pin unavailable: " + "; ".join(mismatched))
        execute_wire(evidence)
        validate_evidence(evidence)
        if evidence["cleanup"]["status"] != "complete":
            raise EvidenceFailure("fixture cleanup did not complete")
        code, status, reason = 0, "pass", "W2 complete old payload and END_STREAM precede the single frozen-bound GOAWAY and EOF"
    except (Blocked, ImportError) as exc:
        code, status = 2, "blocked"
        reason = str(exc) if isinstance(exc, Blocked) else "required dependency could not be imported"
    except OSError as exc:
        if exc.errno in (errno.EPERM, errno.EACCES, errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            code, status, reason = 2, "blocked", "local environment denied required loopback/process capability"
        else:
            reason = "transport or evidence I/O failed: " + type(exc).__name__
    except Exception as exc:
        reason = str(exc) if isinstance(exc, EvidenceFailure) else "W2 execution failed: " + type(exc).__name__
    executed = bool(evidence["client_frames"])
    for key, name in (("client_frames", "client-frames.jsonl"), ("client_events", "client-events.jsonl"),
                      ("origin_requests", "origin-requests.jsonl"), ("proxy_events", "proxy-events.jsonl")):
        (artifacts / name).write_text("".join(json.dumps(item, sort_keys=True, allow_nan=False) + "\n"
                                           for item in evidence[key]))
    (artifacts / "proxy.log").write_text(evidence["proxy_log"])
    write_json(artifacts / "wire-findings.json", {"observations": evidence["observations"],
                                                "status": status, "reason": reason})
    write_json(artifacts / "cleanup.json", evidence["cleanup"])
    write_json(artifacts / "results.json", make_results(status, reason, executed))
    manifest.update(exit_status=code, artifact_sha256={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                                     for path in artifacts.iterdir() if path.is_file()})
    write_json(artifacts / "manifest.json", manifest)
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True, help="new directory for sanitized W2 evidence")
    args = parser.parse_args()
    try:
        code = run(args.artifacts, [sys.executable, *sys.argv])
    except FileExistsError:
        parser.error("--artifacts must not already exist")
    print(json.dumps({"exit_status": code, "artifacts": str(args.artifacts), "scope": "W2 only"}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
