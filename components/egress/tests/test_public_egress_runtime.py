"""Real transparent Bprime chain in a disposable Linux network namespace.

Build pkg/publicegress's Linux test binary into .cache/publicegress.test, then:
  unshare --net -- sh -c 'ip link set lo up; OSB_DISPOSABLE_NETNS=1 ...python -m unittest ...'
Never enable this fixture on a host network namespace. It creates only local
addresses, synthetic CA/JWT/Vault data and its own temporary cgroups.
"""

from __future__ import annotations

import http.client
import base64
import hashlib
import json
import os
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from test_mitmproxy_runtime import _VaultUnixServer
from test_upstream_identity_runtime import _certificate, _jwt
from test_upstream_proxy_runtime import MITMDUMP, _ConnectProxy

REPO = Path(__file__).resolve().parents[3]
BRIDGE = REPO / ".cache/publicegress.test"
ENABLED = sys.platform == "linux" and os.environ.get("OSB_DISPOSABLE_NETNS") == "1"


def _recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("fixture socket closed")
        data.extend(chunk)
    return bytes(data)


class _DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(3)
            length = struct.unpack("!H", _recv_exact(self.request, 2))[0]
            query = _recv_exact(self.request, length)
            offset, labels = 12, []
            while query[offset]:
                size = query[offset]
                labels.append(query[offset + 1 : offset + size + 1].decode("ascii"))
                offset += size + 1
            host = ".".join(labels).lower()
            offset += 1
            qtype, _ = struct.unpack("!HH", query[offset : offset + 4])
            question = query[12 : offset + 4]
            address = self.server.records.get(host)
            answer = b""
            if address and qtype == 1:
                answer = (
                    b"\xc0\x0c"
                    + struct.pack("!HHIH", 1, 1, 30, 4)
                    + socket.inet_aton(address)
                )
            response = (
                struct.pack(
                    "!HHHHHH",
                    int.from_bytes(query[:2], "big"),
                    0x8180,
                    1,
                    bool(answer),
                    0,
                    0,
                )
                + question
                + answer
            )
            self.request.sendall(struct.pack("!H", len(response)) + response)
        except (OSError, EOFError, ValueError, IndexError):
            pass


class _DNSFixture(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _Gateway(_ConnectProxy):
    def start(self):
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("192.0.2.10", 8443))
        self._sock.listen(16)
        self.port = 8443
        threading.Thread(target=self._serve, daemon=True).start()


class _Target(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.seen.append((self.path, dict(self.headers)))
        if self.path == "/ws":
            accept = base64.b64encode(
                hashlib.sha1(
                    (
                        self.headers["Sec-WebSocket-Key"]
                        + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                    ).encode()
                ).digest()
            ).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.flush()
            head = self.rfile.read(2)
            if len(head) != 2 or not head[1] & 0x80:
                return
            size = head[1] & 0x7F
            if size > 125:
                return
            mask = self.rfile.read(4)
            payload = self.rfile.read(size)
            decoded = bytes(
                value ^ mask[index % 4] for index, value in enumerate(payload)
            )
            self.wfile.write(bytes([0x81, len(decoded)]) + decoded)
            self.wfile.flush()
            self.close_connection = True
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://private.example/")
            body = b""
        elif self.path == "/sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"data: first\n\n", b"data: second\n\n"):
                if part == b"data: second\n\n":
                    self.server.sse_second_sent = time.monotonic()
                self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                self.wfile.flush()
                time.sleep(0.5)
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            return
        else:
            self.send_response(200)
            self.send_header(
                "X-Reflected-Authorization", self.headers.get("Authorization", "")
            )
            body = b"strict-public-ok"
            if self.path == "/rebind":
                self.server.dns.records["public.example"] = "10.0.0.9"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        received = self.rfile.read(size)
        self.server.seen.append((self.path, dict(self.headers)))
        body = str(len(received)).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class _ProtocolTarget(ThreadingHTTPServer):
    def finish_request(self, request, client_address):
        if request.selected_alpn_protocol() != "h2":
            return super().finish_request(request, client_address)
        import h2.config
        import h2.connection
        import h2.events

        state = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        )
        state.initiate_connection()
        request.sendall(state.data_to_send())
        streams = {}
        request.settimeout(15)
        try:
            while data := request.recv(65536):
                for event in state.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        streams[event.stream_id] = dict(event.headers)
                    elif isinstance(event, h2.events.DataReceived):
                        state.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, h2.events.StreamEnded):
                        headers = streams.pop(event.stream_id)
                        self.seen.append((headers[":path"], headers))
                        body = b"strict-h2-ok"
                        state.send_headers(
                            event.stream_id,
                            [(":status", "200"), ("content-length", str(len(body)))],
                        )
                        state.send_data(event.stream_id, body, end_stream=True)
                request.sendall(state.data_to_send())
        except (OSError, ValueError):
            pass


def _stop_process(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    reader = getattr(proc, "_fixture_reader", None)
    if reader is not None:
        reader.join(timeout=2)
    if proc.stdout is not None:
        proc.stdout.close()


def _start_process(command, env, ready, logs, *, preexec_fn=None):
    proc = subprocess.Popen(
        command,
        env={**os.environ, **env},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        preexec_fn=preexec_fn,
    )

    def drain():
        for line in proc.stdout:
            logs.append(line.rstrip())

    proc._fixture_reader = threading.Thread(target=drain, daemon=True)
    proc._fixture_reader.start()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if any(ready in line for line in logs):
            return proc
        if proc.poll() is not None:
            _stop_process(proc)
            raise RuntimeError(f"fixture exited: {logs[-15:]}")
        time.sleep(0.05)
    _stop_process(proc)
    raise RuntimeError(f"fixture readiness timed out: {logs[-15:]}")


@unittest.skipUnless(
    ENABLED and MITMDUMP and BRIDGE.exists(),
    "requires disposable Linux netns and the compiled publicegress test bridge",
)
class PublicEgressRuntimeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="osb-strict-runtime-")
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = Path(cls.tmp.name)
        cls.root.chmod(0o755)
        Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").write_text("1024")
        cls.cgroot = Path("/sys/fs/cgroup") / f"osb-runtime-{os.getpid()}"
        cls.egress_cg, cls.app_cg = cls.cgroot / "egress", cls.cgroot / "app"
        cls.original_cg = next(
            line[3:]
            for line in Path("/proc/self/cgroup").read_text().splitlines()
            if line.startswith("0::")
        )
        cls.cgroot.mkdir()
        cls.egress_cg.mkdir()
        cls.app_cg.mkdir()

        def cleanup_cgroups():
            (
                Path("/sys/fs/cgroup") / cls.original_cg.lstrip("/") / "cgroup.procs"
            ).write_text(str(os.getpid()))
            cls.app_cg.rmdir()
            cls.egress_cg.rmdir()
            cls.cgroot.rmdir()

        cls.addClassCleanup(cleanup_cgroups)
        (cls.egress_cg / "cgroup.procs").write_text(str(os.getpid()))
        for ip in ("192.0.2.10", "192.0.2.53", "93.184.216.34", "10.0.0.9"):
            subprocess.run(
                ["ip", "addr", "add", ip + "/32", "dev", "lo"],
                check=True,
                capture_output=True,
            )
        cls.dns = _DNSFixture(("192.0.2.53", 53), _DNSHandler)
        cls.dns.records = {
            "gateway.example": "192.0.2.10",
            "public.example": "93.184.216.34",
            "private.example": "10.0.0.9",
            "internal.example": "10.0.0.9",
        }
        cls.addClassCleanup(cls.dns.server_close)
        cls.addClassCleanup(cls.dns.shutdown)
        threading.Thread(target=cls.dns.serve_forever, daemon=True).start()
        gateway_dir, target_dir, internal_dir = (
            cls.root / "gateway",
            cls.root / "target",
            cls.root / "internal",
        )
        gateway_dir.mkdir()
        target_dir.mkdir()
        internal_dir.mkdir()
        gateway_tls, cls.gateway_ca = _certificate(gateway_dir, "gateway.example")
        target_tls, cls.target_ca = _certificate(target_dir, "public.example")
        internal_tls, internal_ca = _certificate(internal_dir, "internal.example")
        trust_bundle = cls.root / "target-trust.pem"
        trust_bundle.write_bytes(cls.target_ca.read_bytes() + internal_ca.read_bytes())
        # The external gateway lives outside the Pod in production. Here it
        # remaps the approved authority to a loopback TLS fixture, since this
        # disposable netns deliberately has no outside-network route.
        target_tls.set_alpn_protocols(["h2", "http/1.1"])
        cls.target = _ProtocolTarget(("127.0.0.1", 0), _Target)
        cls.target.daemon_threads = True
        cls.target.seen = []
        cls.target.dns = cls.dns
        cls.target.socket = target_tls.wrap_socket(cls.target.socket, server_side=True)
        cls.addClassCleanup(cls.target.server_close)
        cls.addClassCleanup(cls.target.shutdown)
        threading.Thread(target=cls.target.serve_forever, daemon=True).start()
        cls.internal_targets = {}
        for port, context in ((8080, None), (8444, internal_tls)):
            internal = ThreadingHTTPServer(("10.0.0.9", port), _Target)
            internal.daemon_threads = True
            internal.seen = []
            cls.internal_targets[port] = internal
            if context:
                internal.socket = context.wrap_socket(internal.socket, server_side=True)
            cls.addClassCleanup(internal.server_close)
            cls.addClassCleanup(internal.shutdown)
            threading.Thread(target=internal.serve_forever, daemon=True).start()
        cls.gateway = _Gateway(
            gateway_tls,
            {("public.example", 443): ("127.0.0.1", cls.target.server_port)},
        )
        cls.gateway.start()
        cls.addClassCleanup(cls.gateway.stop)
        cls.identity = cls.root / "identity.jwt"
        cls.identity.write_text(_jwt("runtime"))
        cls.identity.chmod(0o644)
        cls.vault = _VaultUnixServer(
            str(cls.root / "vault.sock"),
            b'{"revision":1,"bindings":[],"redactions":[]}',
        )
        cls.vault.start()
        cls.addClassCleanup(cls.vault.stop)
        (cls.root / "vault.sock").chmod(0o666)
        cls.policy = json.dumps(
            {
                "version": 1,
                "dns_servers": ["192.0.2.53"],
                "internal_targets": [
                    {
                        "host": "internal.example",
                        "ips": ["10.0.0.9"],
                        "ports": [8080, 8444],
                    }
                ],
            }
        )
        cls.logs, cls.bridge_logs = [], []
        cls.bridge = _start_process(
            [str(BRIDGE), "-test.run=^TestRuntimeBridge$"],
            {
                "OSB_PUBLIC_RUNTIME_BRIDGE": "1",
                "OPENSANDBOX_EGRESS_PUBLIC_POLICY": cls.policy,
            },
            "OSB_TEST_BRIDGE_READY",
            cls.bridge_logs,
        )
        cls.addClassCleanup(_stop_process, cls.bridge)
        cls.confdir = cls.root / "mitm"
        cls.confdir.mkdir()
        os.chown(cls.confdir, 10042, 10042)
        # Freeze source bytes for this run; mitmproxy otherwise hot-reloads
        # a concurrently edited addon and invalidates in-flight test evidence.
        scripts = cls.root / "addons"
        shutil.copytree(REPO / "components/egress/mitmscripts", scripts)
        command = [
            "setpriv",
            "--reuid=10042",
            "--regid=10042",
            "--clear-groups",
            "--inh-caps=+net_bind_service",
            "--ambient-caps=+net_bind_service",
            "--bounding-set=-all,+net_bind_service",
            MITMDUMP,
            "--mode",
            "transparent",
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            "381",
            "--set",
            "confdir=" + str(cls.confdir),
            "--set",
            "connection_strategy=lazy",
            "--set",
            "upstream_cert=false",
            "--set",
            "rawtcp=false",
            "--set",
            "stream_large_bodies=1m",
            "--set",
            "termlog_verbosity=info",
            "--set",
            "ssl_verify_upstream_trusted_ca=" + str(trust_bundle),
        ]
        for addon in ("system.py", "public_policy.py", "upstream_proxy.py"):
            command.extend(["-s", str(scripts / addon)])

        cls.mitm = _start_process(
            command,
            {
                "PYTHONUNBUFFERED": "1",
                "OPENSANDBOX_EGRESS_PUBLIC_POLICY": cls.policy,
                "OPENSANDBOX_EGRESS_UPSTREAM_PROXY": "https://gateway.example:8443",
                "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_IDENTITY_FILE": str(cls.identity),
                "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_CA_FILE": str(cls.gateway_ca),
                "OPENSANDBOX_CREDENTIAL_PROXY_SOCKET": str(cls.root / "vault.sock"),
            },
            "upstream proxy: ready",
            cls.logs,
        )
        cls.addClassCleanup(_stop_process, cls.mitm)

    def client(self, **params):
        params = {
            "host": "public.example",
            "ip": "93.184.216.34",
            "path": "/",
            "ca": str(self.confdir / "mitmproxy-ca-cert.pem"),
            "cgroup": str(self.app_cg),
            **params,
        }
        result = subprocess.run(
            [
                "setpriv",
                "--bounding-set=-all",
                "--no-new-privs",
                sys.executable,
                str(Path(__file__).resolve()),
                "--client",
            ],
            input=json.dumps(params),
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode:
            return {"error": result.stderr[-1000:] or result.stdout[-1000:]}
        return json.loads(result.stdout)

    def test_01_public_https_and_header_isolation(self):
        result = self.client()
        self.assertEqual(
            result.get("status"), 200, (result, self.logs[-20:], self.bridge_logs[-10:])
        )
        self.assertEqual(result["body"], "strict-public-ok")
        self.assertEqual(self.gateway.requests[-1]["authority"], "public.example:443")
        self.assertTrue(
            self.gateway.requests[-1]["proxy-authorization"].startswith("Bearer ")
        )
        self.assertNotIn("Proxy-Authorization", self.target.seen[-1][1])

    def test_02_binding_denials_and_missing_identity(self):
        for params in (
            {"header_host": "other.example"},
            {"host": "private.example", "ip": "10.0.0.9"},
            {"host": "public.example", "ip": "10.0.0.9"},
        ):
            before = len(self.gateway.requests)
            result = self.client(**params)
            self.assertNotEqual(result.get("status"), 200, result)
            self.assertEqual(len(self.gateway.requests), before, self.logs[-15:])
        token = self.identity.read_text()
        self.identity.unlink()
        try:
            before = len(self.gateway.requests)
            result = self.client()
            self.assertNotEqual(result.get("status"), 200, result)
            self.assertEqual(len(self.gateway.requests), before)
        finally:
            self.identity.write_text(token)
            self.identity.chmod(0o644)

    def test_03_sse_large_upload_and_redirect_binding(self):
        result = self.client(path="/sse", sse_probe=True)
        self.assertEqual(
            result.get("body"),
            "data: first\n\ndata: second\n\n",
            (result, self.logs[-10:]),
        )
        self.assertLess(result["first_event_at"], self.target.sse_second_sent)
        result = self.client(path="/upload", upload_size=2 * 1024 * 1024)
        self.assertEqual(
            result.get("body"), str(2 * 1024 * 1024), (result, self.logs[-10:])
        )
        result = self.client(path="/redirect")
        self.assertEqual(result.get("status"), 302, result)
        self.assertEqual(result["location"], "https://private.example/")
        before = len(self.gateway.requests)
        result = self.client(host="private.example", ip="10.0.0.9")
        self.assertNotEqual(result.get("status"), 200, result)
        self.assertEqual(len(self.gateway.requests), before)

    def test_04_h2_multiplex_and_websocket(self):
        result = self.client(h2=True)
        self.assertEqual(result.get("alpn"), "h2", (result, self.logs[-15:]))
        self.assertEqual(
            result["bodies"],
            {"1": "strict-h2-ok", "3": "strict-h2-ok"},
            self.logs[-15:],
        )
        result = self.client(path="/ws", websocket=True)
        self.assertEqual(result.get("status"), 101, (result, self.logs[-15:]))
        self.assertEqual(result["body"], "strict-wss-echo")

    def test_05_explicit_internal_routes_without_identity(self):
        token = self.identity.read_text()
        self.identity.unlink()
        before = len(self.gateway.requests)
        try:
            for scheme, port in (("http", 8080), ("https", 8444)):
                target = self.internal_targets[port]
                before_target = len(target.seen)
                result = self.client(
                    host="internal.example", ip="10.0.0.9", scheme=scheme, port=port
                )
                self.assertEqual(result.get("status"), 200, (result, self.logs[-15:]))
                self.assertEqual(len(target.seen), before_target + 1)
                self.assertNotIn(
                    "proxy-authorization",
                    {name.lower() for name in target.seen[-1][1]},
                )
            result = self.client(
                host="private.example", ip="10.0.0.9", scheme="http", port=8080
            )
            self.assertNotEqual(result.get("status"), 200, result)
            self.assertEqual(len(self.gateway.requests), before)
        finally:
            self.identity.write_text(token)
            self.identity.chmod(0o644)

    def test_06_keepalive_and_dns_rebinding(self):
        result = self.client(repeat=2, delay=6)
        self.assertEqual(result.get("statuses"), [200, 200], (result, self.logs[-20:]))
        try:
            result = self.client(path="/rebind", repeat=2)
            self.assertEqual(
                result.get("statuses"), [200, 403], (result, self.logs[-15:])
            )
        finally:
            self.dns.records["public.example"] = "93.184.216.34"

    def test_07_vault_rotation_unbind_and_failure(self):
        def payload(revision, value=None, *, paths=None, methods=None):
            bindings = (
                []
                if value is None
                else [
                    {
                        "name": "strict-fixture",
                        "match": {
                            "schemes": ["https"],
                            "hosts": ["public.example"],
                            "methods": methods or ["GET"],
                            "paths": paths or ["/v1/*"],
                        },
                        "headers": [{"name": "Authorization", "value": value}],
                    }
                ]
            )
            return json.dumps(
                {
                    "revision": revision,
                    "bindings": bindings,
                    "redactions": [value] if value else [],
                }
            ).encode()

        try:
            for revision, value in (
                (2, "fixture-vault-first"),
                (3, "fixture-vault-second"),
            ):
                self.vault.set_payload(payload(revision, value))
                result = self.client(path="/v1/chat")
                self.assertEqual(result.get("status"), 200, (result, self.logs[-15:]))
                self.assertEqual(result["reflected"], "[REDACTED]")
                self.assertEqual(self.target.seen[-1][1].get("Authorization"), value)
                self.assertNotIn(value, "\n".join(self.logs))
            value = "fixture-vault-protocols"
            self.vault.set_payload(
                payload(4, value, paths=["/*"], methods=["GET", "POST"])
            )
            for params in (
                {"h2": True},
                {"websocket": True},
                {"path": "/sse", "sse_probe": True},
                {"path": "/upload", "upload_size": 2 * 1024 * 1024},
            ):
                with self.subTest(vault_protocol=params):
                    before_target = len(self.target.seen)
                    before_gateway = len(self.gateway.requests)
                    result = self.client(**params)
                    self.assertNotIn("error", result, (result, self.logs[-15:]))
                    self.assertTrue(
                        result.get("status") in (200, 101)
                        or result.get("alpn") == "h2",
                        result,
                    )
                    seen = self.target.seen[before_target:]
                    self.assertTrue(seen)
                    for _, headers in seen:
                        normalized = {key.lower(): val for key, val in headers.items()}
                        self.assertEqual(normalized.get("authorization"), value)
                        self.assertNotIn("proxy-authorization", normalized)
                    self.assertNotIn(
                        value, json.dumps(self.gateway.requests[before_gateway:])
                    )
                    self.assertNotIn(value, "\n".join(self.logs))
            self.vault.set_payload(payload(5))
            result = self.client(path="/v1/chat")
            self.assertEqual(result.get("reflected"), "caller-placeholder", result)
            before = len(self.gateway.requests)
            self.vault.set_mode("server-error")
            result = self.client(path="/v1/chat")
            self.assertEqual(result.get("status"), 503, result)
            self.assertEqual(len(self.gateway.requests), before)
        finally:
            self.vault.set_mode("normal")
            self.vault.set_payload(payload(6))

    def test_08_gateway_refusal_and_tls_failures(self):
        try:
            self.gateway.reflect_identity_in_rejection = True
            for status, event in (
                (403, "gateway_grant_denied"),
                (429, "gateway_rate_limited"),
                (503, "gateway_connect_denied"),
            ):
                with self.subTest(gateway_status=status):
                    self.gateway.reject_status = status
                    before_target = len(self.target.seen)
                    before_logs = len(self.logs)
                    result = self.client()
                    self.assertNotEqual(result.get("status"), 200, result)
                    reflected_identity = self.gateway.requests[-1]["proxy-authorization"]
                    self.assertTrue(reflected_identity.startswith("Bearer "))
                    self.assertNotIn(reflected_identity, json.dumps(result))
                    self.assertNotIn("Fixture Rejection", json.dumps(result))
                    self.assertEqual(len(self.target.seen), before_target)
                    self.assertTrue(
                        any(
                            "upstream proxy: " + event in line
                            for line in self.logs[before_logs:]
                        ),
                        (result, self.logs[before_logs:]),
                    )
        finally:
            self.gateway.reject_status = None
            self.gateway.reflect_identity_in_rejection = False
        good_context = self.gateway.ssl_context
        bad_cert_dir = self.root / "wrong-gateway"
        bad_cert_dir.mkdir()
        self.gateway.ssl_context, _ = _certificate(bad_cert_dir, "wrong.example")
        try:
            before_gateway = len(self.gateway.requests)
            before_logs = len(self.logs)
            result = self.client()
            self.assertNotEqual(result.get("status"), 200, result)
            self.assertEqual(len(self.gateway.requests), before_gateway)
            self.assertTrue(
                any(
                    "upstream proxy: gateway_tls_failed" in line
                    for line in self.logs[before_logs:]
                ),
                (result, self.logs[before_logs:]),
            )
        finally:
            self.gateway.ssl_context = good_context


def _client_main():
    params = json.load(sys.stdin)
    cgroup = Path(params["cgroup"])
    if not str(cgroup).startswith("/sys/fs/cgroup/osb-runtime-"):
        raise ValueError("not a fixture cgroup")
    (cgroup / "cgroup.procs").write_text(str(os.getpid()))
    context = ssl.create_default_context(cafile=params["ca"])
    if params.get("h2"):
        context.set_alpn_protocols(["h2"])
    port = params.get("port", 443)
    raw = socket.create_connection(
        (params["ip"], port), timeout=8, source_address=("10.0.0.9", 0)
    )
    conn = (
        context.wrap_socket(raw, server_hostname=params["host"])
        if params.get("scheme", "https") == "https"
        else raw
    )
    try:
        if params.get("h2"):
            import h2.config
            import h2.connection
            import h2.events

            state = h2.connection.H2Connection(
                config=h2.config.H2Configuration(
                    client_side=True, header_encoding="utf-8"
                )
            )
            state.initiate_connection()
            for stream in (1, 3):
                state.send_headers(
                    stream,
                    [
                        (":method", "GET"),
                        (":scheme", "https"),
                        (":authority", params["host"]),
                        (":path", "/h2"),
                    ],
                    end_stream=True,
                )
            conn.sendall(state.data_to_send())
            bodies, ended = {1: b"", 3: b""}, set()
            while len(ended) < 2:
                packet = conn.recv(65536)
                if not packet:
                    raise EOFError("H2 closed before stream completion")
                for event in state.receive_data(packet):
                    if isinstance(event, h2.events.DataReceived):
                        bodies[event.stream_id] += event.data
                        state.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, h2.events.StreamEnded):
                        ended.add(event.stream_id)
                    elif isinstance(event, h2.events.StreamReset):
                        raise RuntimeError("H2 stream reset")
                conn.sendall(state.data_to_send())
            print(
                json.dumps(
                    {
                        "alpn": conn.selected_alpn_protocol(),
                        "bodies": {
                            key: value.decode() for key, value in bodies.items()
                        },
                    }
                )
            )
            return
        host = params.get("header_host", params["host"])
        if port not in (80, 443):
            host += f":{port}"
        if params.get("websocket"):
            conn.sendall(
                f"GET /ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: c3RyaWN0LWZpeHR1cmVrZXk=\r\n\r\n".encode()
            )
            response = http.client.HTTPResponse(conn)
            response.begin()
            if response.status != 101:
                print(
                    json.dumps(
                        {"status": response.status, "body": response.read().decode()}
                    )
                )
                return
            payload, mask = b"strict-wss-echo", b"\x01\x02\x03\x04"
            conn.sendall(
                bytes([0x81, 0x80 | len(payload)])
                + mask
                + bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            )
            head = _recv_exact(conn, 2)
            body = _recv_exact(conn, head[1] & 0x7F)
            print(json.dumps({"status": response.status, "body": body.decode()}))
            return
        upload = b"x" * params.get("upload_size", 0)
        method = "POST" if upload else "GET"
        statuses = []
        repeat = params.get("repeat", 1)
        for index in range(repeat):
            connection_header = "keep-alive" if index + 1 < repeat else "close"
            conn.sendall(
                f"{method} {params['path']} HTTP/1.1\r\nHost: {host}\r\nAuthorization: caller-placeholder\r\nProxy-Authorization: caller-proxy-value\r\nContent-Length: {len(upload)}\r\nConnection: {connection_header}\r\n\r\n".encode()
                + upload
            )
            response = http.client.HTTPResponse(conn)
            response.begin()
            first = b""
            first_event_at = None
            if params.get("sse_probe") and response.status == 200:
                first = response.read(len(b"data: first\n\n"))
                first_event_at = time.monotonic()
            result = {
                "status": response.status,
                "body": (first + response.read()).decode("utf-8", "replace"),
                "first_event_at": first_event_at,
                "location": response.getheader("Location"),
                "reflected": response.getheader("X-Reflected-Authorization"),
            }
            statuses.append(response.status)
            response.close()
            if index + 1 < repeat:
                time.sleep(params.get("delay", 0))
        result["statuses"] = statuses
        print(json.dumps(result))
    finally:
        conn.close()


if __name__ == "__main__":
    if "--client" in sys.argv:
        _client_main()
    else:
        unittest.main()
