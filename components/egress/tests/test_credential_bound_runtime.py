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

"""Real-mitmproxy coverage of the live credential-bound admission loop.

Runs a real mitmdump with the system addon under the experimental live
admission bundle and drives the revision IPC exactly like the Go launcher
does (prepare + commit over the authenticated Unix socket). A local HTTPS
origin with its own CA proves both directions:

- bound SNI is decrypted, the origin receives the vault credential, and a
  keepalive connection picks up a rotated revision per request;
- unbound and no-SNI traffic stays end-to-end (the client, trusting only the
  origin CA, verifies the origin's own certificate), while a denied
  ClientHello is terminated instead of decrypted;
- removing the vault fences the tracked connection and returns new
  connections to opaque pass-through.

Requires ``mitmdump`` on PATH, Unix-socket permission and the cryptography
package (both supplied with mitmproxy); setup failures are test failures.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

MITMDUMP = shutil.which("mitmdump")
MITMSCRIPTS = Path(__file__).resolve().parents[1] / "mitmscripts"
CONTROL = "runtime-control"
SUBJECT = "runtime-subject"
TOKEN = "b" * 43
BOUND = "bound.example.com"
UNBOUND = "unbound.example.com"
SECRET_ONE = "runtime-live-secret-one"
SECRET_TWO = "runtime-rotated-secret-two"


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def decision_payload(bindings: list[dict], redactions: list[str], vault_revision: int) -> bytes:
    selectors = sorted(
        host
        for item in bindings
        if "https" in item["match"]["schemes"]
        for host in item["match"]["hosts"]
    )
    return json.dumps(
        {
            "version": 1,
            "vaultRevision": vault_revision,
            "effectivePolicyEpoch": 0,
            "interceptionMode": "credential-bound",
            "state": "active" if bindings else "active-empty",
            "tlsBindingHostSelectors": selectors,
            "fullRenderedBindings": sorted(bindings, key=lambda item: item["name"]),
            "redactions": sorted(redactions, key=lambda item: (-len(item.encode()), item)),
        },
        separators=(",", ":"),
    ).encode()


def binding(secret: str, host: str = BOUND) -> dict:
    return {
        "name": "api",
        "match": {
            "schemes": ["https"],
            "hosts": [host],
            "methods": ["GET", "POST"],
            "paths": ["/v1/*"],
        },
        "headers": [{"name": "Private-Token", "value": secret}],
    }


def generate_origin_certificate(directory: Path) -> None:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, BOUND)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2050, 1, 1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(BOUND),
                    x509.DNSName(UNBOUND),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    (directory / "origin.pem").write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    (directory / "origin-ca.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


class EchoHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args) -> None:
        pass

    def _serve(self) -> None:
        body = json.dumps(
            {
                "host": self.headers.get("Host", ""),
                "path": self.path,
                "private_token": self.headers.get("Private-Token", ""),
            }
        ).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _serve
    do_POST = _serve
    do_DELETE = _serve
    do_PUT = _serve
    do_PATCH = _serve


class ClientError(Exception):
    """A client-side failure with a fixed, secret-free message."""


class TunneledConnection:
    """One proxy CONNECT tunnel with an explicit SNI and keepalive reuse."""

    def __init__(self, proxy_port: int, target_port: int, *, sni: str | None, ca_file: str | None) -> None:
        self.buffer = b""
        self.sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
        self.sock.sendall(
            f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{target_port}\r\n\r\n".encode()
        )
        head, surplus = self._read_head(self.sock)
        if not head.startswith(b"HTTP/1.1 200"):
            raise ClientError("proxy refused the tunnel: " + head[:80].decode("latin1"))
        if surplus:
            raise ClientError("proxy sent unexpected bytes after the tunnel response")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if ca_file:
            context.load_verify_locations(ca_file)
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        context.check_hostname = bool(sni) and bool(ca_file)
        self.tls = context.wrap_socket(self.sock, server_hostname=sni)

    @staticmethod
    def _read_head(stream, buffer: bytes = b"") -> tuple[bytes, bytes]:
        """Return (head, surplus) without discarding bytes after the blank line."""
        data = buffer
        while b"\r\n\r\n" not in data:
            chunk = stream.recv(4096)
            if not chunk:
                raise ClientError("connection closed while reading the proxy response")
            data += chunk
        head, _, surplus = data.partition(b"\r\n\r\n")
        return head, surplus

    def peer_certificate(self) -> bytes:
        return self.tls.getpeercert(binary_form=True)

    def request(self, method: str, path: str, host: str) -> tuple[int, dict]:
        self.tls.sendall(
            f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n".encode()
        )
        head, body = self._read_head(self.tls, self.buffer)
        self.buffer = b""
        status = int(head.split(b" ", 2)[1])
        length = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1].strip())
        while len(body) < length:
            chunk = self.tls.recv(length - len(body))
            if not chunk:
                break
            body += chunk
        self.buffer = body[length:]
        body = body[:length]
        try:
            payload = json.loads(body.decode("utf-8"))
        except ValueError:
            payload = {"raw": body.decode("utf-8", "replace")[:200]}
        return status, payload

    def close(self) -> None:
        for stream in (getattr(self, "tls", None), self.sock):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass


class LiveRuntimeHarness:
    """A real mitmdump addon process, its revision IPC, and a local origin."""

    def __init__(self, root: Path) -> None:
        self.root = root
        # The origin binds canonical 443 inside the test container so the
        # intercepted request port stays 443, as real HTTPS interception has.
        self.origin_port = 443
        self.proxy_port = free_port()
        self.directory = root / "receiver"
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.socket_path = str(self.directory / "receiver.sock")
        generate_origin_certificate(root)
        self.origin = self._start_origin()
        self.process: subprocess.Popen | None = None
        self.log_path = root / "proxy.log"
        self.log = self.log_path.open("w+")

    def _start_origin(self) -> socketserver.ThreadingTCPServer:
        server = socketserver.ThreadingTCPServer(("127.0.0.1", self.origin_port), EchoHandler)
        server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.root / "origin.pem"))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def env(self, drain_seconds: int = 1) -> dict:
        return {
            **os.environ,
            "OPENSANDBOX_EGRESS_REVISION_IPC_SOCKET": self.socket_path,
            "OPENSANDBOX_EGRESS_REVISION_IPC_TOKEN": TOKEN,
            "OPENSANDBOX_EGRESS_REVISION_CONTROL_GENERATION": CONTROL,
            "OPENSANDBOX_EGRESS_REVISION_SUBJECT_GENERATION": SUBJECT,
            "OPENSANDBOX_EGRESS_REVISION_MAX_SNAPSHOT_BYTES": "1048576",
            "OPENSANDBOX_EGRESS_REVISION_TLS_CAPACITY": "64",
            "OPENSANDBOX_EGRESS_REVISION_REQUEST_CAPACITY": "256",
            "OPENSANDBOX_EGRESS_REVISION_DRAIN_TIMEOUT_SECONDS": str(drain_seconds),
        }

    def start(self, drain_seconds: int = 1) -> None:
        self.process = subprocess.Popen(
            [
                MITMDUMP,
                "--listen-host", "127.0.0.1",
                "--listen-port", str(self.proxy_port),
                "--set", "confdir=" + str(self.root / "ca"),
                "--set", "connection_strategy=lazy",
                "--set", "flow_detail=0",
                "--set", "ssl_verify_upstream_trusted_ca=" + str(self.root / "origin.pem"),
                "-s", str(MITMSCRIPTS / "system.py"),
            ],
            env=self.env(drain_seconds),
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError("mitmdump exited before readiness: " + self.read_log()[-2000:])
            if os.path.exists(self.socket_path) and (self.root / "ca" / "mitmproxy-ca-cert.pem").exists():
                if self._ipc_ready():
                    return
            time.sleep(0.05)
        raise AssertionError("mitmdump did not become ready: " + self.read_log()[-2000:])

    def _ipc_ready(self) -> bool:
        try:
            self.active()
            return True
        except Exception:  # noqa: BLE001 - readiness probe only
            return False

    def stop(self) -> None:
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.origin.shutdown()
        self.origin.server_close()
        self.log.close()

    def read_log(self) -> str:
        self.log.flush()
        return self.log_path.read_text(errors="replace")

    # -- revision IPC, the same wire protocol the Go transport speaks -------

    def command(self, path: str, value: dict | None = None) -> tuple[int, dict]:
        body = None if value is None else json.dumps(value).encode()
        headers = {"Authorization": "Bearer " + TOKEN}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("localhost", timeout=5)
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(5)
        connection.sock.connect(self.socket_path)
        try:
            connection.request("POST" if body is not None else "GET", path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def active(self) -> dict | None:
        status, value = self.command("/v1/revisions/active")
        if status != 200:
            raise AssertionError(f"active readback failed: {status} {value}")
        return value["revision"]

    def install(self, epoch: int, bindings: list[dict], redactions: list[str], revision: int) -> dict:
        payload = decision_payload(bindings, redactions, revision)
        envelope = {
            "controlGeneration": CONTROL,
            "subjectGeneration": SUBJECT,
            "decisionEpoch": epoch,
            "vaultRevision": revision,
            "policyEpoch": 0,
            "digest": hashlib.sha256(payload).hexdigest(),
        }
        status, value = self.command(
            "/v1/revisions/prepare",
            {"revision": envelope, "payload": base64.b64encode(payload).decode()},
        )
        if status != 200:
            raise AssertionError(f"prepare failed: {status} {value}")
        status, value = self.command("/v1/revisions/commit", {"revision": envelope})
        if status != 200:
            raise AssertionError(f"commit failed: {status} {value}")
        return envelope

    # -- TLS clients --------------------------------------------------------

    def mitm_ca(self) -> str:
        return str(self.root / "ca" / "mitmproxy-ca-cert.pem")

    def origin_ca(self) -> str:
        return str(self.root / "origin-ca.pem")

    def connect(self, *, sni: str | None, trust: str) -> TunneledConnection:
        ca_file = self.mitm_ca() if trust == "mitm" else self.origin_ca() if trust == "origin" else None
        return TunneledConnection(self.proxy_port, self.origin_port, sni=sni, ca_file=ca_file)


@unittest.skipUnless(MITMDUMP, "mitmdump is not installed")
class CredentialBoundRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="oscbr-", dir="/tmp")
        self.root = Path(self.temporary.name)
        self.harness = LiveRuntimeHarness(self.root)
        self.harness.start()
        self.connections: list[TunneledConnection] = []

    def tearDown(self) -> None:
        for connection in self.connections:
            connection.close()
        self.harness.stop()
        self.temporary.cleanup()

    def connect(self, *, sni: str | None, trust: str) -> TunneledConnection:
        connection = self.harness.connect(sni=sni, trust=trust)
        self.connections.append(connection)
        return connection

    def test_bootstrapping_denies_sni_bearing_tls(self) -> None:
        # No snapshot is installed yet: a bound-looking SNI must be terminated.
        with self.assertRaises((ssl.SSLError, ClientError, OSError, ConnectionError)):
            self.connect(sni=BOUND, trust="mitm")

    def test_bound_sni_is_decrypted_and_receives_credential(self) -> None:
        self.harness.install(1, [binding(SECRET_ONE)], [SECRET_ONE], 1)
        connection = self.connect(sni=BOUND, trust="mitm")
        status, payload = connection.request("GET", "/v1/data", BOUND)
        self.assertEqual(200, status)
        self.assertEqual(SECRET_ONE, payload["private_token"])

    def test_unbound_and_no_sni_pass_through_end_to_end(self) -> None:
        self.harness.install(1, [binding(SECRET_ONE)], [SECRET_ONE], 1)
        origin_peer = None
        unbound = self.connect(sni=UNBOUND, trust="origin")
        status, payload = unbound.request("GET", "/v1/data", UNBOUND)
        self.assertEqual(200, status)
        self.assertEqual("", payload["private_token"])
        origin_peer = unbound.peer_certificate()

        # Bound SNI on the same revision is decrypted, so its peer certificate
        # differs from the origin's own; an untrusted client must fail.
        bound = self.connect(sni=BOUND, trust="mitm")
        self.assertNotEqual(origin_peer, bound.peer_certificate())

        with self.assertRaises((ssl.SSLError, ClientError, OSError, ConnectionError)):
            self.connect(sni=BOUND, trust="origin")

        no_sni = self.connect(sni=None, trust="origin")
        status, payload = no_sni.request("GET", "/v1/data", BOUND)
        self.assertEqual(200, status)
        self.assertEqual("", payload["private_token"])
        self.assertEqual(origin_peer, no_sni.peer_certificate())

    def test_wrong_path_and_method_receive_no_credential(self) -> None:
        self.harness.install(1, [binding(SECRET_ONE)], [SECRET_ONE], 1)
        connection = self.connect(sni=BOUND, trust="mitm")
        status, payload = connection.request("GET", "/health", BOUND)
        self.assertEqual(200, status)
        self.assertEqual("", payload["private_token"])
        status, payload = connection.request("DELETE", "/v1/data", BOUND)
        self.assertEqual(200, status)
        self.assertEqual("", payload["private_token"])

    def test_keepalive_rotation_switches_per_request(self) -> None:
        self.harness.install(1, [binding(SECRET_ONE)], [SECRET_ONE], 1)
        connection = self.connect(sni=BOUND, trust="mitm")
        status, payload = connection.request("GET", "/v1/first", BOUND)
        self.assertEqual(200, status)
        self.assertEqual(SECRET_ONE, payload["private_token"])

        self.harness.install(2, [binding(SECRET_TWO)], [SECRET_TWO], 2)
        status, payload = connection.request("GET", "/v1/second", BOUND)
        self.assertEqual(200, status)
        self.assertEqual(SECRET_TWO, payload["private_token"])

    def test_removal_fences_keepalive_and_returns_to_pass_through(self) -> None:
        self.harness.install(1, [binding(SECRET_ONE)], [SECRET_ONE], 1)
        connection = self.connect(sni=BOUND, trust="mitm")
        status, payload = connection.request("GET", "/v1/data", BOUND)
        self.assertEqual(200, status)
        self.assertEqual(SECRET_ONE, payload["private_token"])

        self.harness.install(2, [], [], 0)
        try:
            status, payload = connection.request("GET", "/v1/after", BOUND)
            self.assertEqual(403, status, "fenced keepalive request was not rejected")
            self.assertEqual("", payload.get("private_token", ""))
        except (ClientError, ssl.SSLError, OSError, ConnectionError):
            # A drained transport closing instead of answering is equally fenced.
            pass

        # New connections are opaque again: the client verifies the origin's
        # own certificate and receives no credential.
        fresh = self.connect(sni=BOUND, trust="origin")
        status, payload = fresh.request("GET", "/v1/data", BOUND)
        self.assertEqual(200, status)
        self.assertEqual("", payload["private_token"])

        # Re-adding the host must not revive the revoked connection. The
        # session is still alive (drain timeout is one second and no request
        # touched it in between), so the permanent fence is what must deny.
        self.harness.install(3, [binding(SECRET_ONE)], [SECRET_ONE], 1)
        try:
            status, payload = connection.request("GET", "/v1/readded", BOUND)
            self.assertGreaterEqual(status, 400, "re-added host revived the revoked connection")
            self.assertEqual("", payload.get("private_token", ""))
        except (ClientError, ssl.SSLError, OSError, ConnectionError):
            pass


if __name__ == "__main__":
    unittest.main()