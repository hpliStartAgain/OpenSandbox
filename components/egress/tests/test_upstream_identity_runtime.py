# Copyright 2026 Alibaba Group Holding Ltd.
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

import base64
import http.client
import json
import socket
import ssl
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from test_upstream_proxy_runtime import (
    MITMDUMP,
    _ConnectProxy,
    _TargetServer,
    _free_port,
    _proxy_get,
    _start_mitmdump,
    _stop,
)


def _jwt(generation):
    fields = [{"alg": "EdDSA"}, {"exp": time.time() + 120, "generation": generation}]
    return (
        ".".join(
            base64.urlsafe_b64encode(json.dumps(f).encode()).decode().rstrip("=")
            for f in fields
        )
        + ".c2lnbmF0dXJl"
    )


def _certificate(root, name="localhost", expired=False):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(
            now - timedelta(days=1) if expired else now + timedelta(days=1)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = root / "cert.pem", root / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    return context, cert_path


@unittest.skipUnless(MITMDUMP, "mitmdump is not installed")
class IdentityRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="egress-identity-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.target = _TargetServer()
        self.target.start()
        self.addCleanup(self.target.stop)
        self.identity = self.root / "identity.jwt"

    def _start(
        self,
        name="localhost",
        expired=False,
        wrong_ca=False,
        extra_args=(),
        extra_env=None,
        system_script=False,
        target_addresses=None,
    ):
        tls, ca = _certificate(self.root, name, expired)
        if wrong_ca:
            other = self.root / "other"
            other.mkdir()
            _, ca = _certificate(other)
        proxy = _ConnectProxy(tls, target_addresses=target_addresses)
        proxy.start()
        self.addCleanup(proxy.stop)
        port = _free_port()
        proc, log = _start_mitmdump(
            port,
            {
                "OPENSANDBOX_EGRESS_UPSTREAM_PROXY": f"https://localhost:{proxy.port}",
                "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_IDENTITY_FILE": str(self.identity),
                "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_CA_FILE": str(ca),
                **(extra_env or {}),
            },
            *extra_args,
            system_script=system_script,
        )
        self.addCleanup(_stop, proc)
        return port, proxy, log

    def _url(self):
        return f"http://127.0.0.1:{self.target.port}/"

    def test_valid_proxy_tls_and_atomic_identity_rotation(self):
        first = _jwt(1)
        self.identity.write_text(first)
        port, proxy, log = self._start()
        status, body = _proxy_get(port, self._url())
        self.assertEqual((status, body), (200, b"upstream-proxy-e2e-ok"), log)
        self.assertEqual(proxy.requests[-1]["proxy-authorization"], "Bearer " + first)
        second = _jwt(2)
        replacement = self.identity.with_suffix(".next")
        replacement.write_text(second)
        replacement.replace(self.identity)
        self.assertEqual(_proxy_get(port, self._url())[0], 200, log)
        self.assertEqual(proxy.requests[-1]["proxy-authorization"], "Bearer " + second)
        self.assertNotIn(first, "\n".join(log))
        self.assertNotIn(second, "\n".join(log))

    def test_missing_identity_ready_but_no_connect(self):
        port, proxy, log = self._start()
        status, body = _proxy_get(port, self._url())
        self.assertEqual(status, 403, log)
        self.assertIn(b"EGRESS_IDENTITY_UNAVAILABLE", body)
        self.assertEqual(proxy.requests, [])
        self.assertEqual(self.target.hits, 0)

    def test_missing_identity_rejects_streaming_upload_without_addon_error(self):
        port, proxy, log = self._start(extra_args=("--set", "stream_large_bodies=1m"))
        for chunked in (False, True):
            with self.subTest(chunked=chunked):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                try:
                    body = (
                        [b"x" * (2 * 1024 * 1024)]
                        if chunked
                        else b"x" * (2 * 1024 * 1024)
                    )
                    conn.request("POST", self._url(), body=body, encode_chunked=chunked)
                    response = conn.getresponse()
                    self.assertGreaterEqual(response.status, 400)
                    response.read()
                except (OSError, http.client.HTTPException):
                    pass  # Fail-closed disconnect is expected for streamed requests.
                finally:
                    conn.close()
        self.assertEqual(proxy.requests, [])
        self.assertEqual(self.target.hits, 0)
        # A later ordinary request also verifies that the proxy still serves.
        self.assertEqual(_proxy_get(port, self._url())[0], 403, log)
        errors = [
            line[:200]
            for line in log
            if "NotImplementedError" in line
            or "Addon error" in line
            or "has crashed" in line
        ]
        self.assertEqual(errors, [])

    def test_identity_removed_after_success_never_falls_back(self):
        self.identity.write_text(_jwt(1))
        port, proxy, log = self._start()
        self.assertEqual(_proxy_get(port, self._url())[0], 200, log)
        self.identity.unlink()
        count = len(proxy.requests)
        self.assertEqual(_proxy_get(port, self._url())[0], 403, log)
        self.assertEqual(len(proxy.requests), count)

    def test_bad_ca_san_and_expiry_never_send_identity_or_reach_target(self):
        for params in (
            {"wrong_ca": True},
            {"name": "wrong.example"},
            {"expired": True},
        ):
            with self.subTest(params=params):
                self.identity.write_text(_jwt(1))
                port, proxy, log = self._start(**params)
                self.assertEqual(_proxy_get(port, self._url())[0], 502, log)
                self.assertEqual(proxy.requests, [])
                self.assertEqual(self.target.hits, 0)

    def test_target_never_receives_proxy_authorization(self):
        # A dedicated target reflects only the two authorization headers.
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading

        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(
                    (
                        self.headers.get("Authorization"),
                        self.headers.get("Proxy-Authorization"),
                    )
                )
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()

            def log_message(self, *args):
                pass

        target = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(target.server_close)
        self.addCleanup(target.shutdown)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        self.identity.write_text(_jwt(1))
        port, proxy, log = self._start()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
        self.addCleanup(conn.close)
        conn.request(
            "GET",
            f"http://127.0.0.1:{target.server_port}/",
            headers={
                "Authorization": "business-credential",
                "Proxy-Authorization": "caller-proxy-value",
            },
        )
        self.assertEqual(conn.getresponse().status, 200, log)
        self.assertEqual(seen, [("business-credential", None)])
        self.assertTrue(proxy.requests[0]["proxy-authorization"].startswith("Bearer "))

    def test_gateway_ca_does_not_become_target_trust(self):
        from test_upstream_proxy_runtime import _TlsTargetServer

        self.identity.write_text(_jwt(1))
        port, proxy, log = self._start()
        target = _TlsTargetServer(self.root / "cert.pem", self.root / "key.pem")
        target.start()
        self.addCleanup(target.stop)
        status, _ = _proxy_get(port, f"https://localhost:{target.port}/")
        self.assertEqual(status, 502, log)
        self.assertEqual(len(proxy.requests), 1)

    @unittest.skipUnless(
        hasattr(socket, "AF_UNIX"), "Vault transport requires Unix sockets"
    )
    def test_system_vault_binding_update_unbind_and_failure_through_gateway(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        from test_mitmproxy_runtime import _VaultUnixServer

        def payload(revision, credential=None):
            bindings = (
                []
                if credential is None
                else [
                    {
                        "name": "test-vault-binding",
                        "match": {
                            "schemes": ["https"],
                            "hosts": ["vault.example"],
                            "methods": ["GET"],
                            "paths": ["/v1/*"],
                        },
                        "headers": [{"name": "Authorization", "value": credential}],
                    }
                ]
            )
            return json.dumps(
                {
                    "revision": revision,
                    "bindings": bindings,
                    "redactions": [credential] if credential else [],
                }
            ).encode()

        vault_path = str(self.root / "vault.sock")
        vault = _VaultUnixServer(vault_path, payload(1, "fixture-vault-first"))
        vault.start()
        self.addCleanup(vault.stop)
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(
                    (
                        self.headers.get("Authorization"),
                        self.headers.get("Proxy-Authorization"),
                    )
                )
                self.send_response(200)
                # Check that system.py still redacts response headers after
                # proxy routing; a fixture value must not be reflected to Agent.
                self.send_header(
                    "X-Reflected-Authorization", self.headers.get("Authorization", "")
                )
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()

            def log_message(self, *args):
                pass

        target = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        target_root = self.root / "vault-target"
        target_root.mkdir()
        target_tls, target_ca = _certificate(target_root, "vault.example")
        target.socket = target_tls.wrap_socket(target.socket, server_side=True)
        self.addCleanup(target.server_close)
        self.addCleanup(target.shutdown)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        self.identity.write_text(_jwt(1))
        port, proxy, log = self._start(
            extra_env={"OPENSANDBOX_CREDENTIAL_PROXY_SOCKET": vault_path},
            extra_args=("--set", "ssl_verify_upstream_trusted_ca=" + str(target_ca)),
            system_script=True,
            target_addresses={("vault.example", 443): ("127.0.0.1", target.server_port)},
        )

        def request(path="/v1/chat"):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            try:
                conn.request(
                    "GET",
                    f"https://vault.example{path}",
                    headers={"Authorization": "caller-placeholder"},
                )
                response = conn.getresponse()
                response.read()
                return response.status, response.getheader("X-Reflected-Authorization")
            finally:
                conn.close()

        self.assertEqual(request(), (200, "[REDACTED]"), log)
        self.assertEqual(seen[-1], ("fixture-vault-first", None))
        self.assertEqual(request("/unmatched"), (200, "caller-placeholder"))
        vault.set_payload(payload(2, "fixture-vault-second"))
        self.assertEqual(request(), (200, "[REDACTED]"))
        self.assertEqual(seen[-1], ("fixture-vault-second", None))
        vault.set_payload(payload(3))
        self.assertEqual(request(), (200, "caller-placeholder"))
        self.assertEqual(seen[-1], ("caller-placeholder", None))
        before = len(proxy.requests)
        vault.set_mode("server-error")
        self.assertEqual(request()[0], 503)
        self.assertEqual(len(proxy.requests), before)
        self.assertTrue(
            all(
                item["proxy-authorization"].startswith("Bearer ")
                for item in proxy.requests
            )
        )
        joined = "\n".join(log)
        self.assertNotIn("fixture-vault-first", joined)
        self.assertNotIn("fixture-vault-second", joined)
        self.assertLess(
            joined.index("credential proxy: system addon ready"),
            joined.index("upstream proxy: ready"),
        )

    def test_separate_target_trust_still_works_through_gateway(self):
        from test_upstream_proxy_runtime import _TlsTargetServer

        self.identity.write_text(_jwt(1))
        target_root = self.root / "target"
        target_root.mkdir()
        _, target_cert = _certificate(target_root)
        target = _TlsTargetServer(target_cert, target_root / "key.pem")
        target.start()
        self.addCleanup(target.stop)
        port, _, log = self._start(
            extra_args=("--set", "ssl_verify_upstream_trusted_ca=" + str(target_cert))
        )
        status, body = _proxy_get(port, f"https://localhost:{target.port}/")
        self.assertEqual((status, body), (200, b"upstream-proxy-tls-e2e-ok"), log)


if __name__ == "__main__":
    unittest.main()
