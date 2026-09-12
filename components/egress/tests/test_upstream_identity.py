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
import json
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_upstream_proxy import _load_addon, _Flow, _Server


def _token(payload=None, header=None):
    parts = [
        header or {"alg": "EdDSA"},
        payload if payload is not None else {"exp": time.time() + 120},
    ]
    return (
        ".".join(
            base64.urlsafe_b64encode(json.dumps(p).encode()).decode().rstrip("=")
            for p in parts
        )
        + ".c2lnbmF0dXJl"
    )


class IdentityTest(unittest.TestCase):
    def setUp(self):
        self.addon = _load_addon()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "identity.jwt"

    def test_reopens_rotated_file_and_never_uses_last_good_after_deletion(self):
        first = _token()
        self.path.write_text(first)
        self.assertEqual(self.addon._read_identity(str(self.path)), first)
        replacement = self.path.with_suffix(".next")
        second = _token({"exp": time.time() + 120, "generation": 2})
        replacement.write_text(second)
        replacement.replace(self.path)
        self.assertEqual(self.addon._read_identity(str(self.path)), second)
        self.path.unlink()
        with self.assertRaisesRegex(self.addon.IdentityError, "UNAVAILABLE"):
            self.addon._read_identity(str(self.path))

    def test_malformed_expired_and_not_yet_valid_are_redacted(self):
        cases = [
            "",
            "very-secret-value",
            "a.b.c",
            "a.b.c\r\nInjected: value",
            "a" * 16385,
            _token({"exp": 0}),
            _token({"exp": True}),
            _token({"exp": "tomorrow"}),
            _token({"exp": float("nan")}),
            _token({}),
            _token({"exp": time.time() + 120, "nbf": time.time() + 60}),
            _token(header={"alg": "none"}),
            _token(header=["not", "object"]),
        ]
        for value in cases:
            with self.subTest(value=value[:20]):
                self.path.write_text(value)
                with self.assertRaises(self.addon.IdentityError) as error:
                    self.addon._read_identity(str(self.path))
                self.assertRegex(str(error.exception), r"^EGRESS_IDENTITY_[A-Z_]+$")
                self.assertNotIn("very-secret", str(error.exception))

    def test_identity_bound_to_connection_and_only_connect_gets_header(self):
        addon = self.addon
        addon._via = ("https", ("gateway.example", 443))
        addon._proxy_address = ("gateway.example", 443)
        addon._identity_file = str(self.path)
        value = _token()
        self.path.write_text(value)
        server = _Server(("gateway.example", 443))
        server.id = "one-connection"
        addon.server_connect(types.SimpleNamespace(server=server))
        self.assertIsNone(server.error)
        connect = _Flow(server)
        addon.http_connect_upstream(connect)
        self.assertEqual(
            connect.request.headers["Proxy-Authorization"], "Bearer " + value
        )
        self.assertEqual(addon._connection_identities, {})
        business = _Flow()
        business.request.headers = {
            "Proxy-Authorization": "caller-value",
            "Authorization": "vault-secret",
        }
        addon.requestheaders(business)
        self.assertEqual(business.request.headers, {"Authorization": "vault-secret"})
        self.path.unlink()
        server.id = "new-connection"
        addon.server_connect(types.SimpleNamespace(server=server))
        self.assertEqual(server.error, "EGRESS_IDENTITY_UNAVAILABLE")
        self.assertNotIn(server.id, addon._connection_identities)

    def test_internal_request_strips_proxy_auth_without_reading_identity(self):
        addon = self.addon
        addon._strict_mode = True
        addon._via = ("https", ("gateway.example", 443))
        addon._identity_file = str(self.path)
        flow = _Flow()
        flow.server_conn._opensandbox_public_policy_direct_permit = object()
        flow.request.headers = {"Proxy-Authorization": "caller-value", "Authorization": "business"}
        addon.requestheaders(flow)
        self.assertEqual(flow.request.headers, {"Authorization": "business"})
        self.assertIsNone(getattr(flow, "response", None))
        self.assertIsNone(flow.server_conn.via)

    def test_missing_identity_refuses_request_before_dial(self):
        addon = self.addon
        addon._via = ("https", ("gateway.example", 443))
        addon._identity_file = str(self.path)
        addon.http.Response = types.SimpleNamespace(make=lambda *args: args)
        flow = _Flow()
        addon.requestheaders(flow)
        self.assertEqual(flow.response[0], 403)
        self.assertIsNone(flow.server_conn.via)

    def test_inline_and_file_identity_cannot_be_combined(self):
        with patch.dict(
            "os.environ",
            {
                "OPENSANDBOX_EGRESS_UPSTREAM_PROXY": "https://gateway.example",
                "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_AUTH": "secret-inline",
                "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_IDENTITY_FILE": str(self.path),
                "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_CA_FILE": "irrelevant",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "no inline"):
                self.addon.load(None)

    def test_identity_check_preserves_existing_vault_rejection(self):
        self.addon._via = ("https", ("gateway.example", 443))
        self.addon._identity_file = str(self.path)
        flow = _Flow()
        response = object()
        flow.response = response
        self.addon.requestheaders(flow)
        self.assertIs(flow.response, response)
        self.assertIsNone(flow.server_conn.via)

    def _strict_gateway(self, server_id="gateway-connection", client_id="client-1"):
        addon = self.addon
        addon._strict_mode = True
        addon._via = ("https", ("gateway.example", 8443))
        addon._proxy_address = ("gateway.example", 8443)
        server = _Server(("192.0.2.10", 8443))
        server.id = server_id
        server._opensandbox_public_policy_proxy_permit = object()
        server._opensandbox_public_policy_proxy_host = "gateway.example"
        client = types.SimpleNamespace(id=client_id)
        data = types.SimpleNamespace(server=server, client=client)
        addon.server_connect(data)
        return addon, server, client, data

    def test_strict_gateway_tls_failure_emits_one_bounded_event(self):
        addon, server, client, _ = self._strict_gateway()
        tls_data = types.SimpleNamespace(
            conn=server, context=types.SimpleNamespace(client=client)
        )
        addon.tls_failed_server(tls_data)
        addon.tls_failed_server(tls_data)
        self.assertEqual(
            addon.ctx.log.messages,
            ["upstream proxy: gateway_tls_failed"],
        )

    def test_gateway_connect_failures_and_policy_denials_are_distinct(self):
        addon, server, client, data = self._strict_gateway("failed", "client-failed")
        server.error = "Connection refused"
        # public_policy.py removes the marker before this later hook.
        del server._opensandbox_public_policy_proxy_permit
        del server._opensandbox_public_policy_proxy_host
        addon.server_connect_error(data)
        self.assertEqual(
            addon.ctx.log.messages,
            ["upstream proxy: gateway_connect_failed"],
        )

        addon.ctx.log.messages.clear()
        addon, server, client, data = self._strict_gateway("denied", "client-denied")
        server.error = "EGRESS_PUBLIC_POLICY_GATEWAY_DNS_BINDING_FAILED"
        del server._opensandbox_public_policy_proxy_permit
        del server._opensandbox_public_policy_proxy_host
        addon.server_connect_error(data)
        self.assertEqual(
            addon.ctx.log.messages,
            ["upstream proxy: gateway_connect_denied"],
        )

    def test_identity_denial_is_not_a_gateway_connect_failure(self):
        addon, server, client, data = self._strict_gateway(
            "identity-denied", "client-identity"
        )
        addon._identity_file = str(self.path)
        addon.server_connect(data)
        self.assertEqual(
            addon.ctx.log.messages,
            ["upstream proxy: identity denied EGRESS_IDENTITY_UNAVAILABLE"],
        )
        server.error = "EGRESS_IDENTITY_UNAVAILABLE"
        del server._opensandbox_public_policy_proxy_permit
        del server._opensandbox_public_policy_proxy_host
        addon.server_connect_error(data)
        self.assertEqual(
            addon.ctx.log.messages,
            ["upstream proxy: identity denied EGRESS_IDENTITY_UNAVAILABLE"],
        )

    def test_upstream_connect_status_events_never_use_business_403(self):
        addon, server, client, _ = self._strict_gateway(
            "connect-status", "client-status"
        )
        for status, expected in (
            (403, "upstream proxy: gateway_grant_denied"),
            (429, "upstream proxy: gateway_rate_limited"),
            (502, "upstream proxy: gateway_connect_denied"),
        ):
            flow = types.SimpleNamespace(
                server_conn=server,
                client_conn=client,
                request=types.SimpleNamespace(method=b"CONNECT"),
                response=types.SimpleNamespace(status_code=status),
            )
            addon.http_connect_error(flow)
            self.assertIn(expected, addon.ctx.log.messages)

        before = list(addon.ctx.log.messages)
        business = types.SimpleNamespace(
            server_conn=server,
            client_conn=client,
            request=types.SimpleNamespace(method=b"GET"),
            response=types.SimpleNamespace(status_code=403),
        )
        addon.http_connect_error(business)
        self.assertEqual(before, addon.ctx.log.messages)

    def test_error_hook_kills_public_failure_and_classifies_only_pinned_refusal(self):
        addon, server, client, _ = self._strict_gateway(
            "error-refusal", "client-error"
        )
        addon._gateway_connections.clear()
        # A generated upstream CONNECT refusal may arrive at the original
        # request's error hook after the gateway Server has disconnected.
        gateway = _Server(("192.0.2.10", 8443))
        gateway.id = "gateway-error"
        gateway._opensandbox_public_policy_proxy_permit = object()
        gateway._opensandbox_public_policy_proxy_host = "gateway.example"
        addon.server_connect(types.SimpleNamespace(server=gateway, client=client))
        del gateway._opensandbox_public_policy_proxy_permit
        del gateway._opensandbox_public_policy_proxy_host
        destination = _Server(("93.184.216.34", 443))
        destination.via = addon._via
        destination._opensandbox_public_policy_proxy_permit = object()
        error = types.SimpleNamespace(
            msg="Upstream proxy 192.0.2.10:8443 refused HTTP CONNECT request: 403 Forbidden; identity=secret"
        )
        flow = types.SimpleNamespace(
            server_conn=destination, client_conn=client, error=error,
            killable=True, kill=Mock(),
        )
        addon.error(flow)
        self.assertEqual(
            addon.ctx.log.messages,
            ["upstream proxy: gateway_grant_denied"],
        )
        flow.kill.assert_called_once_with()

        error.msg = "business response 403 Forbidden"
        addon.error(flow)
        self.assertEqual(
            addon.ctx.log.messages,
            ["upstream proxy: gateway_grant_denied"],
        )

    def test_error_suppression_does_not_depend_on_event_state_or_reason_size(self):
        addon, server, client, _ = self._strict_gateway("uncounted", "client")
        server.via = addon._via
        addon._gateway_connections.clear()
        for message in (
            "Upstream proxy 192.0.2.10:8443 refused HTTP CONNECT request: 403 Denied",
            "Unrecognized private gateway error " + "s" * 32768,
        ):
            flow = types.SimpleNamespace(
                server_conn=server, client_conn=client,
                error=types.SimpleNamespace(msg=message), killable=True, kill=Mock(),
            )
            addon.error(flow)
            flow.kill.assert_called_once_with()
        self.assertEqual(addon.ctx.log.messages, [])
        flow.killable = False
        flow.kill.reset_mock()
        addon.error(flow)
        flow.kill.assert_not_called()

    def test_error_suppression_leaves_legacy_and_internal_flows_unchanged(self):
        addon, server, client, _ = self._strict_gateway("not-public", "client")
        server.via = addon._via
        flow = types.SimpleNamespace(
            server_conn=server, client_conn=client,
            error=types.SimpleNamespace(msg="private error"), killable=True, kill=Mock(),
        )
        server._opensandbox_public_policy_direct_permit = object()
        addon.error(flow)
        del server._opensandbox_public_policy_direct_permit
        addon._strict_mode = False
        addon.error(flow)
        flow.kill.assert_not_called()

    def test_gateway_events_require_strict_gateway_marker(self):
        addon = self.addon
        addon._strict_mode = True
        addon._via = ("https", ("gateway.example", 8443))
        addon._proxy_address = ("gateway.example", 8443)
        server = _Server(("192.0.2.10", 8443))
        server.id = "unmarked"
        addon.tls_failed_server(
            types.SimpleNamespace(
                conn=server, context=types.SimpleNamespace(client=None)
            )
        )
        addon._strict_mode = False
        server._opensandbox_public_policy_proxy_permit = object()
        server._opensandbox_public_policy_proxy_host = "gateway.example"
        addon.tls_failed_server(
            types.SimpleNamespace(
                conn=server, context=types.SimpleNamespace(client=None)
            )
        )
        self.assertEqual(addon.ctx.log.messages, [])


if __name__ == "__main__":
    unittest.main()
