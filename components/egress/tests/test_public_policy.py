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

"""Focused unit tests for the strict public destination policy addon."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


class _Log:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def warn(self, message: str) -> None:
        self.messages.append(message)

    def info(self, message: str) -> None:
        self.messages.append(message)


class _Response:
    def __init__(self, status_code: int, content: bytes, headers: dict[str, str]):
        self.status_code = status_code
        self.content = content
        self.headers = headers


class _Headers:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self._values = dict(values or {})

    def get_all(self, name: str) -> list[str]:
        return [
            value
            for key, value in self._values.items()
            if key.lower() == name.lower()
        ]

    def get(self, name: str, default=None):
        values = self.get_all(name)
        return values[0] if values else default

    def __contains__(self, name: str) -> bool:
        return bool(self.get_all(name))

    def __setitem__(self, name: str, value: str) -> None:
        for key in list(self._values):
            if key.lower() == name.lower():
                del self._values[key]
        self._values[name] = value


class _Request:
    def __init__(
        self,
        host: str,
        port: int,
        scheme: str,
        headers: dict[str, str],
    ) -> None:
        self.host = host
        self.port = port
        self.scheme = scheme
        self.headers = _Headers(headers)
        self.authority = ""
        self.is_http2 = False
        self.is_http3 = False
        self.http_version = "HTTP/1.1"
        self.stream = False

    @property
    def host_header(self) -> str | None:
        return self.headers.get("Host")

    @host_header.setter
    def host_header(self, value: str) -> None:
        self.headers["Host"] = value


class _Connection:
    def __init__(self, ident: str, address: tuple[str, int]):
        self.id = ident
        self.address = address
        self.error = None
        self.transport_protocol = "tcp"
        self.connected = False
        self.via = None


class _Flow:
    def __init__(
        self,
        client: _Connection,
        server: _Connection,
        request: _Request,
    ) -> None:
        self.client_conn = client
        self.server_conn = server
        self.request = request
        self.response = None
        self.error = None
        self.metadata: dict[str, object] = {}
        self.killable = True
        self.killed = False

    def kill(self) -> None:
        self.killed = True


def _load_addon() -> object:
    log = _Log()

    def make_response(status: int, content=b"", headers=None):
        return _Response(status, content, dict(headers or {}))

    mitmproxy = types.ModuleType("mitmproxy")
    mitmproxy.ctx = types.SimpleNamespace(
        log=log,
        options=types.SimpleNamespace(connection_strategy="lazy"),
    )
    mitmproxy.http = types.SimpleNamespace(
        HTTPFlow=object,
        Response=types.SimpleNamespace(make=make_response),
    )
    path = Path(__file__).parents[1] / "mitmscripts" / "public_policy.py"
    spec = importlib.util.spec_from_file_location("opensandbox_public_policy_test", path)
    assert spec is not None and spec.loader is not None
    with mock.patch.dict(sys.modules, {"mitmproxy": mitmproxy}):
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    module._test_log = log
    return module


def _load_upstream_addon() -> object:
    log = _Log()

    def make_response(status: int, content=b"", headers=None):
        return _Response(status, content, dict(headers or {}))

    mitmproxy = types.ModuleType("mitmproxy")
    mitmproxy.ctx = types.SimpleNamespace(
        log=log,
        options=types.SimpleNamespace(
            connection_strategy="lazy",
            ignore_hosts=[],
            tcp_hosts=[],
            udp_hosts=[],
        ),
    )
    mitmproxy.http = types.SimpleNamespace(
        HTTPFlow=object,
        Response=types.SimpleNamespace(make=make_response),
    )
    path = Path(__file__).parents[1] / "mitmscripts" / "upstream_proxy.py"
    spec = importlib.util.spec_from_file_location("opensandbox_upstream_policy_test", path)
    assert spec is not None and spec.loader is not None
    with mock.patch.dict(sys.modules, {"mitmproxy": mitmproxy}):
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    module._test_log = log
    return module


def _policy_json(internal_targets=None) -> str:
    return json.dumps(
        {
            "version": 1,
            "dns_servers": ["10.0.0.53"],
            "internal_targets": internal_targets or [],
        }
    )


class PublicPolicyParsingTest(unittest.TestCase):
    def test_policy_limits_match_supervisor_contract(self) -> None:
        addon = _load_addon()
        self.assertEqual(8, addon.MAX_DNS_SERVERS)
        self.assertEqual(128, addon.MAX_INTERNAL_TARGETS)
        self.assertEqual(32, addon.MAX_TARGET_IPS)
        self.assertEqual(32, addon.MAX_TARGET_PORTS)
        with self.assertRaises(addon.PolicyError):
            addon.parse_policy(" " * (32 * 1024 + 1))

    def test_policy_is_bounded_and_metadata_is_not_an_internal_exception(self) -> None:
        addon = _load_addon()
        for metadata_ip in ("100.100.100.200", "168.63.129.16"):
            with self.subTest(metadata_ip=metadata_ip):
                with self.assertRaises(addon.PolicyError) as error:
                    addon.parse_policy(
                        _policy_json(
                            [
                                {
                                    "host": "admin.example",
                                    "ips": [metadata_ip],
                                    "ports": [443],
                                }
                            ]
                        )
                    )
                self.assertEqual(
                    "EGRESS_PUBLIC_POLICY_INTERNAL_IP_INVALID", str(error.exception)
                )

        with self.assertRaises(addon.PolicyError):
            addon.parse_policy(
                json.dumps(
                    {
                        "version": 1,
                        "dns_servers": ["10.0.0.53"],
                        "internal_targets": [],
                        "unexpected": True,
                    }
                )
            )

        for port in (53, 15353, 18080, 18081):
            with self.subTest(port=port):
                with self.assertRaises(addon.PolicyError):
                    addon.parse_policy(
                        _policy_json(
                            [
                                {
                                    "host": "admin.example",
                                    "ips": ["10.0.0.5"],
                                    "ports": [port],
                                }
                            ]
                        )
                    )

        with mock.patch.dict(
            os.environ,
            {
                "OPENSANDBOX_EGRESS_PUBLIC_POLICY": _policy_json(
                    [
                        {
                            "host": "gateway.example",
                            "ips": ["10.0.0.5"],
                            "ports": [8443],
                        }
                    ]
                ),
                "OPENSANDBOX_EGRESS_UPSTREAM_PROXY": "https://gateway.example:8443",
            },
            clear=True,
        ):
            with self.assertRaises(addon.PolicyError):
                addon.load(types.SimpleNamespace())

    def test_authority_and_hostname_reject_ip_and_ambiguous_forms(self) -> None:
        addon = _load_addon()
        self.assertEqual("example.test", addon.normalize_fqdn("Example.TEST."))
        for value in ("127.0.0.1", "[::1]", "example.test/path", "example..test"):
            with self.subTest(value=value):
                with self.assertRaises(addon.PolicyError):
                    addon._parse_authority(value)
        self.assertEqual(("example.test", 443), addon._parse_authority("example.test:443"))
        with self.assertRaises(addon.PolicyError):
            addon._parse_authority("example.test:0")
        for port in (53, 15353, 18080, 18081):
            with self.subTest(gateway_port=port):
                with self.assertRaises(addon.PolicyError):
                    addon._parse_gateway(f"https://gateway.example:{port}")


class PublicPolicyDnsParserTest(unittest.TestCase):
    @staticmethod
    def _name(value: str) -> bytes:
        return b"".join(
            bytes((len(label),)) + label.encode("ascii")
            for label in value.split(".")
        ) + b"\x00"

    def _response(self, query_id: int, host: str, ip: str) -> bytes:
        question = self._name(host) + b"\x00\x01\x00\x01"
        answer = b"\xc0\x0c" + b"\x00\x01\x00\x01" + b"\x00\x00\x00\x1e" + b"\x00\x04" + bytes(
            int(part) for part in ip.split(".")
        )
        header = query_id.to_bytes(2, "big") + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        return header + question + answer

    def test_matching_id_question_and_a_are_required(self) -> None:
        addon = _load_addon()
        packet = self._response(7, "example.test", "93.184.216.34")
        self.assertEqual(("93.184.216.34",), addon.parse_dns_response(packet, 7, "example.test"))
        with self.assertRaises(addon.PolicyError):
            addon.parse_dns_response(packet, 8, "example.test")
        with self.assertRaises(addon.PolicyError):
            addon.parse_dns_response(packet, 7, "other.test")

    def test_cname_chain_is_followed_but_unrelated_glue_is_not_used(self) -> None:
        addon = _load_addon()
        host = "example.test"
        target = "edge.example.test"
        question = self._name(host) + b"\x00\x01\x00\x01"
        cname_rdata = self._name(target)
        cname = (
            b"\xc0\x0c"
            + b"\x00\x05\x00\x01"
            + b"\x00\x00\x00\x1e"
            + len(cname_rdata).to_bytes(2, "big")
            + cname_rdata
        )
        # The A owner points into the encoded CNAME RDATA.  The parser must
        # follow the owner chain rather than accept an unrelated A record.
        target_offset = 12 + len(question) + 12
        answer = (
            cname
            + b"\xc0"
            + bytes((target_offset,))
            + b"\x00\x01\x00\x01"
            + b"\x00\x00\x00\x1e\x00\x04"
            + bytes((93, 184, 216, 34))
        )
        packet = (
            (9).to_bytes(2, "big")
            + b"\x81\x80"
            + b"\x00\x01\x00\x02\x00\x00\x00\x00"
            + question
            + answer
        )
        self.assertEqual(("93.184.216.34",), addon.parse_dns_response(packet, 9, host))

    def test_cname_loop_and_compression_loop_are_rejected(self) -> None:
        addon = _load_addon()
        host = "example.test"
        edge = "edge.example.test"
        question = self._name(host) + b"\x00\x01\x00\x01"

        def cname(owner: str, target: str) -> bytes:
            target_wire = self._name(target)
            return (
                self._name(owner)
                + b"\x00\x05\x00\x01"
                + b"\x00\x00\x00\x1e"
                + len(target_wire).to_bytes(2, "big")
                + target_wire
            )

        answer = cname(host, edge) + cname(edge, host)
        packet = (
            (10).to_bytes(2, "big")
            + b"\x81\x80"
            + b"\x00\x01\x00\x02\x00\x00\x00\x00"
            + question
            + answer
        )
        with self.assertRaises(addon.PolicyError):
            addon.parse_dns_response(packet, 10, host)

        owner_offset = 12 + len(question)
        owner = b"\xc0" + bytes((owner_offset,))
        loop_packet = (
            (11).to_bytes(2, "big")
            + b"\x81\x80"
            + b"\x00\x01\x00\x01\x00\x00\x00\x00"
            + question
            + owner
            + b"\x00\x01\x00\x01"
            + b"\x00\x00\x00\x1e\x00\x04"
            + bytes((93, 184, 216, 34))
        )
        with self.assertRaises(addon.PolicyError):
            addon.parse_dns_response(loop_packet, 11, host)

    def test_truncated_bad_rcode_and_oversized_responses_are_rejected(self) -> None:
        addon = _load_addon()
        packet = self._response(12, "example.test", "93.184.216.34")
        with self.assertRaises(addon.PolicyError):
            addon.parse_dns_response(packet[:-1], 12, "example.test")
        truncated = bytearray(packet)
        truncated[2] |= 0x02
        with self.assertRaises(addon.PolicyError):
            addon.parse_dns_response(bytes(truncated), 12, "example.test")
        bad_rcode = bytearray(packet)
        bad_rcode[3] = (bad_rcode[3] & 0xF0) | 0x03
        with self.assertRaises(addon.PolicyError):
            addon.parse_dns_response(bytes(bad_rcode), 12, "example.test")
        with self.assertRaises(addon.PolicyError):
            addon.parse_dns_response(
                b"\x00" * (addon.DNS_MAX_MESSAGE + 1), 12, "example.test"
            )

    def test_unrelated_answer_and_additional_glue_cannot_authorize(self) -> None:
        addon = _load_addon()
        host = "example.test"
        question = self._name(host) + b"\x00\x01\x00\x01"

        def answer(owner: str) -> bytes:
            return (
                self._name(owner)
                + b"\x00\x01\x00\x01"
                + b"\x00\x00\x00\x1e\x00\x04"
                + bytes((93, 184, 216, 34))
            )

        unrelated = (
            (13).to_bytes(2, "big")
            + b"\x81\x80"
            + b"\x00\x01\x00\x01\x00\x00\x00\x00"
            + question
            + answer("other.test")
        )
        with self.assertRaises(addon.PolicyError):
            addon.parse_dns_response(unrelated, 13, host)

        glue = (
            (14).to_bytes(2, "big")
            + b"\x81\x80"
            + b"\x00\x01\x00\x00\x00\x00\x00\x01"
            + question
            + answer("edge.example.test")
        )
        with self.assertRaises(addon.PolicyError):
            addon.parse_dns_response(glue, 14, host)


class PublicPolicyHookTest(unittest.TestCase):
    def setUp(self) -> None:
        self.env = mock.patch.dict(
            os.environ,
            {
                "OPENSANDBOX_EGRESS_PUBLIC_POLICY": _policy_json(),
                "OPENSANDBOX_EGRESS_UPSTREAM_PROXY": "https://gateway.example:8443",
            },
            clear=False,
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addon = _load_addon()
        self.addon.load(types.SimpleNamespace())
        self.client = _Connection("client-one", ("127.0.0.1", 40000))

        async def resolve(host: str) -> tuple[str, ...]:
            return {
                "example.test": ("93.184.216.34",),
                "gateway.example": ("10.20.0.8",),
            }[host]

        self.addon.resolve_a = resolve

    def _public_flow(self, host: str = "example.test") -> tuple[_Flow, _Connection]:
        server = _Connection("destination-one", ("93.184.216.34", 443))
        request = _Request("93.184.216.34", 443, "https", {"Host": host})
        return _Flow(self.client, server, request), server

    def test_public_tls_binds_sni_host_original_and_gateway(self) -> None:
        flow, server = self._public_flow()
        context = types.SimpleNamespace(client=self.client, server=server)
        hello = types.SimpleNamespace(
            context=context,
            client_hello=types.SimpleNamespace(sni="example.test"),
            ignore_connection=True,
        )
        asyncio.run(self.addon.tls_clienthello(hello))
        self.assertFalse(hello.ignore_connection)
        asyncio.run(self.addon.requestheaders(flow))
        self.assertEqual("example.test", flow.request.host)
        self.assertIsNone(flow.response)
        self.assertIsNotNone(getattr(server, self.addon.SERVER_PROXY_PERMIT_ATTR))
        self.assertIn("public policy: route public", self.addon._test_log.messages)
        gateway = _Connection("gateway-one", ("gateway.example", 8443))
        asyncio.run(
            self.addon.server_connect(
                types.SimpleNamespace(client=self.client, server=gateway)
            )
        )
        self.assertEqual(("10.20.0.8", 8443), gateway.address)
        self.assertEqual("gateway.example", getattr(gateway, self.addon.SERVER_PROXY_HOST_ATTR))
        self.assertIsNone(gateway.error)

    def test_host_mismatch_and_private_original_are_denied(self) -> None:
        flow, server = self._public_flow("other.test")
        context = types.SimpleNamespace(client=self.client, server=server)
        asyncio.run(
            self.addon.tls_clienthello(
                types.SimpleNamespace(
                    context=context,
                    client_hello=types.SimpleNamespace(sni="example.test"),
                    ignore_connection=False,
                )
            )
        )
        asyncio.run(self.addon.requestheaders(flow))
        self.assertEqual(403, flow.response.status_code)
        self.assertEqual("EGRESS_PUBLIC_POLICY_SNI_HOST_MISMATCH", flow.metadata[self.addon.FLOW_REJECTION_KEY])

    def test_internal_http_uses_direct_exact_permit(self) -> None:
        internal = [
            {"host": "admin.example", "ips": ["10.0.0.5"], "ports": [8080]}
        ]
        self.addon._policy = self.addon.parse_policy(_policy_json(internal))
        self.addon.resolve_a = lambda host: asyncio.sleep(0, result=("10.0.0.5",))
        server = _Connection("destination-admin", ("10.0.0.5", 8080))
        flow = _Flow(
            self.client,
            server,
            _Request("10.0.0.5", 8080, "http", {"Host": "admin.example:8080"}),
        )
        asyncio.run(self.addon.requestheaders(flow))
        self.assertIsNone(flow.response)
        self.assertIsNotNone(getattr(server, self.addon.SERVER_DIRECT_PERMIT_ATTR))
        self.assertIn("public policy: route internal", self.addon._test_log.messages)
        self.assertEqual("admin.example:8080", flow.request.host_header)
        asyncio.run(
            self.addon.server_connect(
                types.SimpleNamespace(client=self.client, server=server)
            )
        )
        self.assertIsNone(server.error)

    def test_internal_https_may_use_configured_non443_port(self) -> None:
        internal = [
            {"host": "admin.example", "ips": ["10.0.0.5"], "ports": [8443]}
        ]
        self.addon._policy = self.addon.parse_policy(_policy_json(internal))
        self.addon.resolve_a = lambda host: asyncio.sleep(0, result=("10.0.0.5",))
        server = _Connection("destination-admin-tls", ("10.0.0.5", 8443))
        flow = _Flow(
            self.client,
            server,
            _Request("10.0.0.5", 8443, "https", {"Host": "admin.example:8443"}),
        )
        context = types.SimpleNamespace(client=self.client, server=server)
        asyncio.run(
            self.addon.tls_clienthello(
                types.SimpleNamespace(
                    context=context,
                    client_hello=types.SimpleNamespace(sni="admin.example"),
                    ignore_connection=False,
                )
            )
        )
        asyncio.run(self.addon.requestheaders(flow))
        self.assertIsNone(flow.response)
        self.assertIsNotNone(getattr(server, self.addon.SERVER_DIRECT_PERMIT_ATTR))
        self.assertEqual("admin.example:8443", flow.request.host_header)

    def test_public_http_is_denied_even_for_global_address(self) -> None:
        flow, _server = self._public_flow()
        flow.request.scheme = "http"
        asyncio.run(self.addon.requestheaders(flow))
        self.assertEqual(403, flow.response.status_code)
        self.assertEqual("EGRESS_PUBLIC_POLICY_PUBLIC_HTTP_DENIED", flow.metadata[self.addon.FLOW_REJECTION_KEY])

    def test_invalid_dns_hook_fails_closed(self) -> None:
        flow, server = self._public_flow()
        self.addon.resolve_a = lambda host: (_ for _ in ()).throw(
            self.addon.PolicyError("EGRESS_PUBLIC_POLICY_DNS_TIMEOUT")
        )
        # No TLS binding can be issued if DNS fails. requestheaders must still
        # produce a local denial, never an exception that lets upstream
        # proxying continue.
        context = types.SimpleNamespace(client=self.client, server=server)
        asyncio.run(
            self.addon.tls_clienthello(
                types.SimpleNamespace(
                    context=context,
                    client_hello=types.SimpleNamespace(sni="example.test"),
                    ignore_connection=False,
                )
            )
        )
        asyncio.run(self.addon.requestheaders(flow))
        self.assertEqual(403, flow.response.status_code)
        self.assertEqual("EGRESS_PUBLIC_POLICY_DNS_TIMEOUT", flow.metadata[self.addon.FLOW_REJECTION_KEY])
        self.assertIsNone(getattr(server, self.addon.SERVER_PROXY_PERMIT_ATTR, None))


class StrictUpstreamIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.env = mock.patch.dict(
            os.environ,
            {
                "OPENSANDBOX_EGRESS_PUBLIC_POLICY": _policy_json(),
                "OPENSANDBOX_EGRESS_UPSTREAM_PROXY": "https://gateway.example:8443",
            },
            clear=False,
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addon = _load_upstream_addon()
        self.addon.load(types.SimpleNamespace())

    def test_existing_public_policy_server_error_is_preserved(self) -> None:
        server = _Connection("gateway-error", ("gateway.example", 8443))
        server.error = "EGRESS_PUBLIC_POLICY_DNS_TIMEOUT"
        self.addon.server_connect(types.SimpleNamespace(server=server))
        self.assertEqual("EGRESS_PUBLIC_POLICY_DNS_TIMEOUT", server.error)

    def test_internal_marker_allows_direct_without_gateway_identity(self) -> None:
        server = _Connection("internal-direct", ("10.0.0.5", 8080))
        setattr(server, self.addon.PUBLIC_DIRECT_PERMIT_ATTR, object())
        self.addon.server_connect(types.SimpleNamespace(server=server))
        self.assertIsNone(server.error)

    def test_proxy_marker_requires_configured_gateway_identity(self) -> None:
        server = _Connection("gateway-proxy", ("10.20.0.8", 8443))
        setattr(server, self.addon.PUBLIC_PROXY_PERMIT_ATTR, object())
        setattr(server, self.addon.PUBLIC_PROXY_HOST_ATTR, "gateway.example")
        self.addon.server_connect(types.SimpleNamespace(server=server))
        self.assertIsNone(server.error)

    def test_identity_denials_are_logged_as_stable_codes(self) -> None:
        self.addon._identity_file = str(Path("missing-identity.jwt"))
        server = _Connection("gateway-identity-error", ("10.20.0.8", 8443))
        setattr(server, self.addon.PUBLIC_PROXY_PERMIT_ATTR, object())
        setattr(server, self.addon.PUBLIC_PROXY_HOST_ATTR, "gateway.example")
        self.addon.server_connect(types.SimpleNamespace(server=server))
        self.assertIn(
            "upstream proxy: identity denied EGRESS_IDENTITY_UNAVAILABLE",
            self.addon._test_log.messages,
        )

        flow = types.SimpleNamespace(
            server_conn=server,
            request=types.SimpleNamespace(
                headers={}, stream=False, http_version="HTTP/1.1"
            ),
            response=None,
            error=None,
            killable=True,
        )
        self.addon.requestheaders(flow)
        self.assertIn(
            "upstream proxy: identity denied EGRESS_IDENTITY_UNAVAILABLE",
            self.addon._test_log.messages,
        )


if __name__ == "__main__":
    unittest.main()
