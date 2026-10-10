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

"""Live credential-bound admission tests for the egress system addon.

These tests drive the addon hooks directly with a fake mitmproxy context
(the same harness style as test_mitmscripts_system.py) plus the real
LiveReceiver/Registry publication stack, covering the OSEP-0023 phase-3
sidecar loop: TLS decrypt/pass-through decisions, per-revision request
admission, SNI/authority agreement, rotation, removal fencing, remove/re-add,
drain expiry, and fail-closed boundaries.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

MITMSCRIPTS = Path(__file__).resolve().parents[1] / "mitmscripts"

ENV = {
    "socket": "OPENSANDBOX_EGRESS_REVISION_IPC_SOCKET",
    "token": "OPENSANDBOX_EGRESS_REVISION_IPC_TOKEN",
    "control": "OPENSANDBOX_EGRESS_REVISION_CONTROL_GENERATION",
    "subject": "OPENSANDBOX_EGRESS_REVISION_SUBJECT_GENERATION",
    "limit": "OPENSANDBOX_EGRESS_REVISION_MAX_SNAPSHOT_BYTES",
}
LIVE_ENV = {
    "tls_capacity": "OPENSANDBOX_EGRESS_REVISION_TLS_CAPACITY",
    "request_capacity": "OPENSANDBOX_EGRESS_REVISION_REQUEST_CAPACITY",
    "drain_timeout": "OPENSANDBOX_EGRESS_REVISION_DRAIN_TIMEOUT_SECONDS",
}

CONTROL = "control-live-a"
SUBJECT = "subject-live-a"
TOKEN = "a" * 43


class _Log:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def warn(self, message: str) -> None:
        self.messages.append(message)

    def info(self, message: str) -> None:
        self.messages.append(message)


class _Headers:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self._values: dict[str, str] = dict(values or {})

    def get(self, name: str, default: str = "") -> str:
        for key, value in self._values.items():
            if key.lower() == name.lower():
                return value
        return default

    def items(self) -> list[tuple[str, str]]:
        return list(self._values.items())

    def __setitem__(self, name: str, value: str) -> None:
        self._values[name] = value

    def __contains__(self, name: str) -> bool:
        return any(key.lower() == name.lower() for key in self._values)

    def __delitem__(self, name: str) -> None:
        for key in list(self._values):
            if key.lower() == name.lower():
                del self._values[key]
                return


class _ClientHello:
    def __init__(self, sni: str | None) -> None:
        self.sni = sni


class _ClientConn:
    _counter = 0

    def __init__(self, sni: str | None = None) -> None:
        _ClientConn._counter += 1
        self.id = f"fake-client-{_ClientConn._counter}"
        self.sni = sni
        self.peername = ("127.0.0.1", 51234)
        self.closed = False
        self.state = "open"

    def close(self) -> None:
        self.closed = True


class _ClientHelloData:
    def __init__(self, sni: str | None, client_conn: _ClientConn | None = None) -> None:
        self.client_hello = _ClientHello(sni)
        client = client_conn if client_conn is not None else _ClientConn(sni)
        self.context = types.SimpleNamespace(client=client)
        self.ignore_connection = False

    @property
    def client_conn(self) -> "_ClientConn":
        return self.context.client


class _Request:
    def __init__(self, host: str = "api.example.com", path: str = "/v1/data") -> None:
        self.pretty_host = host
        self.host = host
        self.port = 443
        self.scheme = "https"
        self.method = "GET"
        self.path = path
        self.headers = _Headers()
        self.raw_content: bytes | None = None
        self.content = b""
        self.stream = False
        self.http_version = "HTTP/1.1"


class _Response:
    def __init__(self) -> None:
        self.headers = _Headers({"content-type": "application/json"})
        self.stream = False

    @staticmethod
    def make(status_code: int, body: bytes = b"", headers: dict | None = None) -> "_Response":
        response = _Response()
        response.status_code = status_code
        response.body = body
        if headers:
            response.headers = _Headers(headers)
        return response


class _Flow:
    def __init__(self, client_conn: _ClientConn | None = None, host: str = "api.example.com") -> None:
        self.request = _Request(host=host)
        self.response: Any = None
        self.metadata: dict[str, Any] = {}
        self.client_conn = client_conn
        self.error = None
        self.live = True
        self.killable = True
        self.killed = False

    def kill(self) -> None:
        self.killed = True
        self.error = "Killed"
        self.live = False


def _load_system_module() -> Any:
    mitmproxy = types.ModuleType("mitmproxy")
    mitmproxy.ctx = types.SimpleNamespace(
        log=_Log(), options=types.SimpleNamespace(ignore_hosts=[], ssl_insecure=False)
    )
    mitmproxy.http = types.SimpleNamespace(HTTPFlow=object, Response=_Response)
    mitmproxy_tls = types.ModuleType("mitmproxy.tls")
    mitmproxy_tls.ClientHelloData = object
    sys.modules["mitmproxy"] = mitmproxy
    sys.modules["mitmproxy.tls"] = mitmproxy_tls
    spec = importlib.util.spec_from_file_location(
        "opensandbox_credential_bound_system", MITMSCRIPTS / "system.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _binding(name: str, host: str, header_value: str, methods=("GET",), paths=("/v1/*",)) -> dict[str, Any]:
    return {
        "name": name,
        "match": {
            "schemes": ["https"],
            "hosts": [host],
            "methods": list(methods),
            "paths": list(paths),
        },
        "headers": [{"name": "Authorization", "value": header_value}],
    }


def _decision_payload(
    bindings: list[dict[str, Any]], redactions: list[str], vault_revision: int
) -> bytes:
    selectors = sorted(
        {
            host
            for binding in bindings
            if "https" in binding["match"]["schemes"]
            for host in binding["match"]["hosts"]
        }
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


def _revision(payload: bytes, epoch: int, vault_revision: int) -> Any:
    from revision_receiver import Revision

    return Revision(CONTROL, SUBJECT, epoch, vault_revision, 0, hashlib.sha256(payload).hexdigest())


def _sort_bindings(bindings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(bindings, key=lambda item: item["name"])


def _system_with_live_runtime() -> tuple[Any, Any, Any]:
    # Load the system module first: it installs the fake mitmproxy package
    # that the mitmscripts modules import at module scope.
    system = _load_system_module()
    from credential_bound import LiveRuntime
    from revision_publication import LiveReceiver

    receiver = LiveReceiver(
        CONTROL, SUBJECT, max_snapshot_bytes=1 << 20, capacity=64, request_capacity=256,
        drain_timeout_seconds=1,
    )
    runtime = LiveRuntime(receiver, identity=(CONTROL, SUBJECT))
    system._live_runtime = runtime
    return system, receiver, runtime


class CredentialBoundTLSTest(unittest.TestCase):
    def setUp(self) -> None:
        sys.path.insert(0, str(MITMSCRIPTS))
        self.system, self.receiver, self.runtime = _system_with_live_runtime()
        self._epoch = 0

    def tearDown(self) -> None:
        sys.path.remove(str(MITMSCRIPTS))
        sys.modules.pop("credential_bound", None)
        sys.modules.pop("revision_ipc", None)
        sys.modules.pop("revision_publication", None)
        sys.modules.pop("revision_receiver", None)
        sys.modules.pop("tls_registry", None)
        sys.modules.pop("tls_decision", None)
        sys.modules.pop("decision_snapshot", None)
        sys.modules.pop("host_selectors", None)

    def _install(self, bindings: list[dict[str, Any]], redactions: list[str], revision: int) -> None:
        self._epoch += 1
        payload = _decision_payload(bindings, redactions, revision)
        identity = _revision(payload, self._epoch, revision)
        self.receiver.prepare(identity, payload)
        self.receiver.commit(identity)

    def test_bootstrapping_state_denies_and_closes(self) -> None:
        data = _ClientHelloData("api.example.com")
        self.system.tls_clienthello(data)
        self.assertFalse(data.ignore_connection)
        self.assertTrue(data.client_conn.closed)

    def test_active_empty_passes_through(self) -> None:
        self._install([], [], 0)
        data = _ClientHelloData("api.example.com")
        self.system.tls_clienthello(data)
        self.assertTrue(data.ignore_connection)
        self.assertFalse(data.client_conn.closed)

    def test_bound_host_decrypts_and_tracks_token(self) -> None:
        self._install([_binding("api", "api.example.com", "token-v1")], ["token-v1"], 1)
        data = _ClientHelloData("api.example.com")
        self.system.tls_clienthello(data)
        self.assertFalse(data.ignore_connection)
        self.assertFalse(data.client_conn.closed)
        self.assertIsNotNone(self.runtime.token_for(data.client_conn))

    def test_unbound_host_passes_through(self) -> None:
        self._install([_binding("api", "api.example.com", "token-v1")], ["token-v1"], 1)
        data = _ClientHelloData("other.example.com")
        self.system.tls_clienthello(data)
        self.assertTrue(data.ignore_connection)
        self.assertFalse(data.client_conn.closed)

    def test_no_sni_passes_through(self) -> None:
        self._install([_binding("api", "api.example.com", "token-v1")], ["token-v1"], 1)
        data = _ClientHelloData(None)
        self.system.tls_clienthello(data)
        self.assertTrue(data.ignore_connection)
        self.assertFalse(data.client_conn.closed)

    def test_invalid_sni_denies(self) -> None:
        self._install([_binding("api", "api.example.com", "token-v1")], ["token-v1"], 1)
        data = _ClientHelloData("api..example.com")
        self.system.tls_clienthello(data)
        self.assertFalse(data.ignore_connection)
        self.assertTrue(data.client_conn.closed)

    def test_legacy_ignore_hosts_static_passthrough_wins(self) -> None:
        import mitmproxy as fake_mitmproxy

        fake_mitmproxy.ctx.options.ignore_hosts = ["^ignored\\."]

        class _WithOptions:
            def __enter__(self) -> None:
                return None

            def __exit__(self, *_args: object) -> bool:
                return True

        # ctx is shared per module load; patch the option directly.
        self.system.ctx.options.ignore_hosts = ["^ignored\\."]
        self._install([_binding("api", "api.example.com", "token-v1")], ["token-v1"], 1)
        data = _ClientHelloData("ignored.example.com")
        self.system.tls_clienthello(data)
        self.assertTrue(data.ignore_connection)
        self.assertFalse(data.client_conn.closed)

    def test_registry_exhaustion_closes_new_bound_connection(self) -> None:
        # capacity=64 in setUp: admit 64 connections first.
        self._install([_binding("api", "api.example.com", "token-v1")], ["token-v1"], 1)
        for _ in range(64):
            data = _ClientHelloData("api.example.com")
            self.system.tls_clienthello(data)
            self.assertFalse(data.ignore_connection)
        overflow = _ClientHelloData("api.example.com")
        self.system.tls_clienthello(overflow)
        self.assertFalse(overflow.ignore_connection)
        self.assertTrue(overflow.client_conn.closed)

    def test_disconnect_releases_token(self) -> None:
        self._install([_binding("api", "api.example.com", "token-v1")], ["token-v1"], 1)
        data = _ClientHelloData("api.example.com")
        self.system.tls_clienthello(data)
        token = self.runtime.token_for(data.client_conn)
        self.assertIsNotNone(token)
        self.system.client_disconnected(data.client_conn)
        self.assertIsNone(self.runtime.token_for(data.client_conn))
        self.assertEqual(self.runtime.registry.count, 0)


class CredentialBoundRequestTest(unittest.TestCase):
    def setUp(self) -> None:
        sys.path.insert(0, str(MITMSCRIPTS))
        self.system, self.receiver, self.runtime = _system_with_live_runtime()
        self._epoch = 0
        self.install_revision(1, "token-v1")

    def tearDown(self) -> None:
        sys.path.remove(str(MITMSCRIPTS))
        for module in (
            "credential_bound",
            "revision_ipc",
            "revision_publication",
            "revision_receiver",
            "tls_registry",
            "tls_decision",
            "decision_snapshot",
            "host_selectors",
        ):
            sys.modules.pop(module, None)

    def install_revision(self, revision_value: int, token: str) -> None:
        self._epoch += 1
        payload = _decision_payload(
            [_binding("api", "api.example.com", token)], [token], revision_value
        )
        identity = _revision(payload, self._epoch, revision_value)
        self.receiver.prepare(identity, payload)
        self.receiver.commit(identity)

    def _admitted_flow(self, host: str = "api.example.com", path: str = "/v1/data") -> _Flow:
        conn = _ClientConn(sni="api.example.com")
        data = _ClientHelloData("api.example.com", conn)
        self.system.tls_clienthello(data)
        self.assertFalse(conn.closed)
        return _Flow(client_conn=conn, host=host)

    def test_authorized_request_receives_credential(self) -> None:
        flow = self._admitted_flow()
        self.system.requestheaders(flow)
        self.assertEqual(flow.request.headers.get("Authorization"), "token-v1")
        handle = flow.metadata.get("opensandbox_credential_request_handle")
        self.assertIsNotNone(handle)
        self.system.response(flow)
        self.assertNotIn("opensandbox_credential_request_handle", flow.metadata)
        self.assertEqual(self.runtime.registry.request_count, 0)

    def test_keepalive_rotation_uses_new_revision_per_request(self) -> None:
        flow_one = self._admitted_flow()
        self.system.requestheaders(flow_one)
        self.assertEqual(flow_one.request.headers.get("Authorization"), "token-v1")

        self.install_revision(2, "token-v2")
        flow_two = self._admitted_flow()
        self.system.requestheaders(flow_two)
        self.assertEqual(flow_two.request.headers.get("Authorization"), "token-v2")
        # The in-flight request admitted before the cutover keeps its snapshot.
        self.assertEqual(flow_one.request.headers.get("Authorization"), "token-v1")
        self.system.response(flow_one)
        self.system.response(flow_two)

    def test_wrong_path_gets_no_credential(self) -> None:
        flow = self._admitted_flow()
        flow.request.path = "/health"
        self.system.requestheaders(flow)
        self.assertNotIn("Authorization", flow.request.headers)
        self.assertIsNone(flow.response)

    def test_wrong_method_gets_no_credential(self) -> None:
        flow = self._admitted_flow()
        flow.request.method = "DELETE"
        self.system.requestheaders(flow)
        self.assertNotIn("Authorization", flow.request.headers)
        self.assertIsNone(flow.response)

    def test_authority_mismatch_is_rejected(self) -> None:
        flow = self._admitted_flow(host="api.example.com")
        # The request authority still matches the binding, but the transport
        # was intercepted for a different SNI: credentials must not flow.
        flow.client_conn.sni = "front.example.com"
        self.system.requestheaders(flow)
        self.assertNotIn("Authorization", flow.request.headers)
        self.assertEqual(flow.response.status_code, 403)
        self.system.response(flow)

    def test_missing_sni_authority_is_rejected(self) -> None:
        flow = self._admitted_flow()
        flow.client_conn.sni = None
        self.system.requestheaders(flow)
        self.assertNotIn("Authorization", flow.request.headers)
        self.assertEqual(flow.response.status_code, 403)
        self.system.response(flow)

    def test_unadmitted_connection_is_rejected(self) -> None:
        flow = _Flow(client_conn=_ClientConn(sni="api.example.com"))
        self.system.requestheaders(flow)
        self.assertEqual(flow.response.status_code, 503)
        self.assertNotIn("Authorization", flow.request.headers)

    def test_plain_http_is_untouched(self) -> None:
        conn = _ClientConn(sni="api.example.com")
        data = _ClientHelloData("api.example.com", conn)
        self.system.tls_clienthello(data)
        flow = _Flow(client_conn=conn)
        flow.request.scheme = "http"
        flow.request.port = 80
        self.system.requestheaders(flow)
        self.assertNotIn("Authorization", flow.request.headers)
        self.assertIsNone(flow.response)

    def test_error_hook_releases_handle(self) -> None:
        flow = self._admitted_flow()
        self.system.requestheaders(flow)
        self.system.error(flow)
        self.assertNotIn("opensandbox_credential_request_handle", flow.metadata)
        self.assertEqual(self.runtime.registry.request_count, 0)


class CredentialBoundRemovalTest(unittest.TestCase):
    def setUp(self) -> None:
        sys.path.insert(0, str(MITMSCRIPTS))
        self.system, self.receiver, self.runtime = _system_with_live_runtime()
        self._epoch = 0
        self.install_revision(1, "token-v1", ["api.example.com"])

    def tearDown(self) -> None:
        sys.path.remove(str(MITMSCRIPTS))
        for module in (
            "credential_bound",
            "revision_ipc",
            "revision_publication",
            "revision_receiver",
            "tls_registry",
            "tls_decision",
            "decision_snapshot",
            "host_selectors",
        ):
            sys.modules.pop(module, None)

    def install_revision(self, revision_value: int, token: str, hosts: list[str]) -> None:
        self._epoch += 1
        bindings = [_binding("api", host, token) for host in hosts]
        redactions = [token] if hosts else []
        payload = _decision_payload(bindings, redactions, revision_value)
        identity = _revision(payload, self._epoch, revision_value)
        self.receiver.prepare(identity, payload)
        self.receiver.commit(identity)

    def _admitted_flow(self) -> tuple[_Flow, _ClientConn]:
        conn = _ClientConn(sni="api.example.com")
        self.system.tls_clienthello(_ClientHelloData("api.example.com", conn))
        return _Flow(client_conn=conn), conn

    def test_delete_fences_new_requests_on_keepalive_connection(self) -> None:
        flow, _conn = self._admitted_flow()
        self.system.requestheaders(flow)
        self.assertEqual(flow.request.headers.get("Authorization"), "token-v1")
        self.system.response(flow)

        self.install_revision(2, "token-v2", [])
        denied = _Flow(client_conn=_conn)
        self.system.requestheaders(denied)
        self.assertNotIn("Authorization", denied.request.headers)
        self.assertEqual(denied.response.status_code, 403)
        self.assertEqual(denied.response.headers.get("connection"), "close")
        self.system.response(denied)

    def test_delete_drains_expired_connection(self) -> None:
        flow, conn = self._admitted_flow()
        self.system.requestheaders(flow)
        self.system.response(flow)
        self.install_revision(2, "token-v2", [])
        self.assertFalse(conn.closed)
        # drain_timeout_seconds=1 in setUp; advance the clock by expiry.
        import tls_registry

        with mock.patch.object(tls_registry.time, "monotonic", return_value=time_time() + 10):
            closed = self.runtime.drain_sweep_once()
        self.assertGreaterEqual(closed, 1)
        self.assertTrue(conn.closed)
        self.system.client_disconnected(conn)
        self.assertEqual(self.runtime.registry.count, 0)

    def test_remove_readd_does_not_resurrect_old_connection(self) -> None:
        flow, conn = self._admitted_flow()
        self.system.requestheaders(flow)
        self.system.response(flow)

        self.install_revision(2, "token-v2", [])
        denied = _Flow(client_conn=conn)
        self.system.requestheaders(denied)
        self.assertEqual(denied.response.status_code, 403)
        self.system.response(denied)

        self.install_revision(3, "token-v3", ["api.example.com"])
        still_denied = _Flow(client_conn=conn)
        self.system.requestheaders(still_denied)
        self.assertEqual(still_denied.response.status_code, 403)
        self.assertNotIn("Authorization", still_denied.request.headers)
        self.system.response(still_denied)

        # A fresh connection is admitted under the re-added host.
        fresh_conn = _ClientConn(sni="api.example.com")
        self.system.tls_clienthello(_ClientHelloData("api.example.com", fresh_conn))
        self.assertFalse(fresh_conn.closed)
        fresh = _Flow(client_conn=fresh_conn)
        self.system.requestheaders(fresh)
        self.assertEqual(fresh.request.headers.get("Authorization"), "token-v3")
        self.system.response(fresh)
        self.system.client_disconnected(conn)
        self.system.client_disconnected(fresh_conn)

    def test_new_connections_pass_through_after_delete(self) -> None:
        self.install_revision(2, "token-v2", [])
        data = _ClientHelloData("api.example.com")
        self.system.tls_clienthello(data)
        self.assertTrue(data.ignore_connection)
        self.assertFalse(data.client_conn.closed)


def time_time() -> float:
    import time

    return time.monotonic()


class CredentialBoundSnapshotValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        sys.path.insert(0, str(MITMSCRIPTS))
        self.system, self.receiver, self.runtime = _system_with_live_runtime()
        self.conn = _ClientConn(sni="api.example.com")
        self.system.tls_clienthello(_ClientHelloData("api.example.com", self.conn))
        self.flow = _Flow(client_conn=self.conn)

    def tearDown(self) -> None:
        sys.path.remove(str(MITMSCRIPTS))
        for module in (
            "credential_bound",
            "revision_ipc",
            "revision_publication",
            "revision_receiver",
            "tls_registry",
            "tls_decision",
            "decision_snapshot",
            "host_selectors",
        ):
            sys.modules.pop(module, None)

    def test_revision_disagreement_fails_closed(self) -> None:
        payload = _decision_payload(
            [_binding("api", "api.example.com", "token-v1")], ["token-v1"], 5
        )
        identity = _revision(payload, 1, 1)  # envelope revision 1, payload says 5
        # The receiver rejects digest/envelope disagreement at prepare, so
        # simulate the corrupted payload reaching the flow layer directly.
        from revision_receiver import Snapshot

        snapshot = Snapshot(identity, payload)
        with mock.patch.object(
            self.runtime, "token_for", return_value=object()
        ), mock.patch.object(
            self.runtime, "acquire_request", return_value=_fake_admission(snapshot)
        ):
            self.system.requestheaders(self.flow)
        self.assertEqual(self.flow.response.status_code, 503)
        self.assertNotIn("Authorization", self.flow.request.headers)

    def test_empty_snapshot_passes_request_through(self) -> None:
        payload = _decision_payload([], [], 0)
        identity = _revision(payload, 1, 0)
        from revision_receiver import Snapshot

        snapshot = Snapshot(identity, payload)
        with mock.patch.object(
            self.runtime, "token_for", return_value=object()
        ), mock.patch.object(
            self.runtime, "acquire_request", return_value=_fake_admission(snapshot)
        ):
            self.system.requestheaders(self.flow)
        self.assertIsNone(self.flow.response)
        self.assertNotIn("Authorization", self.flow.request.headers)
        self.system.response(self.flow)


class _FakeAdmission:
    def __init__(self, snapshot: Any) -> None:
        self.action = "allow"
        self.reason = "admitted"
        self.snapshot = snapshot
        self.handle = object()


def _fake_admission(snapshot: Any) -> _FakeAdmission:
    return _FakeAdmission(snapshot)


class CredentialBoundEnvTest(unittest.TestCase):
    """configure() validation through the real IPC server path."""

    def setUp(self) -> None:
        import tempfile

        self.directory = tempfile.TemporaryDirectory(prefix="oscb-", dir="/tmp")
        self.path = str(Path(self.directory.name) / "receiver.sock")
        sys.path.insert(0, str(MITMSCRIPTS))

    def tearDown(self) -> None:
        sys.path.remove(str(MITMSCRIPTS))
        self.directory.cleanup()

    def _env(self, extra: dict[str, str]) -> dict[str, str]:
        env = {name: value for name, value in ENV.items()}
        env[ENV["socket"]] = self.path
        env[ENV["token"]] = TOKEN
        env[ENV["control"]] = CONTROL
        env[ENV["subject"]] = SUBJECT
        env[ENV["limit"]] = "1048576"
        env.update(extra)
        return env

    def test_live_configuration_builds_runtime_and_server(self) -> None:
        system = _load_system_module()
        live = {
            LIVE_ENV["tls_capacity"]: "64",
            LIVE_ENV["request_capacity"]: "256",
            LIVE_ENV["drain_timeout"]: "5",
        }
        with mock.patch.dict(os_environ(), self._env(live), clear=False):
            system.load(None)
        try:
            self.assertIsNotNone(system._live_runtime)
            self.assertIsNotNone(system._revision_server)
            self.assertTrue(Path(self.path).exists())
            system._live_runtime.close()
        finally:
            system.done()

    def test_partial_live_bundle_fails_closed(self) -> None:
        system = _load_system_module()
        partial = {LIVE_ENV["tls_capacity"]: "64"}
        with mock.patch.dict(os_environ(), self._env(partial), clear=False):
            with self.assertRaises(SystemExit):
                system.load(None)

    def test_invalid_drain_timeout_fails_closed(self) -> None:
        system = _load_system_module()
        invalid = {
            LIVE_ENV["tls_capacity"]: "64",
            LIVE_ENV["request_capacity"]: "256",
            LIVE_ENV["drain_timeout"]: "0",
        }
        with mock.patch.dict(os_environ(), self._env(invalid), clear=False):
            with self.assertRaises(SystemExit):
                system.load(None)

    def test_missing_live_bundle_keeps_installation_receiver(self) -> None:
        system = _load_system_module()
        with mock.patch.dict(os_environ(), self._env({}), clear=False):
            for key in LIVE_ENV.values():
                os_environ().pop(key, None)
            system.load(None)
        try:
            self.assertIsNone(system._live_runtime)
            self.assertIsNotNone(system._revision_server)
        finally:
            system.done()


def os_environ() -> dict[str, str]:
    import os

    return os.environ


if __name__ == "__main__":
    unittest.main()
