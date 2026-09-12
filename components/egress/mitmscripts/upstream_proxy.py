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

# OpenSandbox egress chained upstream-proxy addon.
#
# Loaded by the egress mitmproxy launcher (after system.py, before user addons)
# only when OPENSANDBOX_EGRESS_UPSTREAM_PROXY is set. Routes every
# mitmproxy-handled connection through a chained HTTP CONNECT proxy.
#
# Behavior:
#   1. Sets server_conn.via on each flow, so mitmproxy's upstream-proxy layer
#      dials the configured proxy and issues "CONNECT <request.host>:<port>".
#      For TLS-intercepted traffic request.host is the SNI/Host-derived FQDN,
#      keeping CONNECT authority, SNI and Host consistent; for flows where only
#      the original destination IP is known the authority stays IP:port.
#   2. Optionally injects Proxy-Authorization on the upstream CONNECT from
#      OPENSANDBOX_EGRESS_UPSTREAM_PROXY_AUTH (complete header value, never
#      logged).
#   3. Fail-closed: server_connect refuses any direct dial that is not the
#      proxy's own tunnel connection. TLS pass-through flows (no-SNI,
#      ignore_hosts/tcp_hosts matches) and UDP/QUIC dials cannot be chained,
#      so they are refused rather than silently bypassing the proxy.
#
# Requirements (validated at load; violations fail closed):
#   - connection_strategy must be "lazy" (the shipped config.yaml default).
#      Eager connects upstream before request headers arrive, so no via can be
#      applied and every flow would be refused at runtime.
#   - ignore_hosts / tcp_hosts / udp_hosts must be empty: pass-through traffic
#      cannot be chained and enabling both options would silently exempt
#      destinations from the proxy.
#
# For https:// proxies, TLS to the proxy is verified against
# ssl_verify_upstream_trusted_confdir / _trusted_ca (default /etc/ssl/certs,
# overridable via OPENSANDBOX_EGRESS_MITMPROXY_UPSTREAM_TRUST_DIR) with SNI and
# hostname verification against the proxy host.

from __future__ import annotations

import base64
import json
import math
import os
import re
import stat
import time
import types
from urllib.parse import urlsplit

from mitmproxy import ctx, http

UPSTREAM_PROXY_ENV = "OPENSANDBOX_EGRESS_UPSTREAM_PROXY"
UPSTREAM_PROXY_AUTH_ENV = "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_AUTH"
IDENTITY_FILE_ENV = "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_IDENTITY_FILE"
CA_FILE_ENV = "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_CA_FILE"
PUBLIC_POLICY_ENV = "OPENSANDBOX_EGRESS_PUBLIC_POLICY"

# Private, process-local markers written by public_policy.py.  They are
# deliberately duplicated rather than imported: mitmproxy loads each script
# under a generated module name, and the chained addon must remain usable by
# itself in legacy mode.  These markers have meaning only when the strict
# policy environment is present.
PUBLIC_PROXY_PERMIT_ATTR = "_opensandbox_public_policy_proxy_permit"
PUBLIC_DIRECT_PERMIT_ATTR = "_opensandbox_public_policy_direct_permit"
PUBLIC_PROXY_HOST_ATTR = "_opensandbox_public_policy_proxy_host"
PUBLIC_PERMIT_REQUIRED = "EGRESS_PUBLIC_POLICY_PERMIT_REQUIRED"

_via: tuple[str, tuple[str, int]] | None = None
_proxy_address: tuple[str, int] | None = None
_proxy_auth: str | None = None
_identity_file: str | None = None
_gateway_tls_context = None
_connection_identities: dict[object, str] = {}
_strict_mode = False
_proxy_tls_hostname: str | None = None

# Public events are deliberately a tiny, fixed vocabulary.  Keep the marker
# state separate from mitmproxy's flow objects: public_policy.py is loaded
# first and removes its private Server attributes from server_connect_error /
# server_disconnected.  The state is only an observability correlation aid;
# it never authorizes a connection or carries credentials.
_GATEWAY_EVENT_NAMES = frozenset(
    {
        "gateway_tls_failed",
        "gateway_connect_failed",
        "gateway_connect_denied",
        "gateway_grant_denied",
        "gateway_rate_limited",
    }
)
_MAX_GATEWAY_CONNECTIONS = 1024
_MAX_GATEWAY_EVENT_KEYS = 4096
_GATEWAY_STATE_GRACE = 5.0
_gateway_connections: dict[tuple[object, object], dict[str, object]] = {}
_gateway_event_keys: dict[tuple[object, object, str], None] = {}
_GATEWAY_CONNECT_REFUSAL = re.compile(
    r"^Upstream proxy [^\r\n]{1,512} refused HTTP CONNECT request: "
    r"([0-9]{3})(?:[ \t]+[^\r\n]{0,512})?$"
)


class IdentityError(ValueError):
    """Only a stable code, never file contents, may escape identity parsing."""


def _log_identity_denied(error: BaseException) -> None:
    code = str(error)
    if not re.fullmatch(r"EGRESS_IDENTITY_[A-Z_]+", code):
        code = "EGRESS_IDENTITY_INVALID"
    try:
        ctx.log.warn(f"upstream proxy: identity denied {code}")
    except Exception:
        pass


def _hook_key_part(value, fallback) -> object:
    """Return a bounded-map-safe id without retaining an arbitrary object."""

    candidate = getattr(value, "id", None) if value is not None else None
    if candidate is None:
        return fallback
    try:
        hash(candidate)
    except (TypeError, ValueError):
        return fallback
    return candidate


def _server_hook_key(server, client=None) -> tuple[object, object]:
    # mitmproxy's pinned ServerConnectionHookData always supplies client and
    # server ids.  The object-id fallbacks keep the helper safe for narrowly
    # constructed test doubles without making a global object reference.
    return (
        _hook_key_part(client, id(client) if client is not None else None),
        _hook_key_part(server, id(server)),
    )


def _gateway_error_kind(error) -> str | None:
    """Classify only stable local errors; never retain or log their text."""

    if not isinstance(error, str):
        return None
    if error.startswith("EGRESS_IDENTITY_"):
        return "identity"
    if error.startswith("EGRESS_PUBLIC_POLICY_"):
        return "denied"
    return None


def _strict_gateway_marker(server) -> bool:
    """Recognize only a policy-marked, actual gateway Server object."""

    if not _strict_mode or server is None:
        return False
    if getattr(server, PUBLIC_PROXY_PERMIT_ATTR, None) is None:
        return False
    if _via is None or _proxy_address is None:
        return False
    marker_host = getattr(server, PUBLIC_PROXY_HOST_ATTR, None)
    if not isinstance(marker_host, str):
        return False
    if marker_host.rstrip(".").lower() != str(_proxy_address[0]).rstrip(".").lower():
        return False
    if getattr(server, "transport_protocol", "tcp") != "tcp":
        return False
    # The gateway Server is the outer connection made by mitmproxy's
    # HttpUpstreamProxy.  A destination placeholder has a non-None via and is
    # intentionally not an event source.
    if getattr(server, "via", None) is not None:
        return False
    address = getattr(server, "address", None)
    try:
        if address is None or len(address) < 2 or int(address[1]) != _proxy_address[1]:
            return False
    except (TypeError, ValueError, IndexError):
        return False
    return True


def _purge_gateway_connections() -> None:
    now = time.monotonic()
    removed: set[tuple[object, object]] = set()
    for key, state in list(_gateway_connections.items()):
        closed_at = state.get("closed_at")
        if isinstance(closed_at, (int, float)) and now - closed_at >= _GATEWAY_STATE_GRACE:
            _gateway_connections.pop(key, None)
            removed.add(key)
    # A bounded state map is important for clients that repeatedly fail before
    # mitmproxy can deliver the disconnect callback.
    while len(_gateway_connections) > _MAX_GATEWAY_CONNECTIONS:
        key = next(iter(_gateway_connections))
        _gateway_connections.pop(key, None)
        removed.add(key)
    if removed:
        for event_key in list(_gateway_event_keys):
            if event_key[:2] in removed:
                _gateway_event_keys.pop(event_key, None)
    while len(_gateway_event_keys) > _MAX_GATEWAY_EVENT_KEYS:
        _gateway_event_keys.pop(next(iter(_gateway_event_keys)), None)


def _remember_gateway_connection(data, server) -> dict[str, object] | None:
    if not _strict_gateway_marker(server):
        return None
    _purge_gateway_connections()
    client = getattr(data, "client", None)
    key = _server_hook_key(server, client)
    state = _gateway_connections.get(key)
    if state is None or state.get("server_object") != id(server):
        # A recycled mitmproxy id must never inherit an earlier event state.
        if state is not None:
            _gateway_connections.pop(key, None)
            for event_key in list(_gateway_event_keys):
                if event_key[:2] == key:
                    _gateway_event_keys.pop(event_key, None)
        state = {
            "server_object": id(server),
            "client_object": id(client) if client is not None else None,
            "closed_at": None,
            "identity_denied": False,
        }
        _gateway_connections[key] = state
    else:
        state["closed_at"] = None
    error_kind = _gateway_error_kind(getattr(server, "error", None))
    if error_kind == "identity":
        state["identity_denied"] = True
    return state


def _gateway_state(server, client=None) -> tuple[tuple[object, object], dict[str, object]] | None:
    if server is None:
        return None
    _purge_gateway_connections()
    key = _server_hook_key(server, client)
    state = _gateway_connections.get(key)
    if state is None or state.get("server_object") != id(server):
        return None
    return key, state


def _gateway_state_for_flow(flow) -> tuple[tuple[object, object], dict[str, object]] | None:
    client = getattr(flow, "client_conn", None)
    # The refusal error belongs to the client flow, while its gateway Server
    # object may already have been closed.  Correlate only to the exact client
    # id captured by a strict gateway connection, never to arbitrary traffic.
    _purge_gateway_connections()
    client_key = _hook_key_part(client, id(client) if client is not None else None)
    for key, state in _gateway_connections.items():
        if key[0] == client_key:
            return key, state
    return None


def _emit_gateway_event(
    event: str,
    *,
    server=None,
    client=None,
    flow=None,
    state_ref: tuple[tuple[object, object], dict[str, object]] | None = None,
) -> None:
    if event not in _GATEWAY_EVENT_NAMES or not _strict_mode:
        return
    if state_ref is None:
        state_ref = _gateway_state(server, client)
    if state_ref is None:
        return
    key, state = state_ref
    # A credential refusal is already represented by identity_denied.  Do not
    # turn it into a transport outcome as well.
    if state.get("identity_denied") and event in {
        "gateway_connect_failed",
        "gateway_connect_denied",
    }:
        return
    event_key = (key[0], key[1], event)
    if event_key in _gateway_event_keys:
        return
    _purge_gateway_connections()
    if len(_gateway_event_keys) >= _MAX_GATEWAY_EVENT_KEYS:
        _gateway_event_keys.pop(next(iter(_gateway_event_keys)), None)
    _gateway_event_keys[event_key] = None
    try:
        # Keep this exact and parameter-free.  The Go launch bridge accepts
        # only these five messages and must never receive gateway reason,
        # headers, address, or identity material.
        ctx.log.warn(f"upstream proxy: {event}")
    except Exception:
        pass


def _flow_error_message(flow) -> str | None:
    error = getattr(flow, "error", None)
    if isinstance(error, str):
        return error
    message = getattr(error, "msg", None)
    return message if isinstance(message, str) else None


def _gateway_connect_status(message: str | None) -> int | None:
    if not isinstance(message, str):
        return None
    match = _GATEWAY_CONNECT_REFUSAL.fullmatch(message)
    if match is None:
        return None
    try:
        status = int(match.group(1))
    except (TypeError, ValueError):
        return None
    return status if 100 <= status <= 599 else None


def _response_status(flow) -> int | None:
    response = getattr(flow, "response", None)
    status = getattr(response, "status_code", None)
    if isinstance(status, bool) or not isinstance(status, int):
        return None
    return status if 100 <= status <= 599 else None


def _read_identity(path: str) -> str:
    # Reopen on every new upstream connection; Kubernetes swaps symlinks on
    # projection updates. Never retain an fd or a last-known-good token.
    try:
        with open(path, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise IdentityError("EGRESS_IDENTITY_INVALID")
            data = handle.read(16385)
    except OSError:
        raise IdentityError("EGRESS_IDENTITY_UNAVAILABLE") from None
    if len(data) > 16384:
        raise IdentityError("EGRESS_IDENTITY_INVALID")
    try:
        token = data.decode("ascii").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token):
            raise ValueError
        parts = token.split(".")
        decoded = [base64.b64decode(part + "=" * (-len(part) % 4), altchars=b"-_", validate=True) for part in parts]
        header, payload = (json.loads(part) for part in decoded[:2])
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise ValueError
        if not isinstance(header.get("alg"), str) or header["alg"].lower() == "none" or not header["alg"] or not decoded[2]:
            raise ValueError
        now = time.time()
        exp, nbf = payload.get("exp"), payload.get("nbf", 0)
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) for value in (exp, nbf)):
            raise ValueError
        if exp <= now:
            raise IdentityError("EGRESS_IDENTITY_EXPIRED")
        if nbf > now:
            raise IdentityError("EGRESS_IDENTITY_NOT_YET_VALID")
    except IdentityError:
        raise
    except (ValueError, TypeError, UnicodeError, OverflowError):
        raise IdentityError("EGRESS_IDENTITY_INVALID") from None
    return token


def _parse_upstream(raw: str) -> tuple[str, str, int]:
    """Parse "scheme://host[:port]"; port defaults to the scheme default.

    Userinfo, query and fragment are rejected: the value may only carry an
    address. Credentials belong exclusively in UPSTREAM_PROXY_AUTH_ENV.
    """
    raw = raw.strip()
    if not raw:
        raise ValueError("value is empty")
    if "://" not in raw:
        raise ValueError("missing scheme, want http://host:port or https://host:port")
    try:
        url = urlsplit(raw)
        port = url.port
    except ValueError:
        raise ValueError("invalid proxy URL") from None
    if url.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme {url.scheme!r}, want http or https")
    if url.username is not None or url.password is not None:
        raise ValueError(
            f"userinfo is not allowed, use {UPSTREAM_PROXY_AUTH_ENV} for credentials"
        )
    host = url.hostname
    if not host:
        raise ValueError("missing host")
    if url.query or url.fragment:
        raise ValueError("query and fragment are not allowed")
    if port is None:
        port = 443 if url.scheme == "https" else 80
    elif not 1 <= port <= 65535:
        raise ValueError(f"invalid port {port}")
    if any(c in host for c in " \t\r\n/@"):
        raise ValueError(f"invalid host {host!r}")
    return url.scheme, host.lower(), port


def load(loader) -> None:
    global _via, _proxy_address, _proxy_auth, _identity_file
    global _gateway_tls_context, _strict_mode, _proxy_tls_hostname
    _via = _proxy_address = _proxy_auth = _identity_file = _gateway_tls_context = None
    _strict_mode = PUBLIC_POLICY_ENV in os.environ
    _proxy_tls_hostname = None
    _connection_identities.clear()
    _gateway_connections.clear()
    _gateway_event_keys.clear()
    raw = os.environ.get(UPSTREAM_PROXY_ENV, "").strip()
    auth = os.environ.get(UPSTREAM_PROXY_AUTH_ENV, "").strip()
    identity = os.environ.get(IDENTITY_FILE_ENV, "").strip()
    ca_file = os.environ.get(CA_FILE_ENV, "").strip()
    if not raw:
        if auth or identity or ca_file:
            raise ValueError(
                f"{UPSTREAM_PROXY_AUTH_ENV} is set but {UPSTREAM_PROXY_ENV} is empty"
            )
        return
    scheme, host, port = _parse_upstream(raw)
    _proxy_tls_hostname = host
    if identity or ca_file:
        if not identity or not ca_file or auth or scheme != "https":
            raise ValueError("file identity requires HTTPS, a gateway CA, and no inline proxy authorization")
        if getattr(ctx.options, "ssl_insecure", False):
            raise ValueError("file identity forbids ssl_insecure")
        # Dedicated trust store for the gateway. Do not change the global
        # mitmproxy target CA options or add this private CA to public trust.
        from OpenSSL import SSL
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_min_proto_version(SSL.TLS1_2_VERSION)
        context.set_verify(SSL.VERIFY_PEER, lambda connection, cert, errno, depth, valid: valid)
        context.load_verify_locations(ca_file)
        _gateway_tls_context = context
        _identity_file = identity
    if getattr(ctx.options, "connection_strategy", "lazy") != "lazy":
        raise ValueError(
            f"{UPSTREAM_PROXY_ENV} requires connection_strategy=lazy: eager "
            "connects upstream before a flow exists, so no via can be applied"
        )
    passthrough = [
        name
        for name in ("ignore_hosts", "tcp_hosts", "udp_hosts")
        if getattr(ctx.options, name, [])
    ]
    if passthrough:
        raise ValueError(
            f"{UPSTREAM_PROXY_ENV} is incompatible with {', '.join(passthrough)}: "
            "pass-through traffic cannot be chained and would bypass the proxy"
        )
    _proxy_address = (host, port)
    _via = (scheme, _proxy_address)
    _proxy_auth = auth or None
    ctx.log.info(
        f"upstream proxy: chaining enabled via {scheme}://{host}:{port}"
        + (" with Proxy-Authorization" if _proxy_auth else "")
    )


def running() -> None:
    # The Go supervisor waits for this static-config acknowledgement before
    # declaring the MITM stack ready. Script load errors alone do not stop
    # mitmdump 11.0.2. No JWT read or gateway dial belongs in readiness.
    if _identity_file and _gateway_tls_context is not None and _via is not None:
        ctx.log.info("upstream proxy: ready")


def _set_via_on_conn(conn) -> None:
    if conn is None or getattr(conn, "connected", False):
        return
    # public_policy.py has already authenticated this exact connection as an
    # administrator-approved internal direct route.  In strict mode it must
    # not be sent through the public gateway (and must not cause identity
    # lookup).  Legacy mode intentionally ignores these private attrs.
    if _strict_mode and getattr(conn, PUBLIC_DIRECT_PERMIT_ATTR, None) is not None:
        return
    conn.via = _via


def _set_via(flow: http.HTTPFlow) -> None:
    _set_via_on_conn(getattr(flow, "server_conn", None))


def _deny_strict_flow(flow: http.HTTPFlow) -> None:
    """Fail closed if public_policy.py did not leave a route permit."""

    try:
        request = flow.request
        may_stream = bool(getattr(request, "stream", False)) or (
            "content-length" not in getattr(request, "headers", {})
            and (
                "transfer-encoding" in getattr(request, "headers", {})
                or getattr(request, "http_version", "").upper().startswith("HTTP/2")
            )
        )
        if may_stream and getattr(flow, "killable", False):
            flow.kill()
        elif getattr(flow, "response", None) is None and getattr(flow, "error", None) is None:
            flow.response = http.Response.make(
                403,
                PUBLIC_PERMIT_REQUIRED,
                {"Content-Type": "text/plain"},
            )
    except Exception:
        try:
            flow.error = PUBLIC_PERMIT_REQUIRED
        except Exception:
            pass
    try:
        ctx.log.warn(f"upstream proxy: denied {PUBLIC_PERMIT_REQUIRED}")
    except Exception:
        pass


def tls_clienthello(data) -> None:
    # Anchor via on the (not yet connected) server placeholder while the client
    # TLS hello is parsed — the earliest point a server connection object
    # exists for an intercepted TLS flow.
    if _via is not None:
        _set_via_on_conn(getattr(data.context, "server", None))


def requestheaders(flow: http.HTTPFlow) -> None:
    # Fires before the server connection is opened (lazy strategy); setting via
    # here makes the connection-spec fork chain through the upstream proxy.
    if _via is not None:
        if getattr(flow, "response", None) is not None or getattr(flow, "error", None) is not None:
            return  # Preserve an earlier system/Vault rejection.
        # Includes exact-internal routes: never forward a caller/Vault proxy
        # credential as a business header, even when gateway identity is unused.
        flow.request.headers.pop("Proxy-Authorization", None)
        if _strict_mode:
            server = getattr(flow, "server_conn", None)
            if (
                getattr(server, PUBLIC_DIRECT_PERMIT_ATTR, None) is not None
            ):
                return
            if getattr(server, PUBLIC_PROXY_PERMIT_ATTR, None) is None:
                # An async policy hook may have failed or a new mitmproxy
                # connection fork may have lost its private marker.  Setting
                # ``via`` here would turn that error into a gateway bypass or
                # an unbound CONNECT, so refuse the flow before opening it.
                _deny_strict_flow(flow)
                return
        if _identity_file:
            try:
                _read_identity(_identity_file)
            except IdentityError as error:
                _log_identity_denied(error)
                # Match the system addon's mitmproxy 11.0.2 streaming guard:
                # a local response plus streaming raises NotImplementedError.
                # Unknown-length chunked/H2 bodies can start streaming later.
                unknown_length = "content-length" not in flow.request.headers
                may_stream = getattr(flow.request, "stream", False) or (unknown_length and (
                    "transfer-encoding" in flow.request.headers
                    or getattr(flow.request, "http_version", "").upper().startswith("HTTP/2")
                ))
                if may_stream:
                    if flow.killable:
                        flow.kill()
                else:
                    flow.response = http.Response.make(403, str(error), {"Content-Type": "text/plain"})
                return
        _set_via(flow)


def http_connect(flow: http.HTTPFlow) -> None:
    # Regular-mode client CONNECT: same chaining point before the upstream
    # connection is established.
    if _via is not None:
        if _strict_mode:
            server = getattr(flow, "server_conn", None)
            if getattr(server, PUBLIC_DIRECT_PERMIT_ATTR, None) is not None:
                return
            if getattr(server, PUBLIC_PROXY_PERMIT_ATTR, None) is None:
                _deny_strict_flow(flow)
                return
        _set_via(flow)


def http_connect_upstream(flow: http.HTTPFlow) -> None:
    # The CONNECT mitmproxy sends to our upstream proxy. Attach credentials.
    if _identity_file:
        # mitmproxy 11.0.2 does not honor flow.response in this hook. Validate
        # before dialing in server_connect and bind the token to that exact
        # proxy connection. The gateway must validate expiry again after TLS.
        token = _connection_identities.pop(flow.server_conn.id, None)
        if token is not None:
            flow.request.headers["Proxy-Authorization"] = "Bearer " + token
    elif _proxy_auth:
        flow.request.headers["Proxy-Authorization"] = _proxy_auth


def tls_start_server(data) -> None:
    proxy_permit = (
        _strict_mode
        and getattr(data.conn, PUBLIC_PROXY_PERMIT_ATTR, None) is not None
    )
    if (
        _gateway_tls_context is None
        or (
            not proxy_permit
            and (
                data.conn.address != _proxy_address
                or data.conn is data.context.server
            )
        )
    ):
        return
    from OpenSSL import SSL
    # This replaces only the proxy TLS context supplied by mitmproxy's
    # tlsconfig. Hostname verification happens inside the TLS handshake.
    connection = SSL.Connection(_gateway_tls_context)
    # Strict policy may replace the gateway Server.address with the freshly
    # resolved A answer immediately before this hook.  Certificate/SNI
    # identity remains the administrator-configured DNS hostname.
    hostname_value = _proxy_tls_hostname or _proxy_address[0]
    hostname = hostname_value.encode("idna")
    connection.set_tlsext_host_name(hostname)
    param = SSL._lib.SSL_get0_param(connection._ssl)
    flags = SSL._lib.X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS | SSL._lib.X509_CHECK_FLAG_NEVER_CHECK_SUBJECT
    SSL._lib.X509_VERIFY_PARAM_set_hostflags(param, flags)
    SSL._openssl_assert(SSL._lib.X509_VERIFY_PARAM_set1_host(param, hostname, len(hostname)) == 1)
    connection.set_alpn_protos([b"http/1.1"])
    connection.set_connect_state()
    data.conn.sni = hostname_value
    data.ssl_conn = connection


def tls_failed_server(data) -> None:
    """Record only a strict gateway TLS handshake failure.

    TlsFailedServerHook receives TlsData, whose ``conn`` is the gateway TLS
    connection for the HTTPS upstream-proxy layer.  Destination TLS failures
    use a different Server object and are intentionally ignored here.
    """

    server = getattr(data, "conn", None)
    client = getattr(getattr(data, "context", None), "client", None)
    state_ref = _gateway_state(server, client)
    if state_ref is None:
        if not _strict_gateway_marker(server):
            return
        state_ref = _remember_gateway_connection(
            types.SimpleNamespace(client=client), server
        )
        if state_ref is not None:
            state_ref = _gateway_state(server, client)
    _emit_gateway_event(
        "gateway_tls_failed", server=server, client=client, state_ref=state_ref
    )


def http_connect_error(flow: http.HTTPFlow) -> None:
    """Classify an upstream CONNECT response without touching the flow.

    mitmproxy 11.0.2 documents that ``flow.error`` is not guaranteed for this
    hook.  When a response is present, status 403/429 have the two dedicated
    event names; every other refusal is a generic connect denial.  A normal
    business response never enters this hook, so a business 403 cannot become
    a grant-denied event.
    """

    if not _strict_mode:
        return
    request = getattr(flow, "request", None)
    method = getattr(request, "method", None)
    if isinstance(method, bytes):
        method = method.decode("ascii", "ignore")
    if method is None or str(method).upper() != "CONNECT":
        return
    client = getattr(flow, "client_conn", None)
    server = getattr(flow, "server_conn", None)
    state_ref = _gateway_state(server, client)
    if state_ref is None:
        if not _strict_gateway_marker(server):
            return
        state_ref = _remember_gateway_connection(
            types.SimpleNamespace(client=client), server
        )
        if state_ref is not None:
            state_ref = _gateway_state(server, client)
    status = _response_status(flow)
    if status == 403:
        event = "gateway_grant_denied"
    elif status == 429:
        event = "gateway_rate_limited"
    else:
        event = "gateway_connect_denied"
    _emit_gateway_event(event, server=server, client=client, state_ref=state_ref)


def error(flow: http.HTTPFlow) -> None:
    """Suppress private transport error text and observe bounded refusals.

    For a normal request, the upstream layer's generated CONNECT flow is not
    exposed through ``http_connect_error`` in mitmproxy 11.0.2.  Instead the
    original flow receives a ResponseProtocolError and then the ``error`` hook.
    A gateway's refusal reason may echo its private Proxy-Authorization. Merely
    rewriting ``flow.error.msg`` does not change the queued protocol response.
    On pinned 11.0.2, killing the flow makes ``check_killed`` suppress that
    response. Do so independently of bounded event parsing/state retention.
    """

    if not _strict_mode:
        return
    server = getattr(flow, "server_conn", None)
    if not _strict_proxy_flow_marker(server):
        return
    status = _gateway_connect_status(_flow_error_message(flow))
    if flow.killable:
        flow.kill()
    if status is None:
        return
    state_ref = _gateway_state_for_flow(flow)
    if state_ref is None:
        return
    if status == 403:
        event = "gateway_grant_denied"
    elif status == 429:
        event = "gateway_rate_limited"
    else:
        event = "gateway_connect_denied"
    _emit_gateway_event(event, flow=flow, state_ref=state_ref)


def _strict_proxy_flow_marker(server) -> bool:
    """Recognize the original strict public flow (not a direct/internal one)."""

    if not _strict_mode or server is None or _via is None:
        return False
    if getattr(server, PUBLIC_PROXY_PERMIT_ATTR, None) is None:
        return False
    if getattr(server, PUBLIC_DIRECT_PERMIT_ATTR, None) is not None:
        return False
    if getattr(server, "transport_protocol", "tcp") != "tcp":
        return False
    try:
        return getattr(server, "via", None) == _via
    except Exception:
        return False


def server_disconnected(data) -> None:
    server = getattr(data, "server", None)
    client = getattr(data, "client", None)
    state_ref = _gateway_state(server, client)
    if state_ref is not None:
        state_ref[1]["closed_at"] = time.monotonic()
    _connection_identities.pop(getattr(server, "id", None), None)
    _purge_gateway_connections()


def server_connect_error(data) -> None:
    server = getattr(data, "server", None)
    client = getattr(data, "client", None)
    state_ref = _gateway_state(server, client)
    if state_ref is not None:
        kind = _gateway_error_kind(getattr(server, "error", None))
        if kind == "identity":
            state_ref[1]["identity_denied"] = True
        elif kind == "denied":
            _emit_gateway_event(
                "gateway_connect_denied",
                server=server,
                client=client,
                state_ref=state_ref,
            )
        else:
            _emit_gateway_event(
                "gateway_connect_failed",
                server=server,
                client=client,
                state_ref=state_ref,
            )
        state_ref[1]["closed_at"] = time.monotonic()
    _connection_identities.pop(getattr(server, "id", None), None)
    _purge_gateway_connections()


def client_disconnected(client) -> None:
    if not _strict_mode:
        return
    _purge_gateway_connections()
    client_key = _hook_key_part(client, id(client) if client is not None else None)
    removed: set[tuple[object, object]] = set()
    for key in list(_gateway_connections):
        if key[0] == client_key:
            _gateway_connections.pop(key, None)
            removed.add(key)
    for event_key in list(_gateway_event_keys):
        if event_key[:2] in removed:
            _gateway_event_keys.pop(event_key, None)


def server_connect(data) -> None:
    """Refuse any direct dial while chaining is enabled (fail closed).

    Chained flows never reach this hook for the real destination: the
    upstream-proxy layer dials the proxy itself, so the only legitimate
    connection here is that tunnel. Everything else — TLS pass-through, UDP —
    would silently bypass the proxy, so it is refused.
    """
    if _strict_mode:
        server = data.server
        # Capture the valid gateway marker before public_policy.py's later
        # server_connect_error/server_disconnected hook removes it.  This is
        # also the point at which the identity decision is bound to this exact
        # client/server pair.
        gateway_state = _remember_gateway_connection(data, server)
        # public_policy.py runs first and may have rejected this exact Server
        # object (for example after a DNS timeout, SNI mismatch, or gateway
        # binding failure). Preserve that stable denial; no later marker or
        # credential branch may turn it into a different error or authorize a
        # dial.
        if getattr(server, "error", None):
            return
        if getattr(server, PUBLIC_DIRECT_PERMIT_ATTR, None) is not None:
            # Internal administrator-owned direct destinations intentionally
            # bypass gateway identity reads.  The public policy hook has
            # already matched the exact client/address permit immediately
            # before this hook.
            return
        if getattr(server, PUBLIC_PROXY_PERMIT_ATTR, None) is not None:
            # public_policy.py resolved and bound this gateway connection.  A
            # missing via would indicate an addon ordering/configuration hole,
            # so do not let the marker authorize a direct dial in that case.
            marker_host = getattr(server, PUBLIC_PROXY_HOST_ATTR, None)
            if (
                _via is None
                or _proxy_address is None
                or not isinstance(marker_host, str)
                or marker_host.rstrip(".").lower()
                != str(_proxy_address[0]).rstrip(".").lower()
                or getattr(server, "transport_protocol", "tcp") != "tcp"
            ):
                server.error = PUBLIC_PERMIT_REQUIRED
                return
            if _identity_file:
                try:
                    _connection_identities[server.id] = _read_identity(_identity_file)
                except IdentityError as error:
                    _log_identity_denied(error)
                    if gateway_state is not None:
                        gateway_state["identity_denied"] = True
                    server.error = str(error)
            return
        server.error = PUBLIC_PERMIT_REQUIRED
        return

    if _via is None:
        return
    server = data.server
    address = getattr(server, "address", None)
    # A hook exception is logged by mitmproxy but does not stop the dial, so the
    # comparison must be total: anything we cannot positively identify as the
    # proxy's own tunnel connection is refused.
    try:
        is_proxy_conn = (
            getattr(server, "transport_protocol", "tcp") == "tcp"
            and address is not None
            and len(address) >= 2
            and str(address[0]).lower() == _proxy_address[0]
            and int(address[1]) == _proxy_address[1]
        )
    except (TypeError, ValueError):
        is_proxy_conn = False
    if not is_proxy_conn:
        server.error = (
            "upstream proxy required: direct egress dial refused "
            f"({getattr(server, 'transport_protocol', 'tcp')} to {address})"
        )
    elif _identity_file:
        try:
            _connection_identities[server.id] = _read_identity(_identity_file)
        except IdentityError as error:
            _log_identity_denied(error)
            server.error = str(error)
