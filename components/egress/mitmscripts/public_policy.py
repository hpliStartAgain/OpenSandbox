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

"""Strict transparent egress destination policy.

This addon is intentionally small and self-contained.  It is loaded after the
native system addon and before ``upstream_proxy.py``.  When the policy
environment variable is absent this module is inert, preserving the legacy
transparent proxy behavior.

In strict mode all destination decisions are made from two independently
validated pieces of information:

* the original transparent destination (the address captured by mitmproxy
  from ``SO_ORIGINAL_DST``), and
* a fresh A-only answer obtained over TCP from the pinned local DNS proxy.

The addon never asks libc to resolve a workload or gateway hostname.  It also
does not cache DNS answers.  A short-lived permit is only an authorization
hint for the corresponding mitmproxy connection object; the server hook still
checks the exact client/address key immediately before the socket dial.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import secrets
import socket
import struct
import time
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from mitmproxy import ctx, http


PUBLIC_POLICY_ENV = "OPENSANDBOX_EGRESS_PUBLIC_POLICY"
UPSTREAM_PROXY_ENV = "OPENSANDBOX_EGRESS_UPSTREAM_PROXY"

# The local DNS proxy is a fixed, private control-plane endpoint.  Do not
# replace this with a hostname or with the process resolver.
DNS_CONNECT_HOST = "127.0.0.1"
DNS_CONNECT_PORT = 15353
DNS_QUERY_TIMEOUT = 0.75
DNS_MAX_MESSAGE = 16 * 1024
DNS_MAX_RECORDS = 128
DNS_MAX_NAME_JUMPS = 32

PERMIT_TTL = 5.0
MAX_DNS_SERVERS = 8
MAX_INTERNAL_TARGETS = 128
MAX_TARGET_IPS = 32
MAX_TARGET_PORTS = 32
MAX_PERMITS = 4096
RESERVED_GATEWAY_PORTS = frozenset({53, 353, 380, 381, 15353, 18080, 18081})

# Link-local metadata endpoints are not safe administrator exceptions.  Some
# platform VIPs are reported as ``is_global`` by ipaddress, so keep an
# explicit deny set in addition to the generic special-range checks.
METADATA_IPV4 = frozenset(
    {
        "100.100.100.200",  # Alibaba cloud metadata
        "168.63.129.16",  # Azure platform virtual IP
        "169.254.169.254",  # AWS/GCP/OCI metadata
    }
)

# These names are intentionally private.  They are the only interface between
# this addon and upstream_proxy.py.  The latter must honor them only while the
# strict policy environment is present.
SERVER_PERMIT_ATTR = "_opensandbox_public_policy_permit"
SERVER_HANDSHAKE_ATTR = "_opensandbox_public_policy_handshake"
SERVER_ROUTE_ATTR = "_opensandbox_public_policy_route"
SERVER_PROXY_HOST_ATTR = "_opensandbox_public_policy_proxy_host"
SERVER_PROXY_PERMIT_ATTR = "_opensandbox_public_policy_proxy_permit"
SERVER_DIRECT_PERMIT_ATTR = "_opensandbox_public_policy_direct_permit"

FLOW_PERMIT_KEY = "opensandbox_public_policy_permit"
FLOW_REJECTION_KEY = "opensandbox_public_policy_rejected"

ROUTE_PUBLIC_PROXY = "public-proxy"
ROUTE_INTERNAL_DIRECT = "internal-direct"


class PolicyError(ValueError):
    """An error whose string is a stable, non-sensitive denial code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class InternalTarget:
    __slots__ = ("host", "ips", "ports")

    def __init__(self, host: str, ips: frozenset[str], ports: frozenset[int]) -> None:
        self.host = host
        self.ips = ips
        self.ports = ports


class PublicPolicy:
    __slots__ = ("version", "dns_servers", "internal_targets")

    def __init__(
        self, version: int, dns_servers: tuple[str, ...], internal_targets: dict[str, InternalTarget]
    ) -> None:
        self.version = version
        self.dns_servers = dns_servers
        self.internal_targets = internal_targets


class GatewaySpec:
    __slots__ = ("scheme", "host", "port")

    def __init__(self, scheme: str, host: str, port: int) -> None:
        self.scheme = scheme
        self.host = host
        self.port = port


class Permit:
    __slots__ = ("client_id", "route", "host", "port", "original", "answers", "expires_at")

    def __init__(
        self,
        client_id: str,
        route: str,
        host: str,
        port: int,
        original: tuple[str, int],
        answers: tuple[str, ...],
        expires_at: float,
    ) -> None:
        self.client_id = client_id
        self.route = route
        self.host = host
        self.port = port
        self.original = original
        self.answers = answers
        self.expires_at = expires_at


# A binding is created at ClientHello time and checked again at every
# requestheaders event. It is deliberately separate from Permit so that a TLS
# SNI cannot be used as a substitute for the per-request Host header. The
# binding belongs to the lifetime of this client/server TLS connection rather
# than the short permit window: HTTP keep-alive, H2, WSS, and SSE streams may
# legitimately outlive five seconds. Every request still performs a fresh DNS
# lookup and obtains its own short-lived dial permit.
class HandshakeBinding:
    __slots__ = ("client_id", "route", "host", "port", "original", "answers", "expires_at")

    def __init__(
        self,
        client_id: str,
        route: str,
        host: str,
        port: int,
        original: tuple[str, int],
        answers: tuple[str, ...],
        expires_at: float,
    ) -> None:
        self.client_id = client_id
        self.route = route
        self.host = host
        self.port = port
        self.original = original
        self.answers = answers
        self.expires_at = expires_at


_policy: PublicPolicy | None = None
_strict_configured = False
_strict_config_error: str | None = None
_gateway: GatewaySpec | None = None

# The key includes client.id and the exact server address.  Values are lists
# because two HTTP/2 streams may legitimately establish equivalent connections
# concurrently.  All entries are bounded and expire quickly.
_permits: dict[tuple[str, tuple[str, int]], list[Permit]] = defaultdict(list)
_server_permits: dict[tuple[str, str], Permit | HandshakeBinding] = {}
_proxy_permits: dict[tuple[str, tuple[str, int]], list[Permit]] = defaultdict(list)


def _clear_state() -> None:
    _permits.clear()
    _server_permits.clear()
    _proxy_permits.clear()


def _now() -> float:
    return time.monotonic()


def _stable_code(error: BaseException, fallback: str) -> str:
    if isinstance(error, PolicyError):
        return error.code
    return fallback


def _normalize_fqdn(value: Any, *, code: str = "EGRESS_PUBLIC_POLICY_HOST_INVALID") -> str:
    """Return a strict lower-case ASCII hostname without a root dot."""

    if not isinstance(value, str) or not value or len(value) > 253:
        raise PolicyError(code)
    if value.endswith("."):
        value = value[:-1]
    if not value or value.endswith(".") or any(ord(c) < 0x21 or ord(c) == 0x7F for c in value):
        raise PolicyError(code)
    if any(c in value for c in "/?#@\\[]"):
        raise PolicyError(code)
    try:
        # IDNA is performed label-by-label so that a Unicode label cannot
        # smuggle separators or an IPv4-looking representation.
        labels = value.split(".")
        if any(not label for label in labels):
            raise PolicyError(code)
        encoded = [label.encode("idna").decode("ascii").lower() for label in labels]
    except (UnicodeError, LookupError):
        raise PolicyError(code) from None
    host = ".".join(encoded)
    if len(host) > 253:
        raise PolicyError(code)
    for label in encoded:
        if not 1 <= len(label) <= 63:
            raise PolicyError(code)
        if not (label[0].isalnum() and label[-1].isalnum()):
            raise PolicyError(code)
        if any(not (char.isalnum() or char == "-") for char in label):
            raise PolicyError(code)
    try:
        ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        pass
    else:
        raise PolicyError(code)
    return host


def normalize_fqdn(value: Any) -> str:
    """Public test/helper entry point for hostname normalization."""

    return _normalize_fqdn(value)


def _parse_ipv4(value: Any, code: str = "EGRESS_PUBLIC_POLICY_IP_INVALID") -> str:
    if not isinstance(value, str):
        raise PolicyError(code)
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise PolicyError(code) from None
    if (
        str(address) in METADATA_IPV4
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
    ):
        raise PolicyError(code)
    # IPv4Address.__str__ also rejects alternate textual spellings for the
    # canonical value used in exact-address maps.
    return str(address)


def _is_public_ipv4(value: str) -> bool:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    # ipaddress.is_global alone treats multicast specially on some Python
    # versions.  Public HTTP egress is unicast-only and excludes every special
    # range that can represent loopback, metadata, link-local, or a reserved
    # route.
    return bool(
        str(address) not in METADATA_IPV4
        and
        address.is_global
        and not address.is_private
        and not address.is_reserved
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_unspecified
        and not address.is_multicast
    )


def _is_usable_gateway_ipv4(value: str) -> bool:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    # A configured gateway may be private, but must not be a local, metadata,
    # multicast, or otherwise non-routable special endpoint.
    return bool(
        str(address) not in METADATA_IPV4
        and
        not address.is_unspecified
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
    )


def _parse_port(value: Any, code: str = "EGRESS_PUBLIC_POLICY_PORT_INVALID") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise PolicyError(code)
    return value


def parse_policy(raw: str | bytes) -> PublicPolicy:
    """Parse and bound the strict policy JSON."""

    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise PolicyError("EGRESS_PUBLIC_POLICY_INVALID") from None
    if not isinstance(raw, str):
        raise PolicyError("EGRESS_PUBLIC_POLICY_INVALID")
    try:
        raw_size = len(raw.encode("utf-8", "surrogatepass"))
    except UnicodeEncodeError:
        raise PolicyError("EGRESS_PUBLIC_POLICY_INVALID") from None
    if raw_size > 32 * 1024:
        raise PolicyError("EGRESS_PUBLIC_POLICY_INVALID")
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError, UnicodeError):
        raise PolicyError("EGRESS_PUBLIC_POLICY_INVALID") from None
    if not isinstance(payload, dict) or set(payload) != {"version", "dns_servers", "internal_targets"}:
        raise PolicyError("EGRESS_PUBLIC_POLICY_INVALID")

    version = payload.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise PolicyError("EGRESS_PUBLIC_POLICY_VERSION_UNSUPPORTED")

    dns_servers_raw = payload.get("dns_servers")
    if (
        not isinstance(dns_servers_raw, list)
        or not dns_servers_raw
        or len(dns_servers_raw) > MAX_DNS_SERVERS
    ):
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_SERVERS_INVALID")
    dns_servers: list[str] = []
    for item in dns_servers_raw:
        address = _parse_ipv4(item, "EGRESS_PUBLIC_POLICY_DNS_SERVERS_INVALID")
        if address in dns_servers:
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_SERVERS_INVALID")
        dns_servers.append(address)

    targets_raw = payload.get("internal_targets")
    if not isinstance(targets_raw, list) or len(targets_raw) > MAX_INTERNAL_TARGETS:
        raise PolicyError("EGRESS_PUBLIC_POLICY_INTERNAL_TARGETS_INVALID")
    targets: dict[str, InternalTarget] = {}
    for item in targets_raw:
        if not isinstance(item, dict) or set(item) != {"host", "ips", "ports"}:
            raise PolicyError("EGRESS_PUBLIC_POLICY_INTERNAL_TARGETS_INVALID")
        host = _normalize_fqdn(
            item.get("host"), code="EGRESS_PUBLIC_POLICY_INTERNAL_HOST_INVALID"
        )
        if host in targets:
            raise PolicyError("EGRESS_PUBLIC_POLICY_INTERNAL_TARGETS_INVALID")
        ips_raw = item.get("ips")
        ports_raw = item.get("ports")
        if (
            not isinstance(ips_raw, list)
            or not ips_raw
            or len(ips_raw) > MAX_TARGET_IPS
            or not isinstance(ports_raw, list)
            or not ports_raw
            or len(ports_raw) > MAX_TARGET_PORTS
        ):
            raise PolicyError("EGRESS_PUBLIC_POLICY_INTERNAL_TARGETS_INVALID")
        ips = frozenset(
            _parse_ipv4(ip, "EGRESS_PUBLIC_POLICY_INTERNAL_IP_INVALID") for ip in ips_raw
        )
        if any(ip in METADATA_IPV4 for ip in ips):
            raise PolicyError("EGRESS_PUBLIC_POLICY_INTERNAL_IP_INVALID")
        ports = frozenset(
            _parse_port(port, "EGRESS_PUBLIC_POLICY_INTERNAL_PORT_INVALID")
            for port in ports_raw
        )
        if any(port in RESERVED_GATEWAY_PORTS for port in ports):
            raise PolicyError("EGRESS_PUBLIC_POLICY_INTERNAL_PORT_INVALID")
        if len(ips) != len(ips_raw) or len(ports) != len(ports_raw):
            raise PolicyError("EGRESS_PUBLIC_POLICY_INTERNAL_TARGETS_INVALID")
        targets[host] = InternalTarget(host, ips, ports)

    return PublicPolicy(1, tuple(dns_servers), targets)


def _parse_gateway(raw: str | None) -> GatewaySpec | None:
    if raw is None or not raw.strip():
        return None
    try:
        parsed = urlsplit(raw.strip())
        port = parsed.port
    except ValueError:
        raise PolicyError("EGRESS_PUBLIC_POLICY_GATEWAY_INVALID") from None
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        raise PolicyError("EGRESS_PUBLIC_POLICY_GATEWAY_INVALID")
    if parsed.path or parsed.query or parsed.fragment or not parsed.hostname:
        raise PolicyError("EGRESS_PUBLIC_POLICY_GATEWAY_INVALID")
    host = _normalize_fqdn(
        parsed.hostname, code="EGRESS_PUBLIC_POLICY_GATEWAY_INVALID"
    )
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    port = _parse_port(port, "EGRESS_PUBLIC_POLICY_GATEWAY_INVALID")
    if port in RESERVED_GATEWAY_PORTS:
        raise PolicyError("EGRESS_PUBLIC_POLICY_GATEWAY_PORT_INVALID")
    return GatewaySpec(parsed.scheme, host, port)


def load(loader) -> None:
    """Load policy state; invalid strict configuration remains fail-closed."""

    global _policy, _strict_configured, _strict_config_error, _gateway
    _policy = None
    _strict_configured = PUBLIC_POLICY_ENV in os.environ
    _strict_config_error = None
    _gateway = None
    _clear_state()
    if not _strict_configured:
        return
    raw = os.environ.get(PUBLIC_POLICY_ENV)
    try:
        if raw is None:
            raise PolicyError("EGRESS_PUBLIC_POLICY_INVALID")
        _policy = parse_policy(raw)
        _gateway = _parse_gateway(os.environ.get(UPSTREAM_PROXY_ENV))
        if _gateway is not None and _gateway.host in _policy.internal_targets:
            raise PolicyError("EGRESS_PUBLIC_POLICY_INTERNAL_GATEWAY_CONFLICT")
    except PolicyError as error:
        _strict_config_error = error.code
        raise
    except Exception:
        _strict_config_error = "EGRESS_PUBLIC_POLICY_INVALID"
        raise ValueError(_strict_config_error) from None


def running() -> None:
    if _strict_configured and _policy is not None and _strict_config_error is None:
        ctx.log.info("public policy: ready")


def _client_id(value: Any) -> str:
    client_id = getattr(value, "id", None)
    return client_id if isinstance(client_id, str) and client_id else ""


def _address(value: Any) -> tuple[str, int] | None:
    if not isinstance(value, (tuple, list)) or len(value) < 2:
        return None
    host, port = value[0], value[1]
    if not isinstance(host, str) or isinstance(port, bool) or not isinstance(port, int):
        return None
    try:
        ip = str(ipaddress.IPv4Address(host))
    except ipaddress.AddressValueError:
        ip = host.lower()
    if not 1 <= port <= 65535:
        return None
    return ip, port


def _exact_key(client_id: str, address: Any) -> tuple[str, tuple[str, int]] | None:
    normalized = _address(address)
    if not client_id or normalized is None:
        return None
    return client_id, normalized


def _purge() -> None:
    now = _now()
    for key in list(_permits):
        values = [item for item in _permits[key] if item.expires_at > now]
        if values:
            _permits[key] = values
        else:
            _permits.pop(key, None)
    for key in list(_proxy_permits):
        values = [item for item in _proxy_permits[key] if item.expires_at > now]
        if values:
            _proxy_permits[key] = values
        else:
            _proxy_permits.pop(key, None)
    for key, value in list(_server_permits.items()):
        if value.expires_at <= now:
            _server_permits.pop(key, None)
    if len(_server_permits) > MAX_PERMITS:
        # Expiry is normally enough; this cap is a final guard against a
        # malicious client generating many connection IDs.
        for key in list(_server_permits)[: len(_server_permits) - MAX_PERMITS]:
            _server_permits.pop(key, None)


def _store_permit(permit: Permit, *addresses: Any) -> None:
    _purge()
    unique: set[tuple[str, tuple[str, int]]] = set()
    for address in addresses:
        key = _exact_key(permit.client_id, address)
        if key is None or key in unique:
            continue
        unique.add(key)
        values = _permits[key]
        values.append(permit)
        if len(values) > 8:
            del values[:-8]
    # Bounded total map.  Drop the oldest insertion keys if the cap is hit;
    # permits are only hints and a new request can issue another one.
    while len(_permits) > MAX_PERMITS:
        _permits.pop(next(iter(_permits)), None)


def _store_proxy_permit(permit: Permit) -> None:
    if _gateway is None:
        return
    key = (permit.client_id, (_gateway.host, _gateway.port))
    values = _proxy_permits[key]
    values.append(permit)
    if len(values) > 8:
        del values[:-8]
    while len(_proxy_permits) > MAX_PERMITS:
        _proxy_permits.pop(next(iter(_proxy_permits)), None)


def _lookup_permit(client_id: str, address: Any, route: str | None = None) -> Permit | None:
    key = _exact_key(client_id, address)
    if key is None:
        return None
    _purge()
    values = _permits.get(key, [])
    for permit in reversed(values):
        if permit.expires_at > _now() and (route is None or permit.route == route):
            return permit
    return None


def _pop_proxy_permit(client_id: str, address: Any) -> Permit | None:
    if _gateway is None:
        return None
    normalized = _address(address)
    if not client_id or normalized is None:
        return None
    # The configured DNS address is the primary key.  If the parent resolver
    # has already rewritten the object to an answer IP, a matching answer key
    # is accepted only after a fresh gateway lookup below.
    keys = [(client_id, (_gateway.host, _gateway.port))]
    if normalized[1] == _gateway.port:
        keys.append((client_id, normalized))
    _purge()
    for key in keys:
        values = _proxy_permits.get(key)
        if not values:
            continue
        while values:
            permit = values.pop(0)
            if permit.expires_at > _now():
                if not values:
                    _proxy_permits.pop(key, None)
                return permit
        _proxy_permits.pop(key, None)
    return None


def _server_marker(server: Any, attr: str, value: Any) -> None:
    try:
        setattr(server, attr, value)
    except Exception:
        # The connection object is expected to allow private attrs.  If a
        # future mitmproxy object does not, the map lookup in server_connect
        # still fails closed rather than silently authorizing a dial.
        pass


def _deny_server(server: Any, code: str) -> None:
    try:
        server.error = code
    except Exception:
        pass
    try:
        ctx.log.warn(f"public policy: denied {code}")
    except Exception:
        pass


def _log_route(route: str) -> None:
    # Keep route observability deliberately bounded: this records the policy
    # decision only, never the requested hostname, IP, path, or credentials.
    message = {
        ROUTE_PUBLIC_PROXY: "public policy: route public",
        ROUTE_INTERNAL_DIRECT: "public policy: route internal",
    }.get(route)
    if message is None:
        return
    try:
        ctx.log.info(message)
    except Exception:
        pass


def _flow_has_terminal_result(flow: Any) -> bool:
    # system.py is intentionally first.  Never overwrite its local Vault
    # response/error, including a streaming rejection.
    return getattr(flow, "response", None) is not None or getattr(flow, "error", None) is not None


def _deny_flow(flow: Any, code: str) -> None:
    if _flow_has_terminal_result(flow):
        return
    try:
        metadata = flow.metadata
        metadata[FLOW_REJECTION_KEY] = code
    except Exception:
        pass
    try:
        request = flow.request
        may_stream = bool(getattr(request, "stream", False)) or (
            "content-length" not in getattr(request, "headers", {})
            and (
                "transfer-encoding" in getattr(request, "headers", {})
                or str(getattr(request, "http_version", "")).upper().startswith("HTTP/2")
            )
        )
        if may_stream and getattr(flow, "killable", False):
            flow.kill()
        else:
            flow.response = http.Response.make(
                403, code.encode("ascii"), {"Content-Type": "text/plain"}
            )
    except Exception:
        # Hook errors must never turn into a direct dial.  Keep a flow-level
        # error marker where possible; upstream_proxy.py checks it in strict
        # mode before applying ``via``.
        try:
            flow.error = code
        except Exception:
            pass
    try:
        ctx.log.warn(f"public policy: denied {code}")
    except Exception:
        pass


def _header_values(headers: Any, name: str) -> list[str]:
    values: Any = None
    try:
        values = headers.get_all(name)
    except (AttributeError, TypeError):
        values = None
    if values is None or (not values and hasattr(headers, "items")):
        # The real mitmproxy Headers object is case-insensitive, while the
        # tiny mapping doubles used by tests and future integrations may not
        # be. Treat header names case-insensitively in either case.
        found: list[Any] = []
        try:
            for key, value in headers.items():
                if str(key).lower() != name.lower():
                    continue
                if isinstance(value, (list, tuple)):
                    found.extend(value)
                else:
                    found.append(value)
        except (AttributeError, TypeError, ValueError):
            found = []
        if found:
            values = found
    if values is None:
        try:
            value = headers.get(name)
        except (AttributeError, TypeError):
            value = None
        values = [] if value is None else [value]
    if isinstance(values, str):
        values = [values]
    return [value if isinstance(value, str) else str(value) for value in values]


def _parse_authority(value: Any, *, default_port: int | None = None) -> tuple[str, int | None]:
    if not isinstance(value, str) or not value or len(value) > 255:
        raise PolicyError("EGRESS_PUBLIC_POLICY_AUTHORITY_INVALID")
    if value != value.strip() or any(ord(c) < 0x21 or ord(c) == 0x7F for c in value):
        raise PolicyError("EGRESS_PUBLIC_POLICY_AUTHORITY_INVALID")
    if any(char in value for char in "/?#@\\[]"):
        raise PolicyError("EGRESS_PUBLIC_POLICY_AUTHORITY_INVALID")
    if value.count(":") > 1:
        raise PolicyError("EGRESS_PUBLIC_POLICY_AUTHORITY_INVALID")
    host = value
    explicit_port: int | None = None
    if ":" in value:
        host, raw_port = value.rsplit(":", 1)
        if not raw_port.isdigit():
            raise PolicyError("EGRESS_PUBLIC_POLICY_AUTHORITY_INVALID")
        try:
            explicit_port = _parse_port(
                int(raw_port), "EGRESS_PUBLIC_POLICY_AUTHORITY_INVALID"
            )
        except (TypeError, ValueError, OverflowError):
            raise PolicyError("EGRESS_PUBLIC_POLICY_AUTHORITY_INVALID") from None
    host = _normalize_fqdn(host, code="EGRESS_PUBLIC_POLICY_HOST_INVALID")
    return host, explicit_port if explicit_port is not None else default_port


def _request_authority(request: Any) -> tuple[str, int | None]:
    headers = getattr(request, "headers", {})
    host_values = _header_values(headers, "host")
    authority = getattr(request, "authority", "")
    is_h2 = bool(getattr(request, "is_http2", False) or getattr(request, "is_http3", False))
    if is_h2 and authority:
        parsed_authority = _parse_authority(authority)
        if len(host_values) > 1:
            raise PolicyError("EGRESS_PUBLIC_POLICY_AUTHORITY_INVALID")
        if host_values:
            parsed_host = _parse_authority(host_values[0])
            if parsed_host != parsed_authority:
                raise PolicyError("EGRESS_PUBLIC_POLICY_AUTHORITY_INVALID")
        return parsed_authority
    if len(host_values) != 1:
        # Absolute-form HTTP/1 requests can carry authority without Host.  It
        # is still parsed strictly and must agree with any Host field.
        if authority and not host_values:
            return _parse_authority(authority)
        raise PolicyError("EGRESS_PUBLIC_POLICY_AUTHORITY_INVALID")
    parsed_host = _parse_authority(host_values[0])
    if authority:
        parsed_authority = _parse_authority(authority)
        if parsed_authority != parsed_host:
            raise PolicyError("EGRESS_PUBLIC_POLICY_AUTHORITY_INVALID")
    return parsed_host


def _original_address(server: Any) -> tuple[str, int]:
    address = _address(getattr(server, "address", None))
    if address is None:
        raise PolicyError("EGRESS_PUBLIC_POLICY_ORIGINAL_DEST_INVALID")
    try:
        ip = str(ipaddress.IPv4Address(address[0]))
    except ipaddress.AddressValueError:
        raise PolicyError("EGRESS_PUBLIC_POLICY_ORIGINAL_DEST_INVALID") from None
    return ip, address[1]


def _choose_route(host: str, original: tuple[str, int], answers: tuple[str, ...]) -> str:
    if _policy is None:
        raise PolicyError("EGRESS_PUBLIC_POLICY_INVALID")
    target = _policy.internal_targets.get(host)
    if target is not None:
        if original[0] in target.ips and original[1] in target.ports:
            if original[0] not in answers:
                raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_BINDING_FAILED")
            return ROUTE_INTERNAL_DIRECT
        # An administrator-listed internal name is never allowed to fall
        # through to the public route when its exact IP/port binding fails.
        # Otherwise a DNS or Host change could turn an intended direct-only
        # exception into an unreviewed public gateway request.
        raise PolicyError("EGRESS_PUBLIC_POLICY_INTERNAL_BINDING_FAILED")
    if original[1] != 443:
        raise PolicyError("EGRESS_PUBLIC_POLICY_PUBLIC_PORT_DENIED")
    if not _is_public_ipv4(original[0]):
        raise PolicyError("EGRESS_PUBLIC_POLICY_PUBLIC_ADDRESS_DENIED")
    if original[0] not in answers:
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_BINDING_FAILED")
    return ROUTE_PUBLIC_PROXY


def _new_permit(
    client_id: str,
    route: str,
    host: str,
    original: tuple[str, int],
    answers: tuple[str, ...],
) -> Permit:
    if route == ROUTE_PUBLIC_PROXY and _gateway is None:
        raise PolicyError("EGRESS_PUBLIC_POLICY_GATEWAY_REQUIRED")
    return Permit(
        client_id=client_id,
        route=route,
        host=host,
        port=original[1],
        original=original,
        answers=answers,
        expires_at=_now() + PERMIT_TTL,
    )


def _attach_route(server: Any, permit: Permit | HandshakeBinding) -> None:
    _server_marker(server, SERVER_PERMIT_ATTR, permit)
    _server_marker(server, SERVER_ROUTE_ATTR, permit.route)
    if permit.route == ROUTE_PUBLIC_PROXY:
        _server_marker(server, SERVER_PROXY_PERMIT_ATTR, permit)
        _server_marker(server, SERVER_DIRECT_PERMIT_ATTR, None)
    else:
        _server_marker(server, SERVER_DIRECT_PERMIT_ATTR, permit)
        _server_marker(server, SERVER_PROXY_PERMIT_ATTR, None)


async def _open_dns_connection() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a TCP socket to the numeric local DNS endpoint without getaddrinfo."""

    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(
            loop.sock_connect(sock, (DNS_CONNECT_HOST, DNS_CONNECT_PORT)),
            DNS_QUERY_TIMEOUT,
        )
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(sock=sock), DNS_QUERY_TIMEOUT
        )
        return reader, writer
    except BaseException:
        sock.close()
        raise


def _encode_dns_name(host: str) -> bytes:
    labels = host.split(".")
    try:
        return b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\x00"
    except (UnicodeError, ValueError, OverflowError):
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_QUERY_INVALID") from None


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode one DNS name with bounded compression-pointer traversal."""

    if not 0 <= offset < len(packet):
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
    labels: list[str] = []
    current = offset
    consumed: int | None = None
    pointers: set[int] = set()
    jumps = 0
    total = 0
    while True:
        if current >= len(packet):
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
        length = packet[current]
        if length == 0:
            if consumed is None:
                consumed = current + 1
            break
        if (length & 0xC0) == 0xC0:
            if current + 1 >= len(packet):
                raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
            pointer = ((length & 0x3F) << 8) | packet[current + 1]
            if pointer >= len(packet) or pointer in pointers:
                raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
            pointers.add(pointer)
            jumps += 1
            if jumps > DNS_MAX_NAME_JUMPS:
                raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
            if consumed is None:
                consumed = current + 2
            current = pointer
            continue
        if length & 0xC0:
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
        if length > 63 or current + 1 + length > len(packet):
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
        raw_label = packet[current + 1 : current + 1 + length]
        try:
            label = raw_label.decode("ascii").lower()
        except UnicodeDecodeError:
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID") from None
        if not label or any(not (char.isalnum() or char == "-") for char in label):
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
        if label[0] == "-" or label[-1] == "-":
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
        total += length + 1
        if total > 253:
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
        labels.append(label)
        current += 1 + length
    if consumed is None:
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
    return ".".join(labels), consumed


def _skip_question(packet: bytes, offset: int) -> tuple[str, int, int, int]:
    name, offset = _read_name(packet, offset)
    if offset + 4 > len(packet):
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
    qtype, qclass = struct.unpack_from("!HH", packet, offset)
    return name, offset + 4, qtype, qclass


def _read_records(
    packet: bytes, offset: int, count: int
) -> tuple[int, dict[str, set[str]], dict[str, set[str]]]:
    if count > DNS_MAX_RECORDS:
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
    cname: dict[str, set[str]] = defaultdict(set)
    addresses: dict[str, set[str]] = defaultdict(set)
    for _ in range(count):
        owner, offset = _read_name(packet, offset)
        if offset + 10 > len(packet):
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
        rtype, rclass, _ttl, rdlength = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        end = offset + rdlength
        if end > len(packet):
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
        if rtype == 1 and rclass == 1:
            if rdlength != 4:
                raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
            addresses[owner].add(str(ipaddress.IPv4Address(packet[offset:end])))
        elif rtype == 5 and rclass == 1:
            target, consumed = _read_name(packet, offset)
            if consumed != end:
                raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
            try:
                target = _normalize_fqdn(target, code="EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
            except PolicyError:
                raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID") from None
            cname[owner].add(target)
        offset = end
    return offset, dict(addresses), dict(cname)


def parse_dns_response(packet: bytes, query_id: int, query_host: str) -> tuple[str, ...]:
    """Validate a DNS response and return A records on the queried CNAME chain."""

    if not isinstance(packet, bytes) or not 12 <= len(packet) <= DNS_MAX_MESSAGE:
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
    try:
        response_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
            "!HHHHHH", packet, 0
        )
    except struct.error:
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID") from None
    if (
        response_id != query_id
        or not (flags & 0x8000)
        or (flags >> 11) & 0xF
        or flags & 0x0070  # DNS Z/reserved bits
        or flags & 0xF
    ):
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
    if flags & 0x0200:  # truncated responses are not accepted over this channel
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
    if qdcount != 1 or any(count > DNS_MAX_RECORDS for count in (ancount, nscount, arcount)):
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
    expected = _normalize_fqdn(query_host, code="EGRESS_PUBLIC_POLICY_DNS_QUERY_INVALID")
    question, offset, qtype, qclass = _skip_question(packet, 12)
    if question != expected or qtype != 1 or qclass != 1:
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
    offset, addresses, cname = _read_records(packet, offset, ancount)
    offset, more_addresses, more_cname = _read_records(packet, offset, nscount)
    # Parse additional records for bounds/format validation but do not use A
    # glue from them for authorization.
    offset, _ignored_addresses, _ignored_cname = _read_records(packet, offset, arcount)
    if offset != len(packet):
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
    # Authority-section CNAME/A records are not authoritative answer data.
    del more_addresses, more_cname

    current = expected
    visited: set[str] = set()
    answer_ips: set[str] = set()
    while True:
        if current in visited:
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
        visited.add(current)
        current_addresses = addresses.get(current, set())
        current_cnames = cname.get(current, set())
        if len(current_cnames) > 1:
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
        if current_addresses and current_cnames:
            # A CNAME owner cannot also carry address data. Reject the
            # ambiguous RRset instead of choosing whichever record happens to
            # be encountered first.
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
        answer_ips.update(current_addresses)
        if current_addresses or not current_cnames:
            break
        current = next(iter(current_cnames))
    if not answer_ips:
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_NO_A")
    return tuple(sorted(answer_ips))


async def resolve_a(host: str) -> tuple[str, ...]:
    """Query only the pinned local TCP DNS proxy and return validated A data."""

    normalized = _normalize_fqdn(host, code="EGRESS_PUBLIC_POLICY_HOST_INVALID")
    query_id = secrets.randbits(16)
    question = _encode_dns_name(normalized) + struct.pack("!HH", 1, 1)
    message = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question
    reader = writer = None
    try:
        reader, writer = await _open_dns_connection()
        peer = writer.get_extra_info("peername")
        if peer is not None and (
            not isinstance(peer, (tuple, list))
            or len(peer) < 2
            or peer[0] != DNS_CONNECT_HOST
            or int(peer[1]) != DNS_CONNECT_PORT
        ):
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_UNTRUSTED")
        if len(message) > 65535:
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_QUERY_INVALID")
        writer.write(struct.pack("!H", len(message)) + message)
        await asyncio.wait_for(writer.drain(), DNS_QUERY_TIMEOUT)
        raw_length = await asyncio.wait_for(reader.readexactly(2), DNS_QUERY_TIMEOUT)
        (length,) = struct.unpack("!H", raw_length)
        if length < 12 or length > DNS_MAX_MESSAGE:
            raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_RESPONSE_INVALID")
        packet = await asyncio.wait_for(reader.readexactly(length), DNS_QUERY_TIMEOUT)
        return parse_dns_response(packet, query_id, normalized)
    except PolicyError:
        raise
    except asyncio.TimeoutError:
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_TIMEOUT") from None
    except (OSError, asyncio.IncompleteReadError, struct.error, ValueError, TypeError):
        raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_UNAVAILABLE") from None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def _resolve_a(host: str) -> tuple[str, ...]:
    """Compatibility alias used by tests and sibling launch integrations."""

    return await resolve_a(host)


async def _validate_tls_binding(
    client_id: str, server: Any, sni_value: Any
) -> HandshakeBinding:
    if not client_id:
        raise PolicyError("EGRESS_PUBLIC_POLICY_CLIENT_INVALID")
    if sni_value is None or sni_value == "":
        raise PolicyError("EGRESS_PUBLIC_POLICY_SNI_REQUIRED")
    host = _normalize_fqdn(sni_value, code="EGRESS_PUBLIC_POLICY_SNI_INVALID")
    original = _original_address(server)
    answers = await resolve_a(host)
    route = _choose_route(host, original, answers)
    return HandshakeBinding(
        client_id=client_id,
        route=route,
        host=host,
        port=original[1],
        original=original,
        answers=answers,
        # Connection lifetime is bounded by mitmproxy's server_disconnected
        # cleanup. Do not expire this identity binding while a keep-alive
        # connection is still carrying requests.
        expires_at=float("inf"),
    )


async def tls_clienthello(data: Any) -> None:
    """Bind SNI and original transparent destination before TLS interception."""

    if not _strict_configured:
        return
    # system.py runs first and intentionally passes no-SNI connections
    # through in legacy mode.  Strict mode must override that decision and
    # fail closed instead.
    try:
        data.ignore_connection = False
    except Exception:
        pass
    if _policy is None or _strict_config_error is not None:
        code = _strict_config_error or "EGRESS_PUBLIC_POLICY_INVALID"
        _deny_server(getattr(getattr(data, "context", None), "server", None), code)
        try:
            data.context.client.error = code
        except Exception:
            pass
        return
    context = getattr(data, "context", None)
    server = getattr(context, "server", None)
    client = getattr(context, "client", None)
    if getattr(server, "error", None) or getattr(client, "error", None):
        # Keep a terminal decision made by system.py (or an earlier hook) and
        # do not attach a route marker that could make the later upstream
        # addon treat this connection as dialable.
        return
    client_id = _client_id(client)
    sni = getattr(getattr(data, "client_hello", None), "sni", None)
    try:
        binding = await _validate_tls_binding(client_id, server, sni)
        _server_marker(server, SERVER_HANDSHAKE_ATTR, binding)
        _attach_route(server, binding)
        _server_permits[(client_id, getattr(server, "id", ""))] = binding
        _purge()
    except asyncio.CancelledError:
        _deny_server(server, "EGRESS_PUBLIC_POLICY_HOOK_FAILED")
        try:
            client.error = "EGRESS_PUBLIC_POLICY_HOOK_FAILED"
        except Exception:
            pass
    except Exception as error:
        code = _stable_code(error, "EGRESS_PUBLIC_POLICY_TLS_BINDING_FAILED")
        _deny_server(server, code)
        try:
            client.error = code
        except Exception:
            pass


async def tls_start_client(data: Any) -> None:
    """Ensure a rejected strict ClientHello cannot be intercepted or passed through."""

    if not _strict_configured:
        return
    context = getattr(data, "context", None)
    client = getattr(context, "client", None)
    if getattr(client, "error", None):
        # None means the built-in tlsconfig addon cannot supply a context, and
        # the TLS layer closes the connection.  This is safer than setting
        # ignore_connection=True, which would pass raw bytes around the policy.
        try:
            data.ssl_conn = None
        except Exception:
            pass


async def requestheaders(flow: http.HTTPFlow) -> None:
    """Check Host/SNI and issue a one-request destination permit."""

    if not _strict_configured:
        return
    if _flow_has_terminal_result(flow):
        return
    request = getattr(flow, "request", None)
    server = getattr(flow, "server_conn", None)
    client_id = _client_id(getattr(flow, "client_conn", None))
    prior_server_error = getattr(server, "error", None)
    if prior_server_error:
        # A failed ClientHello or an earlier server hook may already have
        # made the connection terminal. Preserve our stable policy code when
        # possible instead of replacing it with a later, less precise SNI or
        # permit error. Never expose arbitrary mitmproxy error text to the
        # workload.
        code = (
            prior_server_error
            if isinstance(prior_server_error, str)
            and prior_server_error.startswith("EGRESS_PUBLIC_POLICY_")
            else "EGRESS_PUBLIC_POLICY_SERVER_REJECTED"
        )
        _deny_flow(flow, code)
        return
    if _policy is None or _strict_config_error is not None:
        _deny_flow(flow, _strict_config_error or "EGRESS_PUBLIC_POLICY_INVALID")
        return
    try:
        if not client_id:
            raise PolicyError("EGRESS_PUBLIC_POLICY_CLIENT_INVALID")
        scheme = str(getattr(request, "scheme", "")).lower()
        host, explicit_port = _request_authority(request)
        original = _original_address(server)
        if scheme == "https":
            binding = getattr(server, SERVER_HANDSHAKE_ATTR, None)
            if not isinstance(binding, HandshakeBinding):
                binding = _server_permits.get((client_id, getattr(server, "id", "")))
            if not isinstance(binding, HandshakeBinding):
                raise PolicyError("EGRESS_PUBLIC_POLICY_SNI_REQUIRED")
            if binding.client_id != client_id or binding.original != original:
                raise PolicyError("EGRESS_PUBLIC_POLICY_ORIGINAL_DEST_CHANGED")
            if host != binding.host:
                raise PolicyError("EGRESS_PUBLIC_POLICY_SNI_HOST_MISMATCH")
            answers = await resolve_a(host)
            if original[0] not in answers:
                raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_BINDING_FAILED")
            route = _choose_route(host, original, answers)
            if route != binding.route:
                raise PolicyError("EGRESS_PUBLIC_POLICY_DNS_BINDING_FAILED")
            if explicit_port is not None and explicit_port != original[1]:
                raise PolicyError("EGRESS_PUBLIC_POLICY_PORT_DENIED")
        elif scheme == "http":
            if explicit_port is not None and explicit_port != original[1]:
                raise PolicyError("EGRESS_PUBLIC_POLICY_PORT_DENIED")
            target = _policy.internal_targets.get(host)
            # Plain HTTP has no public route. Reject it before doing a DNS
            # lookup so a public HTTP request cannot spend time on (or learn
            # anything from) the resolver. Only an exact configured internal
            # target may proceed to the fresh DNS/original-destination bind.
            if target is None:
                raise PolicyError("EGRESS_PUBLIC_POLICY_PUBLIC_HTTP_DENIED")
            answers = await resolve_a(host)
            if (
                original[0] not in target.ips
                or original[1] not in target.ports
                or original[0] not in answers
            ):
                raise PolicyError("EGRESS_PUBLIC_POLICY_INTERNAL_BINDING_FAILED")
            route = ROUTE_INTERNAL_DIRECT
        else:
            raise PolicyError("EGRESS_PUBLIC_POLICY_SCHEME_DENIED")

        _log_route(route)
        permit = _new_permit(client_id, route, host, original, answers)
        # For internal traffic retain the IP as the connect target; Host and
        # SNI still carry the administrator-authorized FQDN.  For public
        # traffic rewrite only mitmproxy's target host so its upstream CONNECT
        # authority is the normalized FQDN, never the transparent IP.
        if route == ROUTE_PUBLIC_PROXY:
            request.host = host
            request.port = 443
            _store_proxy_permit(permit)
        else:
            try:
                normalized_authority = host
                if explicit_port is not None:
                    normalized_authority = f"{host}:{explicit_port}"
                request.host_header = normalized_authority
            except Exception:
                pass
        _attach_route(server, permit)
        key = _exact_key(client_id, original)
        if key is not None:
            _store_permit(permit, original, getattr(server, "address", None))
        try:
            flow.metadata[FLOW_PERMIT_KEY] = permit
        except Exception:
            pass
    except asyncio.CancelledError:
        _deny_flow(flow, "EGRESS_PUBLIC_POLICY_HOOK_FAILED")
    except Exception as error:
        _deny_flow(flow, _stable_code(error, "EGRESS_PUBLIC_POLICY_DESTINATION_DENIED"))


async def http_connect(flow: http.HTTPFlow) -> None:
    """Reject inbound regular-mode CONNECT in strict transparent deployments."""

    if not _strict_configured or _flow_has_terminal_result(flow):
        return
    # The strict contract depends on SO_ORIGINAL_DST from transparent mode.
    # A regular proxy CONNECT supplies an authority but no kernel-captured
    # original destination; allowing it would make the gateway the authority
    # for an unbound request.  The generated CONNECT sent *to* the gateway is
    # handled by upstream_proxy.py and uses the permit's normalized host.
    _deny_flow(flow, "EGRESS_PUBLIC_POLICY_TRANSPARENT_REQUIRED")


async def server_connect(data: Any) -> None:
    """Authorize and bind every server object immediately before its dial."""

    if not _strict_configured:
        return
    server = getattr(data, "server", None)
    client = getattr(data, "client", None)
    client_id = _client_id(client)
    try:
        if getattr(server, "error", None):
            # A previous hook (including this addon on a raced/reused object)
            # has already denied the connection. Never replace that reason.
            return
        if _policy is None or _strict_config_error is not None:
            raise PolicyError(_strict_config_error or "EGRESS_PUBLIC_POLICY_INVALID")
        if not client_id or server is None:
            raise PolicyError("EGRESS_PUBLIC_POLICY_PERMIT_REQUIRED")

        # Internal direct permits are checked first.  This avoids confusing an
        # administrator-authorized internal endpoint with a same-address
        # gateway endpoint in unusual test/deployment topologies.
        permit = _lookup_permit(client_id, getattr(server, "address", None), ROUTE_INTERNAL_DIRECT)
        if permit is not None:
            _attach_route(server, permit)
            _server_permits[(client_id, getattr(server, "id", ""))] = permit
            _purge()
            return

        # In upstream-proxy mode the destination placeholder carries a
        # non-None ``via`` specification and is not the socket that will be
        # dialled. The actual gateway Server object has no ``via``. Never let
        # a destination object (or a copied marker on one) be mistaken for a
        # gateway merely because both happen to use port 443.
        if getattr(server, "via", None) is not None:
            raise PolicyError("EGRESS_PUBLIC_POLICY_PERMIT_REQUIRED")

        # A public flow must already have a permit issued by requestheaders.
        # The gateway connection is a different mitmproxy Server object, so
        # it is authorized by a short-lived per-client queue keyed to the
        # exact configured gateway address.
        if _gateway is None:
            raise PolicyError("EGRESS_PUBLIC_POLICY_GATEWAY_REQUIRED")
        gateway_address = getattr(server, "address", None)
        gateway_key = _address(gateway_address)
        if gateway_key is None or gateway_key[1] != _gateway.port:
            raise PolicyError("EGRESS_PUBLIC_POLICY_PERMIT_REQUIRED")
        pending = _pop_proxy_permit(client_id, gateway_address)
        if pending is None:
            raise PolicyError("EGRESS_PUBLIC_POLICY_PERMIT_REQUIRED")

        gateway_answers = await resolve_a(_gateway.host)
        configured_host = gateway_key[0]
        if configured_host != _gateway.host:
            # A parent may pre-resolve the gateway to an IP before invoking
            # this hook.  It is accepted only when the IP is a fresh A answer.
            if configured_host not in gateway_answers:
                raise PolicyError("EGRESS_PUBLIC_POLICY_GATEWAY_DNS_BINDING_FAILED")
            selected_ip = configured_host
        else:
            usable = [ip for ip in gateway_answers if _is_usable_gateway_ipv4(ip)]
            if not usable:
                raise PolicyError("EGRESS_PUBLIC_POLICY_GATEWAY_DNS_BINDING_FAILED")
            # Stable selection keeps connection tests and diagnostics
            # deterministic while still requiring a fresh answer per dial.
            selected_ip = usable[0]
        if not _is_usable_gateway_ipv4(selected_ip):
            raise PolicyError("EGRESS_PUBLIC_POLICY_GATEWAY_DNS_BINDING_FAILED")
        # Preserve the original configured FQDN for upstream TLS hostname
        # verification.  upstream_proxy.py reads this private attr after this
        # hook mutates the transport address to the fresh A answer.
        _server_marker(server, SERVER_PROXY_HOST_ATTR, _gateway.host)
        _attach_route(server, pending)
        _server_marker(server, SERVER_PROXY_PERMIT_ATTR, pending)
        try:
            server.address = (selected_ip, _gateway.port)
        except Exception:
            raise PolicyError("EGRESS_PUBLIC_POLICY_GATEWAY_BINDING_FAILED") from None
        _server_permits[(client_id, getattr(server, "id", ""))] = pending
        _purge()
    except asyncio.CancelledError:
        _deny_server(server, "EGRESS_PUBLIC_POLICY_HOOK_FAILED")
    except Exception as error:
        _deny_server(server, _stable_code(error, "EGRESS_PUBLIC_POLICY_PERMIT_REQUIRED"))


def client_disconnected(client: Any) -> None:
    if not _strict_configured:
        return
    client_id = _client_id(client)
    if not client_id:
        return
    for key in list(_permits):
        if key[0] == client_id:
            _permits.pop(key, None)
    for key in list(_proxy_permits):
        if key[0] == client_id:
            _proxy_permits.pop(key, None)
    for key in list(_server_permits):
        if key[0] == client_id:
            _server_permits.pop(key, None)


def server_disconnected(data: Any) -> None:
    if not _strict_configured:
        return
    server = getattr(data, "server", None)
    client = getattr(data, "client", None)
    client_id = _client_id(client)
    if client_id:
        _server_permits.pop((client_id, getattr(server, "id", "")), None)
    for attr in (
        SERVER_PERMIT_ATTR,
        SERVER_HANDSHAKE_ATTR,
        SERVER_ROUTE_ATTR,
        SERVER_PROXY_HOST_ATTR,
        SERVER_PROXY_PERMIT_ATTR,
        SERVER_DIRECT_PERMIT_ATTR,
    ):
        try:
            delattr(server, attr)
        except Exception:
            pass


def server_connect_error(data: Any) -> None:
    server_disconnected(data)


__all__ = [
    "DNS_CONNECT_HOST",
    "DNS_CONNECT_PORT",
    "FLOW_PERMIT_KEY",
    "GatewaySpec",
    "InternalTarget",
    "PERMIT_TTL",
    "PolicyError",
    "PublicPolicy",
    "PUBLIC_POLICY_ENV",
    "ROUTE_INTERNAL_DIRECT",
    "ROUTE_PUBLIC_PROXY",
    "SERVER_DIRECT_PERMIT_ATTR",
    "SERVER_HANDSHAKE_ATTR",
    "SERVER_PERMIT_ATTR",
    "SERVER_PROXY_HOST_ATTR",
    "SERVER_PROXY_PERMIT_ATTR",
    "parse_dns_response",
    "parse_policy",
    "resolve_a",
    "normalize_fqdn",
]
