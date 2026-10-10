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

"""TLS client driver for the OSEP-0023 live vault image test.

Runs inside the egress container's network namespace via ``docker exec`` so
the transparent interception rules apply. Takes a JSON plan on argv:

    {"requests": [
        {"host": "...", "path": "...", "method": "GET",
         "trust": "mitm" | "origin" | "none",
         "host_header": optional override,
         "sni": optional SNI override,
         "no_sni": bool,
         "keepalive_with": index of a previous request to reuse
        }
    ]}

Prints one JSON result per request: status, error, and the origin's echo
body. Never prints credential values directly; the origin echoes them, so
the driver masks well-known authorization headers in its own output.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import sys

MITM_CA = "/opt/opensandbox/mitmproxy-ca-cert.pem"
ORIGIN_CA = "/run/live-origin/ca.pem"


def trust_context(trust: str, hostname: str | None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if trust == "mitm":
        context.load_verify_locations(MITM_CA)
    elif trust == "origin":
        context.load_verify_locations(ORIGIN_CA)
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    # Hostname checking is off for SNI-less dials; chain verification stays on.
    context.check_hostname = bool(hostname)
    return context


class Result:
    def __init__(self) -> None:
        self.connection: http.client.HTTPSConnection | None = None

    def close(self) -> None:
        if self.connection is not None:
            with_suppressed(self.connection.close)
            self.connection = None


def with_suppressed(fn) -> None:
    try:
        fn()
    except Exception:
        pass


def perform(plan: dict) -> list[dict]:
    results: list[dict] = []
    connections: list[http.client.HTTPSConnection | None] = []
    for index, request in enumerate(plan["requests"]):
        if request.get("vault_api"):
            results.append(vault_api(request["vault_api"]))
            connections.append(None)
            continue
        if request.get("delay_ms"):
            import time

            time.sleep(request["delay_ms"] / 1000.0)
        result = perform_one(request, connections)
        results.append(result)
        connections.append(result.pop("_connection", None))
    for connection in connections:
        if connection is not None:
            with_suppressed(connection.close)
    return results


def vault_api(command: dict) -> dict:
    """Call the egress policy server from inside the container."""
    connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=10)
    body = command.get("body")
    headers = {"OPENSANDBOX-EGRESS-AUTH": command.get("token", "")}
    if body is not None:
        headers["content-type"] = "application/json"
    try:
        connection.request(command.get("method", "GET"), command["path"], body=body, headers=headers)
        response = connection.getresponse()
        return {
            "vault_api": command["path"],
            "status": response.status,
            "body": response.read().decode("utf-8", "replace")[:400],
        }
    except Exception as exc:  # noqa: BLE001
        return {"vault_api": command["path"], "error": type(exc).__name__ + ": " + str(exc)[:160]}
    finally:
        with_suppressed(connection.close)


def perform_one(request: dict, connections: list) -> dict:
    host = request["host"]
    path = request.get("path", "/echo")
    method = request.get("method", "GET")
    trust = request.get("trust", "none")
    host_header = request.get("host_header", host)
    no_sni = request.get("no_sni", False)
    reuse = request.get("keepalive_with")
    output = {"host": host, "path": path, "method": method, "trust": trust}
    connection = connections[reuse] if reuse is not None else None
    # Reuse is measured on the TCP socket, not the Python object: http.client
    # silently opens a new socket when the previous response said Connection:
    # close, and that new transport is a new interception decision.
    if connection is not None:
        try:
            current_socket = connection.sock.getsockname() if connection.sock else None
        except OSError:
            current_socket = None
        output["reused_connection"] = current_socket is not None and (
            current_socket == getattr(connection, "_live_socket", None)
        )
    else:
        output["reused_connection"] = False
    try:
        if connection is None:
            context = trust_context(trust, None if no_sni else host)
            if no_sni:
                # A connection without SNI: dial the resolved address with the
                # hostname kept only for the Host header.
                address = socket.gethostbyname(host)
                connection = http.client.HTTPSConnection(
                    address, 443, context=context, timeout=10
                )
            else:
                connection = http.client.HTTPSConnection(
                    host, 443, context=context, timeout=10
                )
        connection.request(method, path, headers={"Host": host_header})
        response = connection.getresponse()
        body = response.read().decode("utf-8", "replace")
        output["status"] = response.status
        output["connection_close"] = "close" in response.getheader("Connection", "").lower()
        try:
            echoed = json.loads(body)
            echoed["authorization"] = mask(echoed.get("authorization", ""))
            echoed["private_token"] = mask(echoed.get("private_token", ""))
            output["echo"] = echoed
        except ValueError:
            output["body"] = body[:200]
    except Exception as exc:  # noqa: BLE001 - every failure mode is evidence
        output["error"] = type(exc).__name__ + ": " + str(exc)[:160]
        if connection is not None:
            with_suppressed(connection.close)
            connection = None
    if connection is not None and no_sni:
        # Verify the actual TLS peer certificate against the origin CA: with
        # no SNI the connection must have passed through untouched, so the
        # peer certificate is the origin's own, not a mitmproxy one.
        with_suppressed(lambda: output.update(peer_matches_origin=peer_is_origin(connection)))
    if connection is not None:
        try:
            connection._live_socket = connection.sock.getsockname() if connection.sock else None
        except OSError:
            connection._live_socket = None
    output["_connection"] = connection
    return output


def peer_is_origin(connection: http.client.HTTPSConnection) -> bool | None:
    try:
        import hashlib

        peer_der = connection.sock.getpeercert(binary_form=True)
        origin_pem = open(ORIGIN_CA, "rb").read()
        origin_der = ssl.PEM_cert_to_DER_cert(origin_pem.decode("ascii"))
        return hashlib.sha256(peer_der).hexdigest() == hashlib.sha256(origin_der).hexdigest()
    except Exception:  # noqa: BLE001 - failure to inspect is reported as unknown
        return None


def mask(value: str) -> str:
    if not value:
        return ""
    return "present(" + str(len(value)) + " chars)"


if __name__ == "__main__":
    plan = json.loads(sys.argv[1])
    print(json.dumps(perform(plan)))
