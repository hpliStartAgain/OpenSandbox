#!/usr/bin/env python3
# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Real Docker image coverage of the OSEP-0023 live Vault binding loop.

Builds the ordinary components/egress/Dockerfile image (or takes --image),
then runs the real sidecar with the experimental revision runtime and live
admission bundle against an independent HTTPS origin on a Docker network:

- unbound HTTPS keeps end-to-end TLS (a client that trusts only the origin
  CA succeeds, proving no termination), while a bound host is decrypted and
  receives the injected credential only on matching requests;
- rotation switches per-request on one HTTP/1.1 keepalive connection, stale
  expectedRevision conflicts, and a removed/re-added host never resurrects a
  revoked connection;
- failures fail closed: wrong path/method inject nothing, an untrusted
  client cannot complete TLS, an origin presenting the wrong certificate
  never sees the request, and unauthorized API calls are rejected.

Unavailable Docker/build prerequisites FAIL. Management uses docker exec
inside the real network namespace; evidence (per-case results, origin logs,
egress logs) is written to an artifacts directory without credential values.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[3]
EGRESS = "/opt/opensandbox-egress/egress"
SUPERVISOR = "/opt/opensandbox-egress/supervisor"
FIXTURES = ROOT / "components/egress/tests/fixtures"
ENTRYPOINT = [SUPERVISOR, "--pre-start=/opt/opensandbox-egress/cleanup.sh",
              "--name=egress", "--grace-period=20s", "--", EGRESS]
TOKEN = "live-vault-test-token"
SECRET_ONE = "live-secret-one" * 2
SECRET_TWO = "rotated-live-secret-two" * 3
BOUND = "bound.example.com"
UNBOUND = "unbound.example.com"
BADCERT = "badcert.example.com"
ORIGIN_PORT_WAIT = 20
# Some hosts exhaust Docker's predefined address pools (many CI networks).
# Try explicit private subnets before falling back to the daemon default.
SUBNET_CANDIDATES = ["192.168.207.0/24", "192.168.208.0/24", "10.207.77.0/24", "172.30.207.0/24"]
# Docker's embedded DNS listens on 127.0.0.11 and is reached through the
# daemon's own DOCKER_OUTPUT chain, which precedes the sidecar's port-53
# redirect. On a Docker network the sidecar therefore never sees those queries,
# so DNS-learned dynamic allow entries are not produced. The test pins the
# origin addresses and allows them statically instead, which keeps policy
# enforcement (default deny) fully in the path while removing the dependency on
# the Docker DNS implementation. Kubernetes deployments resolve through a
# non-loopback cluster DNS and exercise the dynamic path as designed.
ORIGIN_IP_SUFFIX = 10
BADCERT_IP_SUFFIX = 11

REQUIRED = [
    "TestLiveVaultImagePrerequisites",
    "TestUnboundTrafficKeepsEndToEndTLS",
    "TestBoundHostInjectsCredential",
    "TestRotationStaleAndKeepalive",
    "TestDeleteRevocationAndRemoveReadd",
    "TestFailureBoundaries",
]


class Failure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


class Docker:
    def __init__(self, artifacts: Path) -> None:
        self.artifacts = artifacts

    def run(self, *args, check=True, timeout=60):
        command = ["docker", *map(str, args)]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Failure(f"Docker command failed: {command[:3]}: {exc}") from exc
        with (self.artifacts / "commands.jsonl").open("a") as stream:
            stream.write(json.dumps({
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-4000:],
            }) + "\n")
        if check and result.returncode:
            raise Failure(f"docker {' '.join(map(str, args[:3]))} failed ({result.returncode}): "
                          f"{result.stdout[-3000:]}{result.stderr[-3000:]}")
        return result

    def json(self, *args):
        return json.loads(self.run(*args).stdout)


def vault_body(secret: str) -> str:
    return json.dumps({
        "credentials": [{"name": "api-token", "source": {"type": "inline", "value": secret}}],
        "bindings": [{
            "name": "api",
            "match": {
                "schemes": ["https"],
                "hosts": [BOUND],
                "methods": ["GET", "POST"],
                "paths": ["/v1/*"],
            },
            "auth": {"type": "apiKey", "name": "Private-Token", "credential": "api-token"},
        }],
    })


def vault_body_two_bindings(secret: str) -> str:
    body = json.loads(vault_body(secret))
    body["bindings"].append({
        "name": "badcert",
        "match": {"schemes": ["https"], "hosts": [BADCERT], "methods": ["GET"], "paths": ["/v1/*"]},
        "auth": {"type": "apiKey", "name": "Private-Token", "credential": "api-token"},
    })
    return json.dumps(body)


def rotate_body(expected: int, secret: str) -> str:
    return json.dumps({
        "expectedRevision": expected,
        "credentials": {"replace": [{"name": "api-token", "source": {"type": "inline", "value": secret}}]},
    })


class LiveVaultRuntime:
    def __init__(self, docker: Docker, image: str, drain_seconds: int) -> None:
        self.docker = docker
        self.image = image
        self.drain_seconds = drain_seconds
        self.network = "osbs-live-vault-" + uuid.uuid4().hex[:12]
        self.egress = self.network + "-egress"
        self.origin = self.network + "-origin"
        self.badcert = self.network + "-badcert"
        self.workdir = Path(tempfile.mkdtemp(prefix="osbs-live-vault-"))
        self.subnet = ""

    def origin_addresses(self) -> tuple[str, str]:
        prefix = self.subnet.rsplit(".", 1)[0]
        return f"{prefix}.{ORIGIN_IP_SUFFIX}", f"{prefix}.{BADCERT_IP_SUFFIX}"

    def __enter__(self):
        if not self._create_network():
            raise Failure("cannot allocate a Docker network for the live vault test")
        origin_ip, badcert_ip = self.origin_addresses()
        try:
            shared = self.workdir / "shared"
            shared.mkdir()
            (shared / "badcert").mkdir()
            self.docker.run(
                "run", "-d", "--name", self.origin, "--network", self.network,
                "--ip", origin_ip, "--network-alias", BOUND,
                "--network-alias", UNBOUND,
                "-v", f"{shared}:/run/live-origin",
                "-v", f"{FIXTURES}:/fixtures:ro",
                "--entrypoint", "python3", self.image,
                "/fixtures/live_vault_origin.py", BOUND, UNBOUND,
            )
            self.docker.run(
                "run", "-d", "--name", self.badcert, "--network", self.network,
                "--ip", badcert_ip, "--network-alias", BADCERT,
                "-v", f"{shared}/badcert:/run/live-origin",
                "-v", f"{FIXTURES}:/fixtures:ro",
                "--entrypoint", "python3", self.image,
                "/fixtures/live_vault_origin.py", "good.example.com",
            )
            self.wait_origin(self.origin, shared)
            self.wait_origin(self.badcert, shared / "badcert")
            env = {
                "OPENSANDBOX_EGRESS_EXPERIMENTAL_REVISION_RUNTIME": "true",
                "OPENSANDBOX_EGRESS_MODE": "dns+nft",
                "OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT": "true",
                "OPENSANDBOX_EGRESS_RULES": json.dumps({
                    "defaultAction": "deny",
                    "egress": [
                        {"action": "allow", "target": BOUND},
                        {"action": "allow", "target": UNBOUND},
                        {"action": "allow", "target": BADCERT},
                        {"action": "allow", "target": origin_ip},
                        {"action": "allow", "target": badcert_ip},
                    ],
                }),
                "OPENSANDBOX_EGRESS_TOKEN": TOKEN,
                "OPENSANDBOX_EGRESS_MITMPROXY_UPSTREAM_EXTRA_CA": "/run/live-origin/ca.pem",
                "OPENSANDBOX_EGRESS_REVISION_DRAIN_TIMEOUT_SECONDS": str(self.drain_seconds),
            }
            args = ["run", "-d", "--name", self.egress, "--network", self.network,
                    "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges",
                    "-v", f"{shared}:/run/live-origin:ro",
                    "--add-host", f"{BOUND}:{origin_ip}",
                    "--add-host", f"{UNBOUND}:{origin_ip}",
                    "--add-host", f"{BADCERT}:{badcert_ip}"]
            for key, value in env.items():
                args += ["--env", key + "=" + value]
            self.docker.run(*args, self.image)
            self.docker.run("cp", str(FIXTURES / "live_vault_client.py"),
                            f"{self.egress}:/tmp/live_vault_client.py")
            self.wait_health()
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def _create_network(self) -> bool:
        """Allocate the test network, preferring an explicit private subnet."""
        for subnet in SUBNET_CANDIDATES:
            result = self.docker.run(
                "network", "create", "--subnet", subnet, self.network, check=False
            )
            if result.returncode == 0:
                self.subnet = subnet
                return True
        result = self.docker.run("network", "create", self.network, check=False)
        if result.returncode == 0:
            self.subnet = self.docker.run(
                "network", "inspect", self.network,
                "--format", "{{(index .IPAM.Config 0).Subnet}}",
            ).stdout.strip()
        return result.returncode == 0

    def wait_origin(self, name: str, shared: Path) -> None:
        deadline = time.monotonic() + ORIGIN_PORT_WAIT
        while time.monotonic() < deadline:
            logs = self.docker.run("logs", name, check=False).stdout
            if '"ready": true' in logs:
                require((shared / "ca.pem").exists(), f"origin {name} did not export its CA")
                return
            time.sleep(0.3)
        raise Failure(f"origin {name} did not become ready")

    def wait_health(self) -> None:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            status = self.health()
            if status == "200":
                return
            time.sleep(0.5)
        raise Failure(f"egress did not become healthy (last status {self.health()})")

    def health(self) -> str:
        result = self.docker.run(
            "exec", self.egress, "python3", "-c",
            "import urllib.request;"
            "\ntry:\n print(urllib.request.urlopen('http://127.0.0.1:18080/healthz',timeout=3).status)"
            "\nexcept Exception as exc:\n print('error', type(exc).__name__)",
            check=False,
        )
        if result.returncode != 0:
            return "error"
        return result.stdout.strip().splitlines()[-1] if result.stdout.strip() else "error"

    def exec_egress(self, *args, timeout=90):
        return self.docker.run("exec", self.egress, *map(str, args), timeout=timeout)

    def exec_origin(self, name: str, *args, timeout=30, check=True):
        return self.docker.run("exec", name, *map(str, args), timeout=timeout, check=check)

    def client(self, plan: dict) -> list[dict]:
        # docker exec passes arguments directly (no shell), so the plan travels
        # as one raw argv entry without any quoting.
        result = self.exec_egress("python3", "/tmp/live_vault_client.py", json.dumps(plan))
        try:
            return json.loads(result.stdout)
        except ValueError as exc:
            raise Failure(f"client output not JSON: {result.stdout[:2000]}") from exc

    def origin_log(self, name: str = None) -> list[dict]:
        name = name or self.origin
        result = self.exec_origin(name, "cat", "/tmp/origin-log.jsonl", check=False)
        out = []
        for line in result.stdout.splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def egress_logs(self) -> str:
        return self.docker.run("logs", self.egress, timeout=60).stdout

    def __exit__(self, *_exc):
        for name in (self.egress, self.origin, self.badcert):
            if name:
                self.docker.run("rm", "-f", name, check=False, timeout=60)
        if self.network:
            self.docker.run("network", "rm", self.network, check=False, timeout=60)
        shutil.rmtree(self.workdir, ignore_errors=True)
        return False


def run_case(name, action, results, artifacts):
    print("=== RUN   " + name, flush=True)
    started = time.monotonic()
    record = {"name": name, "status": "RUN"}
    results.append(record)
    try:
        action()
    except Exception as exc:
        record.update(status="FAIL", error=str(exc))
        print(f"--- FAIL: {name}: {exc}", flush=True)
        raise
    record.update(status="PASS", seconds=round(time.monotonic() - started, 3))
    print(f"--- PASS: {name} ({record['seconds']:.3f}s)", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", help="ordinary egress image to test")
    parser.add_argument("--artifacts", type=Path, help="directory for evidence")
    parser.add_argument("--drain-seconds", type=int, default=2,
                        help="credential transition drain timeout in the sidecar")
    args = parser.parse_args(argv)
    artifacts = args.artifacts or Path(tempfile.mkdtemp(prefix="egress-live-vault-"))
    artifacts.mkdir(parents=True, exist_ok=True)
    docker = Docker(artifacts)
    image = args.image or "opensandbox-egress-livevault:" + uuid.uuid4().hex[:12]
    results = []
    success = False

    def prerequisites():
        require(shutil.which("docker") is not None, "Docker CLI unavailable; real image test did not run")
        info = docker.json("info", "--format", "{{json .}}")
        (artifacts / "docker-runtime.json").write_text(json.dumps(info, indent=2) + "\n")
        require(info["OSType"] == "linux" and not any("rootless" in x for x in info.get("SecurityOptions", [])),
                "live vault image test requires rootful Linux Docker with NET_ADMIN")
        if not args.image:
            build_args = ["--build-arg", "GOPROXY=" + _host_goproxy()] if _host_goproxy() else []
            docker.run("build", "-f", ROOT / "components/egress/Dockerfile", *build_args,
                       "-t", image, ROOT, timeout=1800)
        require(docker.json("image", "inspect", image)[0]["Config"]["Entrypoint"] == ENTRYPOINT,
                "image has an unexpected entrypoint")

    def test_unbound_end_to_end_tls(runtime: LiveVaultRuntime):
        plan = {"requests": [{"host": UNBOUND, "path": "/anything", "trust": "origin"}]}
        outcomes = runtime.client(plan)
        require(len(outcomes) == 1 and outcomes[0].get("status") == 200,
                f"unbound HTTPS did not succeed with origin-only trust: {outcomes}")
        echo = outcomes[0]["echo"]
        require(not echo.get("private_token") and not echo.get("authorization"),
                f"unbound traffic received credentials: {echo}")
        require(runtime.origin_log(), "unbound request never reached the origin")

    def test_bound_injection(runtime: LiveVaultRuntime):
        created = runtime.client({"requests": [{
            "vault_api": {"method": "POST", "path": "/credential-vault",
                          "body": vault_body(SECRET_ONE), "token": TOKEN},
        }]})
        require(created and created[0].get("status") == 201,
                f"vault create failed: {created}")

        authorized = runtime.client({"requests": [
            {"host": BOUND, "path": "/v1/data", "trust": "mitm"},
            {"host": UNBOUND, "path": "/anything", "trust": "origin"},
        ]})
        bound, unbound = authorized
        require(bound.get("status") == 200, f"bound request failed: {bound}")
        require(bound["echo"].get("private_token") == f"present({len(SECRET_ONE)} chars)",
                f"bound request did not receive the vault credential: {bound}")
        require(unbound.get("status") == 200 and not unbound["echo"].get("private_token"),
                f"unbound traffic changed after binding: {unbound}")

    def test_rotation_stale_keepalive(runtime: LiveVaultRuntime):
        stale = runtime.client({"requests": [{
            "vault_api": {"method": "PATCH", "path": "/credential-vault",
                          "body": rotate_body(99, SECRET_TWO), "token": TOKEN},
        }]})
        require(stale[0].get("status") == 409, f"stale expectedRevision must conflict: {stale}")

        plan = {"requests": [
            {"host": BOUND, "path": "/v1/first", "trust": "mitm"},
            {"vault_api": {"method": "PATCH", "path": "/credential-vault",
                           "body": rotate_body(1, SECRET_TWO), "token": TOKEN}},
            {"host": BOUND, "path": "/v1/second", "trust": "mitm", "keepalive_with": 0},
        ]}
        outcomes = runtime.client(plan)
        first, patched, second = outcomes
        require(first.get("status") == 200 and first["echo"].get("private_token") == f"present({len(SECRET_ONE)} chars)",
                f"pre-rotation request missing first credential: {first}")
        require(patched.get("status") == 200, f"rotation PATCH failed: {patched}")
        require(second.get("status") == 200 and second["echo"].get("private_token") == f"present({len(SECRET_TWO)} chars)",
                f"keepalive request did not pick up the rotated credential: {second}")

    def test_delete_revocation(runtime: LiveVaultRuntime):
        # Phase A keeps the revoked transport untouched until after the host is
        # re-added, so the same TCP connection is asked again: the permanent
        # fence, not the transport close, must be what denies it. No request
        # runs between delete and re-add, because a fenced rejection answers
        # Connection: close and the client would silently open a new transport.
        phase_a = {"requests": [
            {"host": BOUND, "path": "/v1/data", "trust": "mitm"},
            {"vault_api": {"method": "DELETE", "path": "/credential-vault", "token": TOKEN}},
            {"vault_api": {"method": "POST", "path": "/credential-vault",
                           "body": vault_body(SECRET_ONE), "token": TOKEN}},
            {"host": BOUND, "path": "/v1/after-readd", "trust": "mitm", "keepalive_with": 0},
        ]}
        live, deleted, recreated, resurrected = runtime.client(phase_a)
        require(live.get("status") == 200 and live["echo"].get("private_token"),
                f"pre-delete request missing credential: {live}")
        require(deleted.get("status") == 204, f"vault delete failed: {deleted}")
        require(recreated.get("status") == 201, f"vault re-create failed: {recreated}")
        require(resurrected.get("reused_connection") is True,
                f"revocation check lost its transport and proved nothing: {resurrected}")
        require("error" in resurrected or (
                resurrected.get("status", 0) >= 400
                and not (resurrected.get("echo") or {}).get("private_token")),
                f"removed/re-added host revived the revoked connection: {resurrected}")

        # Phase B starts from the vault re-added in phase A: a new connection is
        # credentialed again, removal makes further connections opaque, and the
        # now-idle retired transport is force-closed at its drain deadline (no
        # request runs on it in between, so only the timer can close it).
        phase_b = {"requests": [
            {"host": BOUND, "path": "/v1/recreated", "trust": "mitm"},
            {"vault_api": {"method": "DELETE", "path": "/credential-vault", "token": TOKEN}},
            {"host": BOUND, "path": "/v1/fresh", "trust": "origin"},
            {"host": BOUND, "path": "/v1/after-deadline", "trust": "mitm", "keepalive_with": 0,
             "delay_ms": (runtime.drain_seconds + 2) * 1000},
        ]}
        credentialed, deleted_again, fresh, expired = runtime.client(phase_b)
        require(credentialed.get("status") == 200 and credentialed["echo"].get("private_token"),
                f"re-added vault did not inject its credential: {credentialed}")
        require(deleted_again.get("status") == 204, f"second vault delete failed: {deleted_again}")
        require(fresh.get("status") == 200 and not fresh["echo"].get("private_token"),
                f"new connection after delete was not opaque: {fresh}")
        require("error" in expired or expired.get("status", 0) >= 400,
                f"drain deadline did not close the retired transport: {expired}")
        require(not (expired.get("echo") or {}).get("private_token"),
                f"expired request still received credentials: {expired}")

    def test_failure_boundaries(runtime: LiveVaultRuntime):
        created = runtime.client({"requests": [{
            "vault_api": {"method": "POST", "path": "/credential-vault",
                          "body": vault_body(SECRET_ONE), "token": TOKEN},
        }]})
        require(created[0].get("status") == 201, f"vault create failed: {created}")
        wrong_scope = runtime.client({"requests": [
            {"host": BOUND, "path": "/health", "trust": "mitm"},
            {"host": BOUND, "path": "/v1/data", "trust": "mitm", "method": "DELETE"},
        ]})
        wrong_path, wrong_method = wrong_scope
        require(wrong_path.get("status") == 200 and not wrong_path["echo"].get("private_token"),
                f"out-of-scope path received credentials: {wrong_path}")
        require(wrong_method.get("status") == 200 and not wrong_method["echo"].get("private_token"),
                f"out-of-scope method received credentials: {wrong_method}")

        untrusted = runtime.client({"requests": [
            {"host": BOUND, "path": "/v1/data", "trust": "origin"},
        ]})[0]
        require("error" in untrusted and "CERTIFICATE_VERIFY_FAILED" in untrusted.get("error", ""),
                f"untrusted client did not fail TLS verification: {untrusted}")

        added = runtime.client({"requests": [{
            "vault_api": {"method": "PATCH", "path": "/credential-vault",
                          "body": _add_badcert_binding(1), "token": TOKEN},
        }]})[0]
        require(added.get("status") == 200, f"badcert binding PATCH failed: {added}")
        bad = runtime.client({"requests": [{"host": BADCERT, "path": "/v1/data", "trust": "mitm"}]})[0]
        require(bad.get("status") == 502 or "error" in bad,
                f"wrong upstream certificate was not rejected: {bad}")
        require(not runtime.origin_log(runtime.badcert),
                "wrong-certificate origin still received requests")

        no_sni = runtime.client({"requests": [
            {"host": BOUND, "path": "/v1/data", "no_sni": True, "trust": "origin"},
        ]})[0]
        require(no_sni.get("status") == 200 and not (no_sni.get("echo") or {}).get("private_token"),
                f"no-SNI traffic did not pass through uncredentialed: {no_sni}")
        require(no_sni.get("peer_matches_origin") is True,
                f"no-SNI connection was terminated by the proxy: {no_sni}")

        unauthorized = runtime.client({"requests": [{
            "vault_api": {"method": "POST", "path": "/credential-vault", "body": vault_body(SECRET_ONE)},
        }]})[0]
        require(unauthorized.get("status") == 401, f"unauthorized write was accepted: {unauthorized}")

    def _add_badcert_binding(expected: int) -> str:
        return json.dumps({
            "expectedRevision": expected,
            "bindings": {"add": [{
                "name": "badcert",
                "match": {"schemes": ["https"], "hosts": [BADCERT], "methods": ["GET"], "paths": ["/v1/*"]},
                "auth": {"type": "apiKey", "name": "Private-Token", "credential": "api-token"},
            }]},
        })

    try:
        run_case(REQUIRED[0], prerequisites, results, artifacts)
        with LiveVaultRuntime(docker, image, args.drain_seconds) as runtime:
            run_case(REQUIRED[1], lambda: test_unbound_end_to_end_tls(runtime), results, artifacts)
            run_case(REQUIRED[2], lambda: test_bound_injection(runtime), results, artifacts)
            run_case(REQUIRED[3], lambda: test_rotation_stale_keepalive(runtime), results, artifacts)
            run_case(REQUIRED[4], lambda: test_delete_revocation(runtime), results, artifacts)
            run_case(REQUIRED[5], lambda: test_failure_boundaries(runtime), results, artifacts)
            (artifacts / "egress-logs.txt").write_text(runtime.egress_logs())
        require([r["name"] for r in results] == REQUIRED and all(r["status"] == "PASS" for r in results),
                "required live vault RUN/PASS evidence is incomplete")
        success = True
    except (Failure, ValueError, KeyError) as exc:
        print("Live vault image validation FAILED: " + str(exc), file=sys.stderr)
    finally:
        (artifacts / "results.json").write_text(json.dumps({
            "kind": "real-runtime-docker-image-live-vault",
            "image": image,
            "passed": success,
            "required": REQUIRED,
            "results": results,
        }, indent=2) + "\n")
        print("Live vault image evidence: " + str(artifacts.resolve()), flush=True)
        if not args.image and shutil.which("docker"):
            docker.run("image", "rm", image, check=False)
    return 0 if success else 1


def _host_goproxy() -> str:
    try:
        result = subprocess.run(["go", "env", "GOPROXY"], capture_output=True, text=True, timeout=10)
        value = result.stdout.strip()
        return value if value and value != "proxy.golang.org,direct" else ""
    except OSError:
        return ""


if __name__ == "__main__":
    sys.exit(main())
