#!/usr/bin/env python3
# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0

"""Real Docker image regressions; unavailable prerequisites FAIL, never skip.

Run from any directory:
  python3 components/egress/scripts/test_quarantine_image.py --image IMAGE

IMAGE must be built from components/egress/Dockerfile with
--build-arg GOFLAGS=-tags=egress_quarantine_faults. Without --image this script
builds that test-only image. It never publishes it. Each sidecar uses the real
image ENTRYPOINT, a private network/PID namespace, NET_ADMIN, and a dedicated
named journal volume. No host network, privileged container, host bind mount,
public reset/replay API, or production fault-injection switch is involved.

The provisioning helper has no capabilities/network and a read-only rootfs.
Runtime retains Docker's baseline process/ownership capabilities (mitmdump
needs SETUID/SETGID), drops NET_RAW, and adds only NET_ADMIN. Management uses
docker exec and nft netlink readback, which remain usable behind the fence.
This is image/lifecycle coverage, not a substitute for the real packet matrix.
An unprivileged workload survives in the original shared network namespace.
Same-namespace Go restarts must fence that original namespace. A whole-container
restart can split the two-container topology into different namespaces. That
boundary must report QuarantineUnknown/rebuild-required and refuse relaunch;
it does NOT establish isolation of the surviving workload's old namespace.
Old loopback traffic and both namespaces' fences are recorded independently.
Docker endpoint removal on one daemon/version is not a cross-runtime guarantee.
Mocked unit tests of this runner are NOT evidence that these cases executed.
"""

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[3]
STATE = "/var/lib/opensandbox-egress/quarantine"
EGRESS = "/opt/opensandbox-egress/egress"
SUPERVISOR = "/opt/opensandbox-egress/supervisor"
GUARD_FAILURE = "quarantine guard failed; cleanup and worker launch refused"
WORKER_STARTED = "supervisor: worker started ("
STAGES = {
    "before-intent": ("guarded", False, True),
    "after-intent": ("intent", False, True),
    "after-effects": ("intent", True, True),
    "before-commit": ("intent", True, True),
    "after-commit": ("committed", True, True),
    "before-unfence": ("running", True, True),
    "after-unfence": ("running", True, False),
    "before-ready": ("running", True, False),
}
INVALID_STATES = ("missing-record", "missing-lock", "corrupt", "identity-mismatch", "readonly")
ENTRYPOINT = [SUPERVISOR, "--pre-start=/opt/opensandbox-egress/cleanup.sh",
              "--name=egress", "--grace-period=20s", "--", EGRESS]

# Inspect only test-owned processes, never /proc/*/environ (IPC credentials).
SNAPSHOT = r'''
import json, os, pathlib, stat
root = pathlib.Path("/var/lib/opensandbox-egress/quarantine")
ns = os.stat("/proc/self/ns/net")
out = {"processes": [], "files": {}, "netns": os.readlink("/proc/self/ns/net"),
       "netns_dev": ns.st_dev, "netns_inode": ns.st_ino,
       "host_boot_id": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
for p in pathlib.Path("/proc").iterdir():
    if not p.name.isdecimal():
        continue
    try:
        args = [v.decode() for v in (p / "cmdline").read_bytes().split(b"\0") if v]
        status = dict(line.split(":", 1) for line in (p / "status").read_text().splitlines())
        if not args or status["State"].strip().startswith("Z"):
            continue
        role = None
        if args == ["/opt/opensandbox-egress/egress"]:
            role = "worker"
        elif args[0] == "/opt/opensandbox-egress/supervisor":
            role = "supervisor"
        elif any(pathlib.Path(a).name == "mitmdump" for a in args[:2]):
            role = "mitmdump"
        if role:
            out["processes"].append({"pid": int(p.name), "ppid": int(status["PPid"]),
                "uid": int(status["Uid"].split()[0]), "role": role})
    except (OSError, KeyError, ValueError):
        continue
for name in ("journal.json", "journal.lock", "checkpoint"):
    p = root / name
    try:
        s = p.lstat()
        out["files"][name] = {"hex": p.read_bytes().hex(), "mode": stat.S_IMODE(s.st_mode),
            "uid": s.st_uid, "gid": s.st_gid, "nlink": s.st_nlink,
            "regular": stat.S_ISREG(s.st_mode)}
    except FileNotFoundError:
        out["files"][name] = None
s = root.stat()
out["directory"] = {"mode": stat.S_IMODE(s.st_mode), "uid": s.st_uid, "gid": s.st_gid}
print(json.dumps(out))
'''

# A separate, unprivileged process supplies its own TCP echo peer. The listener,
# established client and fresh clients all live in the workload's original
# network namespace, so reconnecting the sidecar to a NEW namespace cannot
# produce a false isolation pass. Unix-domain control never traverses nft.
WORKLOAD = r'''
import json, os, pathlib, socket, threading, uuid
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen()
address = listener.getsockname()
boot = str(uuid.uuid4())
existing = None
def echo(conn):
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                return
            conn.sendall(data)
def serve():
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=echo, args=(conn,), daemon=True).start()
threading.Thread(target=serve, daemon=True).start()
def exchange(conn):
    token = uuid.uuid4().hex.encode()
    try:
        conn.sendall(token)
        received = b""
        while len(received) < len(token):
            part = conn.recv(len(token) - len(received))
            if not part:
                return False
            received += part
        return received == token
    except OSError:
        return False
def probe():
    fresh = False
    try:
        with socket.create_connection(address, timeout=0.35) as conn:
            fresh = exchange(conn)
    except OSError:
        pass
    return {"new_tcp": fresh, "established_tcp": None if existing is None else exchange(existing)}
control = socket.socket(socket.AF_UNIX)
control.bind("/tmp/quarantine-workload.sock")
os.chmod("/tmp/quarantine-workload.sock", 0o600)
control.listen()
while True:
    conn, _ = control.accept()
    with conn:
        request = json.loads(conn.makefile("rb").readline())
        status = dict(line.split(":", 1) for line in pathlib.Path("/proc/self/status").read_text().splitlines())
        reply = {"boot": boot, "uid": os.geteuid(), "cap_eff": status["CapEff"].strip(),
                 "netns": os.readlink("/proc/self/ns/net")}
        if request["op"] == "establish":
            try:
                existing = socket.create_connection(address, timeout=0.35)
                reply["established"] = exchange(existing)
            except OSError:
                reply["established"] = False
        elif request["op"] == "probe":
            reply.update(probe())
        conn.sendall(json.dumps(reply).encode() + b"\n")
'''

WORKLOAD_CLIENT = r'''
import json, socket, sys
with socket.socket(socket.AF_UNIX) as conn:
    conn.settimeout(5)
    conn.connect("/tmp/quarantine-workload.sock")
    conn.sendall(json.dumps({"op": sys.argv[1]}).encode() + b"\n")
    print(conn.makefile("r").readline().strip())
'''

FENCE_OBSERVER = r'''
import json, os, subprocess
namespace = os.readlink("/proc/self/ns/net")
result = subprocess.run(["nft", "-j", "list", "ruleset", "inet"],
                        check=True, capture_output=True, text=True)
print(json.dumps({"netns": namespace, "ruleset": json.loads(result.stdout)}))
'''


class Failure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def fence_present(data):
    """Require the exact independent, unconditional inet fence or true absence."""
    require(isinstance(data, dict) and set(data) == {"nftables"}, "invalid nft JSON envelope")
    require(isinstance(data["nftables"], list), "invalid nft JSON entries")
    owned = []
    for entry in data["nftables"]:
        require(isinstance(entry, dict) and len(entry) == 1, "invalid nft entry")
        kind, obj = next(iter(entry.items()))
        require(isinstance(obj, dict), "invalid nft object")
        if obj.get("family") == "inet" and obj.get("name" if kind == "table" else "table") == "opensandbox_quarantine":
            owned.append((kind, obj))
    if not owned:
        return False
    require(len(owned) == 7, "fence must contain exactly one table, three chains and three rules")
    tables, chains, rules = [], {}, {}
    for kind, obj in owned:
        if kind == "table":
            require(set(obj) <= {"family", "name", "handle", "comment", "flags"}, "unknown fence table property")
            require(obj.get("comment") == "opensandbox quarantine v1" and obj.get("flags", []) == [],
                    "fence has wrong owner or nonempty flags")
            tables.append(obj)
        elif kind == "chain":
            require(set(obj) <= {"family", "table", "name", "handle", "type", "hook", "prio", "policy"},
                    "unknown fence chain property")
            name = obj.get("name")
            require(name in ("input", "output", "forward") and name not in chains, "invalid fence chain")
            require((obj.get("type"), obj.get("hook"), obj.get("prio"), obj.get("policy")) ==
                    ("filter", name, -450, "drop"), "fence base hook is not fail-closed")
            chains[name] = obj
        elif kind == "rule":
            require(set(obj) <= {"family", "table", "chain", "handle", "expr"}, "unknown fence rule property")
            name = obj.get("chain")
            require(name in ("input", "output", "forward") and name not in rules, "invalid fence rule")
            require(obj.get("expr") == [{"drop": None}], "fence contains a conditional rule or exception")
            rules[name] = obj
        else:
            raise Failure("unexpected fence object: " + kind)
    require(len(tables) == 1 and set(chains) == set(rules) == {"input", "output", "forward"},
            "fence is missing required hooks")
    return True


def processes(snapshot, role):
    return [p for p in snapshot["processes"] if p["role"] == role]


def journal(snapshot):
    value = snapshot["files"]["journal.json"]
    require(value is not None, "journal is absent")
    return json.loads(bytes.fromhex(value["hex"]))


def journal_identity(record):
    return record["bootID"], record["netnsDev"], record["netnsInode"]


def namespace_identity(snapshot):
    return snapshot["host_boot_id"], snapshot["netns_dev"], snapshot["netns_inode"]


def assert_bound_journal(snapshot):
    record = journal(snapshot)
    require(record["version"] == 2 and journal_identity(record) == namespace_identity(snapshot),
            "journal is not bound to the actual original boot/network namespace identity")


def assert_restart_journal(before, after):
    """A mismatch may quarantine metadata, but must never rebind or replay it."""
    old, current = journal(before), journal(after)
    require(old["version"] == current["version"] == 2 and old["incarnation"] == current["incarnation"]
            and journal_identity(current) == journal_identity(old),
            "restart replaced the original journal incarnation or namespace identity")
    split = namespace_identity(before) != namespace_identity(after)
    if split:
        require(current == {**old, "phase": "quarantine", "reason": "namespace-mismatch/rebuild-required"},
                "namespace mismatch must persist quarantine/rebuild-required metadata")
        for name, value in before["files"].items():
            if name != "journal.json":
                require(after["files"][name] == value, "namespace mismatch changed unrelated lifecycle files")
    else:
        require(after["files"] == before["files"], "same-namespace restart modified or replayed durable state")
    return split


def assert_process_chain(snapshot, mitm):
    owners, workers, children = (processes(snapshot, role) for role in ("supervisor", "worker", "mitmdump"))
    require(len(owners) == 1 and owners[0]["pid"] == 1, "real supervisor must be PID 1")
    require(len(workers) == 1 and workers[0]["ppid"] == 1, "real Go worker must be the supervisor child")
    if mitm:
        require(len(children) == 1, "exactly one real mitmdump must be alive")
        require(children[0]["uid"] == 10042 and children[0]["ppid"] == workers[0]["pid"],
                "mitmdump must run as its dedicated user and be the Go worker's child")
    else:
        require(not children, "mitmdump launched before the expected bootstrap boundary")


class Docker:
    def __init__(self, artifacts):
        self.artifacts = artifacts

    def run(self, *args, check=True, timeout=30):
        command = ["docker", *map(str, args)]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Failure(f"Docker prerequisite/command failed: {command[:3]}: {exc}") from exc
        with (self.artifacts / "commands.jsonl").open("a") as stream:
            stream.write(json.dumps({"command": command, "returncode": result.returncode,
                                     "stdout": result.stdout, "stderr": result.stderr}) + "\n")
        if check and result.returncode:
            raise Failure(f"docker {' '.join(map(str, args[:3]))} failed ({result.returncode}): "
                          f"{result.stdout[-3000:]}{result.stderr[-3000:]}")
        return result

    def json(self, *args):
        return json.loads(self.run(*args).stdout)


class Sidecar:
    def __init__(self, docker, image, name):
        self.docker, self.image = docker, image
        self.name = "egress-quarantine-" + name + "-" + uuid.uuid4().hex[:10]
        self.volume = self.name + "-state"
        self.identity = str(uuid.uuid4())
        self.created = False
        self.volume_created = False
        self.artifacts = docker.artifacts / name
        self.artifacts.mkdir()

    def helper(self, *args, entrypoint=EGRESS, check=True):
        return self.docker.run("run", "--rm", "--network", "none", "--cap-drop", "ALL", "--read-only",
            "--mount", f"type=volume,src={self.volume},dst={STATE}",
            "--env", "OPENSANDBOX_EGRESS_QUARANTINE_ID=" + self.identity,
            "--entrypoint", entrypoint, self.image, *args, check=check)

    def provision(self):
        self.docker.run("volume", "create", "--label", "opensandbox.quarantine-image-test=true", self.volume)
        self.volume_created = True
        self.helper("--provision-quarantine")
        snapshot = json.loads(self.helper("-c", SNAPSHOT, entrypoint="python3").stdout)
        require(snapshot["directory"] == {"mode": 0o700, "uid": 0, "gid": 0}, "journal directory is not private root-owned")
        for name in ("journal.json", "journal.lock"):
            value = snapshot["files"][name]
            require(value and all(value[key] == expected for key, expected in
                {"mode": 0o600, "uid": 0, "gid": 0, "nlink": 1, "regular": True}.items()),
                f"{name} is not an exclusive, private root-owned regular file")
        require(journal(snapshot) == {"version": 2, "incarnation": self.identity, "phase": "fresh", "operation": "",
                                      "bootID": "", "netnsDev": 0, "netnsInode": 0, "reason": ""},
                "provision did not create the expected fresh metadata-only journal")
        self.provisioned = snapshot

    def start(self, stage=None, invalid=None):
        if invalid in ("missing-record", "missing-lock", "corrupt"):
            target = "journal.lock" if invalid == "missing-lock" else "journal.json"
            mutation = f"from pathlib import Path; p=Path('{STATE}/{target}'); "
            mutation += "p.write_bytes(b'{invalid-json\\n')" if invalid == "corrupt" else "p.unlink()"
            self.helper("-c", mutation, entrypoint="python3")
        self.before = json.loads(self.helper("-c", SNAPSHOT, entrypoint="python3").stdout)
        identity = str(uuid.uuid4()) if invalid == "identity-mismatch" else self.identity
        mount = f"type=volume,src={self.volume},dst={STATE}" + (",readonly" if invalid == "readonly" else "")
        args = ["create", "--name", self.name, "--network", "none", "--cap-drop", "NET_RAW",
                "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges", "--mount", mount]
        env = {"OPENSANDBOX_EGRESS_QUARANTINE_ID": identity,
               "OPENSANDBOX_EGRESS_EXPERIMENTAL_REVISION_RUNTIME": "true",
               "OPENSANDBOX_EGRESS_MODE": "dns+nft",
               "OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT": "true",
               "OPENSANDBOX_EGRESS_RULES": '{"defaultAction":"deny","egress":[]}',
               "OPENSANDBOX_EGRESS_DNS_UPSTREAM": "1.1.1.1:53"}
        if stage:
            env["OPENSANDBOX_EGRESS_TEST_QUARANTINE_PAUSE"] = stage
        for key, value in env.items():
            args += ["--env", key + "=" + value]
        self.container_id = self.docker.run(*args, self.image).stdout.strip()
        self.created = True
        info = self.docker.json("inspect", self.name)[0]
        host = info["HostConfig"]
        require(info["Config"]["Entrypoint"] == ENTRYPOINT, "sidecar must use the image's real entrypoint")
        require(not host["Privileged"] and host["NetworkMode"] == "none" and not host["PidMode"],
                "sidecar must have isolated network/PID namespaces without privileged mode")
        require(host["CapAdd"] == ["NET_ADMIN"] and host["CapDrop"] == ["NET_RAW"], "unexpected runtime capabilities")
        mounts = [m for m in info["Mounts"] if m["Destination"] == STATE]
        require(len(mounts) == 1 and mounts[0]["Type"] == "volume" and mounts[0]["Name"] == self.volume
                and mounts[0]["RW"] == (invalid != "readonly"), "journal must be the intended private named volume")
        self.docker.run("start", self.name)

    def snapshot(self):
        return self.docker.json("exec", self.name, "python3", "-c", SNAPSHOT)

    def logs(self):
        result = self.docker.run("logs", self.name)
        return result.stdout + result.stderr

    def fence(self):
        return fence_present(self.docker.json("exec", self.name, "nft", "-j", "list", "ruleset", "inet"))

    def health(self):
        result = self.docker.run("exec", self.name, "curl", "--noproxy", "*", "--silent",
            "--output", "/dev/null", "--write-out", "%{http_code}", "--max-time", "1",
            "http://127.0.0.1:18080/healthz", check=False)
        require(result.returncode in (0, 7, 28), "health probe could not execute: " + result.stderr)
        return result.stdout

    def wait(self, description, predicate, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = predicate()
            if result:
                return result
            info = self.docker.json("inspect", self.name)[0]
            require(info["State"]["Running"], f"container exited while waiting for {description}")
            time.sleep(0.2)
        raise Failure(f"timed out waiting for {description}")

    def checkpoint(self, stage):
        def reached():
            snapshot = self.snapshot()
            value = snapshot["files"]["checkpoint"]
            return snapshot if value and bytes.fromhex(value["hex"]).decode() == stage else None
        return self.wait("test-build checkpoint " + stage, reached)

    def kill(self, role):
        selected = processes(self.snapshot(), role)
        require(len(selected) == 1, "SIGKILL target must be one exact " + role)
        self.docker.run("exec", self.name, "kill", "-KILL", str(selected[0]["pid"]))

    def assert_refused(self, expected_starts, prior_failures=0):
        # Two distinct rejected prestarts prove that retry did not become a
        # successful second launch. We do not wait for the crashloop breaker,
        # which would destroy the namespace and prevent netlink verification.
        self.wait("two refused prestart attempts", lambda: self.logs().count(GUARD_FAILURE) >= prior_failures + 2, timeout=30)
        snapshot = self.snapshot()
        require(not processes(snapshot, "worker"), "guard allowed another Go worker")
        require(self.logs().count(WORKER_STARTED) == expected_starts, "supervisor launched a forbidden worker")
        require(self.fence(), "failed guard did not retain/re-establish the independent fence")
        require(self.health() != "200", "refused sidecar became ready")
        return snapshot

    def restart_and_refuse(self, expected_starts, bound=False):
        before = self.snapshot()
        failures = self.logs().count(GUARD_FAILURE)
        self.docker.run("restart", "--time", "1", self.name, timeout=40)
        require(self.docker.json("inspect", self.name)[0]["Id"] == self.container_id,
                "restart test must reuse the exact same Docker container")
        after = self.assert_refused(expected_starts, failures)
        if bound:
            if assert_restart_journal(before, after):
                require("QuarantineUnknown: rebuild-required" in self.logs(),
                        "split-namespace restart must explicitly report QuarantineUnknown/rebuild-required")
        else:
            require(after["files"] == before["files"], "container restart modified or replayed durable state")
        return after

    def collect(self):
        if not self.created:
            return
        for name, args in (("logs.txt", ("logs", self.name)),
                           ("inspect.json", ("inspect", self.name)),
                           ("snapshot.json", ("exec", self.name, "python3", "-c", SNAPSHOT)),
                           ("ruleset.json", ("exec", self.name, "nft", "-j", "list", "ruleset"))):
            result = self.docker.run(*args, check=False)
            (self.artifacts / name).write_text(result.stdout + result.stderr)

    def close(self):
        # Only unique names created by this test are ever deleted.
        if self.created:
            self.docker.run("rm", "--force", self.name, check=False)
        if self.volume_created:
            self.docker.run("volume", "rm", self.volume, check=False)


class Workload:
    """Survives sidecar death without privileges or access to its journal."""

    def __init__(self, sidecar):
        self.sidecar = sidecar
        self.docker = sidecar.docker
        self.name = sidecar.name + "-workload"
        self.created = False
        self.had_existing = False

    def __enter__(self):
        try:
            self.container_id = self.docker.run("create", "--name", self.name,
                "--network", "container:" + self.sidecar.name, "--user", "1000:1000",
                "--cap-drop", "ALL", "--read-only", "--security-opt", "no-new-privileges",
                "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,mode=1777", "--entrypoint", "python3",
                self.sidecar.image, "-u", "-c", WORKLOAD).stdout.strip()
            self.created = True
            info = self.docker.json("inspect", self.name)[0]
            host = info["HostConfig"]
            require(info["Config"]["User"] == "1000:1000" and host["CapDrop"] == ["ALL"]
                    and not host["CapAdd"] and not host["Privileged"], "workload must be unprivileged UID 1000")
            require(host["NetworkMode"].startswith("container:") and not host["PidMode"],
                    "workload must share only the sidecar network namespace")
            require(not any(m["Destination"] == STATE or m["Type"] == "volume" for m in info["Mounts"]),
                    "workload must have no journal or named volume access")
            self.docker.run("start", self.name)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                result = self.docker.run("exec", self.name, "python3", "-c", WORKLOAD_CLIENT, "status", check=False)
                if result.returncode == 0:
                    self.original = json.loads(result.stdout)
                    break
                require(self.docker.json("inspect", self.name)[0]["State"]["Running"], "workload process exited")
                time.sleep(0.1)
            else:
                raise Failure("unprivileged workload control socket did not become ready")
            require(self.original["uid"] == 1000 and int(self.original["cap_eff"], 16) == 0,
                    "workload has unexpected effective credentials")
            require(self.original["netns"] == self.sidecar.snapshot()["netns"],
                    "workload did not join the original sidecar namespace")
            self.record("workload-original", self.original)
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def __exit__(self, *_):
        if not self.created:
            return
        try:
            for label, args in (("workload-inspect.json", ("inspect", self.name)),
                                ("workload-logs.txt", ("logs", self.name))):
                result = self.docker.run(*args, check=False)
                (self.sidecar.artifacts / label).write_text(result.stdout + result.stderr)
        finally:
            self.docker.run("rm", "--force", self.name, check=False)

    def record(self, label, value):
        (self.sidecar.artifacts / (label + ".json")).write_text(json.dumps(value, indent=2) + "\n")

    def call(self, operation):
        value = self.docker.json("exec", self.name, "python3", "-c", WORKLOAD_CLIENT, operation)
        require(all(value.get(key) == self.original[key] for key in ("boot", "uid", "cap_eff", "netns")),
                "workload process or its original namespace was replaced")
        require(self.docker.json("inspect", self.name)[0]["Id"] == self.container_id,
                "workload must survive as the exact same container")
        return value

    def fence(self):
        # The observer has NET_ADMIN only in the already-owned workload netns.
        # Verify its ACTUAL namespace before trusting the nft readback; Docker's
        # requested --network target alone is not evidence of where it ran.
        # It runs nft list, never a rule mutation, and mounts no journal data.
        data = self.docker.json("run", "--rm", "--network", "container:" + self.name,
            "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--read-only", "--entrypoint", "python3",
            self.sidecar.image, "-c", FENCE_OBSERVER)
        self.record("workload-fence-observer", data)
        require(data.get("netns") == self.original["netns"],
                "fence observer ran in the wrong namespace: expected " + self.original["netns"] +
                ", observed " + str(data.get("netns")))
        self.record("workload-ruleset", data["ruleset"])
        return fence_present(data["ruleset"])

    def establish(self):
        require(self.call("establish")["established"], "workload could not establish its positive-control TCP flow")
        self.had_existing = True
        probe = self.call("probe")
        self.record("workload-positive-control", probe)
        require(probe["new_tcp"] and probe["established_tcp"], "workload packet positive controls failed")

    def observe(self, label):
        probe = self.call("probe")
        sidecar_namespace = self.sidecar.snapshot()["netns"]
        diverged = probe["netns"] != sidecar_namespace
        evidence = {"workload": probe, "sidecar_netns": sidecar_namespace,
                    "namespace_diverged": diverged, "fenced": None,
                    "current_namespace_fenced": self.sidecar.fence(),
                    "scope": "Observed Docker daemon only; endpoint removal is not a cross-runtime isolation guarantee"}
        self.record(label, evidence)
        try:
            fenced = self.fence()
        except Failure as exc:
            evidence["fence_readback_error"] = str(exc)
            self.record(label, evidence)
            raise Failure("original workload fence readback is unconfirmed: sidecar " + sidecar_namespace +
                          ", original workload " + probe["netns"] + ": " + str(exc)) from exc
        evidence["fenced"] = fenced
        self.record(label, evidence)
        if diverged:
            print("DIAGNOSTIC: namespace divergence: sidecar " + sidecar_namespace +
                  ", original surviving workload " + probe["netns"] +
                  f"; original fenced={fenced}, new_tcp={probe['new_tcp']}, "
                  f"established_tcp={probe['established_tcp']}", flush=True)
        return evidence

    def assert_contained(self, label):
        evidence = self.observe(label)
        self.assert_blocked(evidence)

    def assert_blocked(self, evidence):
        probe = evidence["workload"]
        # A restart may get a different namespace while the surviving workload
        # retains the old one. Quarantine-only succeeds only from independent
        # evidence about that ORIGINAL namespace, never the new sidecar's fence.
        require(evidence["fenced"], "original surviving workload namespace has no confirmed fence")
        existing_blocked = probe["established_tcp"] is False if self.had_existing else probe["established_tcp"] in (False, None)
        require(not probe["new_tcp"] and existing_blocked,
                "original surviving workload still delivers new or established TCP packets")

    def assert_rebuild_boundary(self, before, after, label):
        split = assert_restart_journal(before, after)
        evidence = self.observe(label)
        evidence["journal_before"] = journal(before)
        evidence["journal_after"] = journal(after)
        evidence["original_namespace_identity"] = namespace_identity(before)
        evidence["current_namespace_identity"] = namespace_identity(after)
        require(split == evidence["namespace_diverged"], "journal and workload namespace observations disagree")
        require(not processes(after, "worker") and self.sidecar.health() != "200",
                "whole-container restart relaunched a worker or published readiness")
        require(evidence["current_namespace_fenced"], "current sidecar namespace has no confirmed fence")
        if split:
            require("QuarantineUnknown: rebuild-required" in self.sidecar.logs(),
                    "split-namespace restart must explicitly report QuarantineUnknown/rebuild-required")
            # Deliberately do not claim or require an old-netns fence here. A
            # restarted container has no authority over a surviving workload's
            # disconnected namespace. The supported result is explicit rebuild
            # refusal, with old packet observations retained as evidence.
            evidence["outcome"] = "QuarantineUnknown/rebuild-required; old workload isolation not established"
            print("REBUILD REQUIRED: original workload namespace isolation is not established; "
                  "old TCP observations are diagnostic, not a cross-runtime containment guarantee", flush=True)
        else:
            self.assert_blocked(evidence)
            evidence["outcome"] = "same-namespace packet quarantine confirmed"
        self.record(label, evidence)


@contextmanager
def sidecar(docker, image, name):
    fixture = Sidecar(docker, image, name)
    try:
        fixture.provision()
        yield fixture
    finally:
        try:
            fixture.collect()
        finally:
            fixture.close()


def test_bootstrap(docker, image):
    with sidecar(docker, image, "bootstrap") as s:
        # Provision is exclusive; even the trusted helper has no reset path.
        result = s.helper("--provision-quarantine", check=False)
        require(result.returncode != 0, "repeat provision overwrote a live journal")
        require(json.loads(s.helper("-c", SNAPSHOT, entrypoint="python3").stdout)["files"] == s.provisioned["files"],
                "repeat provision changed the fresh journal")
        s.start()
        s.wait("successful real MITM bootstrap", lambda: s.health() == "200")
        snapshot = s.snapshot()
        assert_process_chain(snapshot, mitm=True)
        assert_bound_journal(snapshot)
        require(journal(snapshot)["phase"] == "running", "readiness preceded durable running state")
        require(not s.fence(), "successful bootstrap left the fence installed")
        require(s.logs().count(WORKER_STARTED) == 1 and "[egress-cleanup] done" in s.logs(),
                "the real prestart/supervisor path did not execute")
        # A child crash must contain traffic and must not start another child.
        child = processes(snapshot, "mitmdump")[0]["pid"]
        s.kill("mitmdump")
        s.wait("MITM crash quarantine", lambda: journal(s.snapshot())["phase"] == "quarantine", timeout=30)
        require(s.fence() and s.health() != "200", "MITM death did not fail closed")
        time.sleep(2)
        remaining = processes(s.snapshot(), "mitmdump")
        require(not remaining, f"MITM {child} death was followed by an unauthorized child restart")
        require(len(processes(s.snapshot(), "worker")) == 1, "MITM crash unexpectedly replaced the Go worker")


def test_crash(docker, image, stage):
    with sidecar(docker, image, stage) as s:
        s.start(stage=stage)
        snapshot = s.checkpoint(stage)
        phase, mitm, fenced = STAGES[stage]
        assert_process_chain(snapshot, mitm)
        assert_bound_journal(snapshot)
        require(journal(snapshot)["phase"] == phase, f"{stage}: wrong durable phase")
        require(s.fence() == fenced, f"{stage}: wrong pre-crash fence state")
        health = s.health()
        require(health != "200", f"{stage}: readiness published before final boundary")
        if not fenced:
            require(health == "503", f"{stage}: unfenced readiness gate must explicitly return 503")
        with Workload(s) as workload:
            if not fenced:
                workload.establish()
            else:
                workload.assert_contained("workload-before-worker-kill")
            s.kill("worker")
            after = s.assert_refused(expected_starts=1)
            require(namespace_identity(after) == namespace_identity(snapshot),
                    "Go-worker restart unexpectedly changed the original namespace")
            require(after["files"] == snapshot["files"], f"{stage}: guard repaired or replayed journal state")
            require(s.logs().count("[egress-cleanup] done") == 1, f"{stage}: failed guard continued destructive cleanup")
            workload.assert_contained("workload-after-worker-kill")
            s.restart_and_refuse(expected_starts=1, bound=True)
            workload.assert_contained("workload-after-container-restart")


def test_running_container_crash(docker, image):
    with sidecar(docker, image, "running-container-sigkill") as s:
        s.start()
        s.wait("Running sidecar before whole-container SIGKILL", lambda: s.health() == "200")
        before = s.snapshot()
        assert_process_chain(before, mitm=True)
        assert_bound_journal(before)
        require(journal(before)["phase"] == "running" and not s.fence(), "positive control must start unfenced and Running")
        with Workload(s) as workload:
            workload.establish()
            require(not workload.fence(), "original workload unexpectedly fenced before SIGKILL")
            docker.run("kill", "--signal", "KILL", s.name)
            deadline = time.monotonic() + 10
            while docker.json("inspect", s.name)[0]["State"]["Running"]:
                require(time.monotonic() < deadline, "whole sidecar container survived SIGKILL")
                time.sleep(0.1)
            # Capture the kill-to-prestart interval honestly. A process-local
            # fence cannot be installed by a dead sidecar. Do not substitute a
            # new namespace or silently kill the workload to hide this window.
            workload.record("workload-after-container-kill", workload.call("probe"))
            docker.run("restart", "--time", "1", s.name, timeout=40)
            require(docker.json("inspect", s.name)[0]["Id"] == s.container_id,
                    "whole-container test must restart the exact original sidecar")
            after = s.assert_refused(expected_starts=1)
            workload.assert_rebuild_boundary(before, after, "workload-after-running-container-restart")


def test_invalid_state(docker, image, invalid):
    with sidecar(docker, image, invalid) as s:
        s.start(invalid=invalid)
        after = s.assert_refused(expected_starts=0)
        require(after["files"] == s.before["files"], f"{invalid}: guard created or repaired invalid state")
        require(not processes(after, "mitmdump"), f"{invalid}: mitmdump launched despite invalid state")
        require("[egress-cleanup] done" not in s.logs(), f"{invalid}: cleanup continued after guard failure")
        s.restart_and_refuse(expected_starts=0)


def required_cases():
    return ["TestSidecarImagePrerequisites", "TestSidecarRealBootstrapAndMitmCrash",
            "TestSidecarRunningContainerSIGKILLRebuildBoundary"] + [
        "TestSidecarSIGKILL_" + stage.replace("-", "_") for stage in STAGES] + [
        "TestSidecarUnsafeJournal_" + value.replace("-", "_") for value in INVALID_STATES]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", help="existing test-only image built with egress_quarantine_faults")
    parser.add_argument("--artifacts", type=Path, help="directory for logs and machine-readable evidence")
    args = parser.parse_args(argv)
    artifacts = args.artifacts or Path(tempfile.mkdtemp(prefix="egress-quarantine-image-"))
    artifacts.mkdir(parents=True, exist_ok=True)
    docker = Docker(artifacts)
    image = args.image or "opensandbox-egress-quarantine-test:" + uuid.uuid4().hex[:12]
    results = []

    def run_case(name, action):
        print("=== RUN   " + name, flush=True)
        start = time.monotonic()
        record = {"name": name, "status": "RUN"}
        results.append(record)
        try:
            action()
        except Exception as exc:
            record.update(status="FAIL", error=str(exc))
            print(f"--- FAIL: {name}: {exc}", flush=True)
            raise
        record.update(status="PASS", seconds=round(time.monotonic() - start, 3))
        print(f"--- PASS: {name} ({record['seconds']:.3f}s)", flush=True)

    def prerequisites():
        require(shutil.which("docker") is not None, "Docker CLI is unavailable; real image tests did not run")
        info = docker.json("info", "--format", "{{json .}}")
        (artifacts / "docker-runtime.json").write_text(json.dumps(info, indent=2) + "\n")
        require(info["OSType"] == "linux", "real image tests require a Linux Docker daemon")
        require(not any("rootless" in value for value in info.get("SecurityOptions", [])),
                "real image tests require rootful Docker with NET_ADMIN and durable named volumes")
        if not args.image:
            docker.run("build", "-f", ROOT / "components/egress/Dockerfile", "--build-arg",
                       "GOFLAGS=-tags=egress_quarantine_faults", "-t", image, ROOT, timeout=1800)
        config = docker.json("image", "inspect", image)[0]
        require(config["Config"]["Entrypoint"] == ENTRYPOINT, "image has an unexpected entrypoint")
        docker.run("run", "--rm", "--network", "none", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
                   "--entrypoint", "nft", image, "-j", "list", "ruleset", "inet")

    success = False
    try:
        run_case("TestSidecarImagePrerequisites", prerequisites)
        run_case("TestSidecarRealBootstrapAndMitmCrash", lambda: test_bootstrap(docker, image))
        run_case("TestSidecarRunningContainerSIGKILLRebuildBoundary", lambda: test_running_container_crash(docker, image))
        for stage in STAGES:
            run_case("TestSidecarSIGKILL_" + stage.replace("-", "_"), lambda stage=stage: test_crash(docker, image, stage))
        for invalid in INVALID_STATES:
            run_case("TestSidecarUnsafeJournal_" + invalid.replace("-", "_"),
                     lambda invalid=invalid: test_invalid_state(docker, image, invalid))
        require([r["name"] for r in results] == required_cases() and all(r["status"] == "PASS" for r in results),
                "required real-image RUN/PASS evidence is incomplete")
        success = True
    except (Failure, ValueError, KeyError) as exc:
        print("Real quarantine image validation FAILED: " + str(exc), file=sys.stderr)
    finally:
        (artifacts / "results.json").write_text(json.dumps({"kind": "real-docker-image", "image": image,
            "passed": success, "required": required_cases(), "results": results}, indent=2) + "\n")
        print("Image validation artifacts: " + str(artifacts.resolve()), flush=True)
        if not args.image and shutil.which("docker"):
            docker.run("image", "rm", image, check=False)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
