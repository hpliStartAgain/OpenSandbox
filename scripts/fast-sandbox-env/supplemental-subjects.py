#!/usr/bin/env python3
# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0
"""Synthetic Actions v1 scale driver, executed inside one isolated egress.

Two real, colocated guests must already be active. They count toward the
requested total. HTTP 200 SET is registration only. A successful ready Hook
proves its current snapshot ACK and activation; failures remain counted.
All attempted identities are removed in finally. No identity enters output.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request
import uuid


def envelope(prefix, index, operation):
    ip = ipaddress.ip_address('198.18.0.2')+index
    return {'apiVersion': 'sandbox.fast.io/actions/v1', 'operation': operation,
            'invocationId': str(uuid.uuid4()),
            'sandbox': {'uid': prefix+'-'+str(index), 'name': 'supplemental', 'namespace': 'bench'},
            'revision': {'specGeneration': 1, 'runtimeInstanceId': prefix, 'attachmentId': 'a-'+str(index), 'routeGeneration': 1},
            'attachment': {'network': {'ip': str(ip), 'gateway': '198.18.0.1',
                           'privateCidr': '198.18.0.0/15', 'hostVeth': 'supscale0'}},
            'binding': {'input': json.dumps({'defaultAction': 'deny', 'egress': []})},
            'hook': {'name': 'sandbox.data-plane-ready', 'sequence': 1}}


def request(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except OSError:
        return 0


def reading():
    p = Path('/sys/fs/cgroup')
    relative = Path('/proc/self/cgroup').read_text().split('0::')[-1].strip()
    d = p/relative.lstrip('/')
    if not (d/'memory.current').is_file():
        d = p
    out = {'memory_current': int((d/'memory.current').read_text())}
    for file, keys in [('memory.stat', ['anon']), ('cpu.stat', ['usage_usec'])]:
        values = dict(line.split() for line in (d/file).read_text().splitlines())
        out.update({k: int(values[k]) for k in keys})
    try:
        nft = json.loads(subprocess.check_output(['nft', '-j', 'list', 'ruleset'], timeout=20))
        out['nft_rules'] = sum('rule' in x for x in nft['nftables'])
    except (OSError, ValueError, subprocess.SubprocessError):
        out['nft_rules'] = None
    return out


def run(args):
    prefix = 'supplemental-'+uuid.uuid4().hex
    registered, active, attempted, points = set(), set(), [], []
    result = {'v': 1, 'points': points, 'cleanup_ok': False, 'recovery_ok': None}
    try:
        for target in args.steps:
            registration_ms = activation_ms = 0
            for i in range(len(attempted), target-args.real_subjects):
                attempted.append(i)
                t = time.monotonic()
                if request(args.url, envelope(prefix, i, 'SET_BINDING')) == 200:
                    registered.add(i)
                registration_ms += (time.monotonic()-t)*1000
                if i in registered:
                    t = time.monotonic()
                    for attempt in range(args.retries):
                        if request(args.url, envelope(prefix, i, 'LIFECYCLE_HOOK')) == 200:
                            active.add(i)
                            break
                        time.sleep(.1)
                    activation_ms += (time.monotonic()-t)*1000
            points.append(dict(target=target, registered=len(registered)+args.real_subjects,
                               acked=len(active)+args.real_subjects, active=len(active)+args.real_subjects,
                               registration_ms=registration_ms, activation_ms=activation_ms, **reading()))
            # A host-side probe can exercise the real pair at this exact scale.
            if args.control_dir:
                d = Path(args.control_dir)
                d.mkdir(exist_ok=True)
                (d/'scale').write_text(str(target))
                deadline = time.monotonic()+120
                while not (d/('continue-'+str(target))).exists():
                    if time.monotonic()>deadline:
                        raise TimeoutError('probe controller missing')
                    time.sleep(.1)
        if args.steps[-1] > 4096 and active:
            victim = min(active)
            removed = request(args.url, envelope(prefix, victim, 'REMOVE_BINDING')) == 200
            active.discard(victim)
            overflow = max(registered)
            result['recovery_ok'] = False
            if removed:
                # Removal publishes asynchronously; retry the same fence.
                for attempt in range(50):
                    if request(args.url, envelope(prefix, overflow, 'SET_BINDING')) == 200 and request(args.url, envelope(prefix, overflow, 'LIFECYCLE_HOOK')) == 200:
                        result['recovery_ok'] = True
                        break
                    time.sleep(.1)
    finally:
        removed = [request(args.url, envelope(prefix, i, 'REMOVE_BINDING')) == 200 for i in attempted]
        result['cleanup_ok'] = all(removed)
        Path(args.out).write_text(json.dumps(result))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--url', default='http://127.0.0.1:18080/_fastlet/v1/actions')
    p.add_argument('--steps', type=int, nargs='+', default=[256, 1024, 2048, 4096, 4097])
    p.add_argument('--real-subjects', type=int, default=2)
    p.add_argument('--retries', type=int, default=20)
    p.add_argument('--control-dir', default='')
    p.add_argument('--out', required=True)
    a = p.parse_args()
    if sorted(set(a.steps)) != a.steps or not 2 <= min(a.steps) <= max(a.steps) <= 4097:
        p.error('steps must be strictly increasing in 2..4097')
    run(a)


if __name__ == '__main__':
    main()
