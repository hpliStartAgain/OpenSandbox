#!/usr/bin/env python3
# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0
"""Synthetic Actions v1 scale driver, executed outside the measured egress cgroup.

Two real, colocated guests must already be active. They count toward the
requested total. HTTP 200 SET is registration only. A successful ready Hook
proves its current snapshot ACK and activation; failures remain counted.
All attempted identities are removed in finally. No identity enters output.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import os
import resource
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
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except OSError:
        return 0


def status_reasons(url):
    # Closed status vocabulary; response bodies and identity fields stay private.
    try:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url.rstrip('/')+'/status',timeout=30) as response:
            reasons=json.load(response).get('subjectLifecycleDegraded',[])
        return [v for v in reasons if v=='subject_capacity_exhausted']
    except (OSError,ValueError,TypeError):
        return None


def driver_cost():
    # This process runs in the task runner cgroup. It never reads the
    # egress cgroup; product snapshots are supplied by the host controller.
    rss=None
    try:
        rss=int(next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('VmRSS:')))*1024
    except (OSError,StopIteration):
        pass
    return dict(cpu_s=time.process_time(),rss_bytes=rss,maxrss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


def run(args):
    prefix = 'supplemental-'+uuid.uuid4().hex
    registered, active, attempted, points = set(), set(), [], []
    result = {'v': 1, 'points': points, 'cleanup_ok': False, 'recovery_ok': None}
    try:
        for target in args.steps:
            registration_ms = activation_ms = 0
            before=status_reasons(args.url)
            rejections=[]
            for i in range(len(attempted), target-args.real_subjects):
                attempted.append(i)
                t = time.monotonic()
                set_code=request(args.url, envelope(prefix, i, 'SET_BINDING'))
                if set_code == 200:
                    registered.add(i)
                ready_codes=[]
                registration_ms += (time.monotonic()-t)*1000
                if i in registered:
                    t = time.monotonic()
                    for attempt in range(args.retries):
                        ready_code=request(args.url, envelope(prefix, i, 'LIFECYCLE_HOOK'))
                        ready_codes.append(ready_code)
                        if ready_code == 200:
                            active.add(i)
                            break
                        time.sleep(.1)
                    activation_ms += (time.monotonic()-t)*1000
                if i not in active:
                    after=status_reasons(args.url)
                    capacity_before='subject_capacity_exhausted' in before if before is not None else None
                    capacity_after='subject_capacity_exhausted' in after if after is not None else None
                    rejections.append(dict(object_index=i,phase='initial',stage='ready' if i in registered else 'SET',
                        set_status=set_code,ready_status=ready_codes[-1] if ready_codes else None,
                        ready_attempt_statuses=ready_codes,capacity_before=capacity_before,capacity_after=capacity_after,
                        reason='subject_capacity_exhausted' if capacity_before is False and capacity_after is True else None,
                        attribution='isolated_serial_action_status_transition'))
            points.append(dict(target=target, registered=len(registered)+args.real_subjects,
                               acked=len(active)+args.real_subjects, active=len(active)+args.real_subjects,
                               registration_ms=registration_ms, activation_ms=activation_ms, driver_cost=driver_cost(),
                               rejections=rejections,capacity_rejections=sum(x['reason']=='subject_capacity_exhausted' for x in rejections)))
            # A host-side probe can exercise the real pair at this exact scale.
            if args.control_dir:
                d = Path(args.control_dir)
                d.mkdir(exist_ok=True)
                temp=d/'scale.tmp';temp.write_text(str(target));os.replace(temp,d/'scale')
                deadline = time.monotonic()+120
                while not (d/('continue-'+str(target))).exists():
                    if time.monotonic()>deadline:
                        raise TimeoutError('probe controller missing')
                    time.sleep(.1)
        if args.steps[-1] > 4096:
            pending=set(attempted)-active
            result['recovery_ok']=False
            recovery=dict(object_index=min(pending) if len(pending)==1 else None,
                          release_confirmed=False,release_attempts=[],attempts=[])
            result['recovery']=recovery
            if len(pending)==1 and active:
                overflow=min(pending);victim=min(active)
                recovery['released_object_index']=victim
                # REMOVE 200 confirms local enforcement cleanup; a ready 409
                # verifies that the same fenced victim is no longer registered.
                for attempt in range(50):
                    code=request(args.url,envelope(prefix,victim,'REMOVE_BINDING'))
                    gone=request(args.url,envelope(prefix,victim,'LIFECYCLE_HOOK')) if code==200 else None
                    recovery['release_attempts'].append(dict(remove_status=code,ready_status=gone))
                    if code==200 and gone==409:
                        recovery['release_confirmed']=True
                        active.discard(victim);registered.discard(victim)
                        break
                    time.sleep(.1)
                if recovery['release_confirmed']:
                    for attempt in range(50):
                        set_code=request(args.url,envelope(prefix,overflow,'SET_BINDING'))
                        ready_code=request(args.url,envelope(prefix,overflow,'LIFECYCLE_HOOK')) if set_code==200 else None
                        recovery['attempts'].append(dict(set_status=set_code,ready_status=ready_code))
                        if set_code==200 and ready_code==200:
                            registered.add(overflow);active.add(overflow)
                            result['recovery_ok']=True
                            break
                        time.sleep(.1)
            recovery['final_counts']=dict(registered=len(registered)+args.real_subjects,
                acked=len(active)+args.real_subjects,active=len(active)+args.real_subjects)
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
