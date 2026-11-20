#!/usr/bin/env python3
# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0
"""Sample one container cgroup at the shared fixture's scheduled boundaries."""
import argparse
import json
from pathlib import Path
import time
import urllib.request


def cgroup():
    root=Path('/sys/fs/cgroup')
    relative=Path('/proc/self/cgroup').read_text().split('0::')[-1].strip()
    candidate=root/relative.lstrip('/')
    return candidate if (candidate/'memory.current').is_file() else root


def reading():
    d=cgroup()
    out=dict(captured_at_s=time.time(),memory_current=int((d/'memory.current').read_text()))
    for file,keys in [('memory.stat',['anon']),('cpu.stat',['usage_usec','nr_throttled','throttled_usec']),('memory.events',['oom_kill'])]:
        values=dict(line.split() for line in (d/file).read_text().splitlines())
        out.update({k:int(values[k]) for k in keys})
    out['fd']=sum(len(list(p.iterdir())) for p in Path('/proc').glob('[0-9]*/fd') if p.exists())
    try: out['conntrack']=int(Path('/proc/sys/net/netfilter/nf_conntrack_count').read_text())
    except OSError: out['conntrack']=None
    return out


def wait_until(at):
    time.sleep(max(0,at-time.time()))


def run(a):
    with urllib.request.urlopen(a.gate_url+'/wait/'+a.gate_key+'/'+a.participant,timeout=300) as response:
        release=json.load(response)
    # All containers on this host share CLOCK_REALTIME. Guests use the
    # fixture timestamp to translate the gate into their monotonic clock.
    at=release['start_at_s']
    wait_until(at); first=reading()
    wait_until(at+a.duration); last=reading()
    print(json.dumps(dict(start=first,end=last,scheduled_start_s=at)),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--gate-url',required=True);p.add_argument('--gate-key',required=True)
    p.add_argument('--participant',required=True);p.add_argument('--duration',type=float,required=True)
    run(p.parse_args())
