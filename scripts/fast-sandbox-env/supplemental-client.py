#!/usr/bin/env python3
# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0
"""Async closed-loop TLS load and synchronous-start burst client; Python 3.9+.

Every successful response is classified by verified certificate and origin
credential. Never emits digests, peer names or arbitrary exception messages.
"""
import argparse
import copy
import errno
from collections import Counter
import asyncio
import hashlib
import json
import math
import os
import resource
from pathlib import Path
import ssl
import time


def error_kind(exc, phase):
    if isinstance(exc,OSError) and exc.errno in (errno.ENOMEM,errno.EMFILE,errno.ENFILE,errno.ENOBUFS,errno.EADDRNOTAVAIL):
        return 'client/resource_exhausted'
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        kind = 'timeout'
    elif isinstance(exc, ssl.SSLCertVerificationError):
        kind = 'verify_failed'
    elif isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
        kind = 'tls_closed'
    elif isinstance(exc, ssl.SSLError):
        kind = 'tls_error'
    elif isinstance(exc, ConnectionResetError):
        kind = 'reset'
    elif isinstance(exc, asyncio.IncompleteReadError):
        kind = 'eof'
    elif isinstance(exc, ConnectionRefusedError):
        kind = 'refused'
    else:
        kind = 'io_error'
    return phase + '/' + kind


def save(path, result):
    tmp = str(path)+'.tmp'
    Path(tmp).write_text(json.dumps(result, separators=(',', ':')))
    os.replace(tmp, path)


def summarize(values):
    ordered = sorted(values)
    n = len(ordered)
    if not n:
        return {'n': 0}
    return dict(n=n, mean=sum(ordered)/n, input_histogram_ms=dict(Counter(str(v) for v in ordered)), **{'p'+str(p).replace('.', '_'): ordered[max(0, math.ceil(n*p/100)-1)] for p in [50, 90, 99, 99.9]})


class Session:
    def __init__(self, args, context):
        self.args, self.context = args, context
        self.reader = self.writer = None
        self.leaf = 'none'
        self.origin_connection = None

    async def connect(self):
        start = time.monotonic()
        self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(
            self.args.ip, self.args.port, ssl=self.context, server_hostname=self.args.host), self.args.timeout)
        tls = self.writer.get_extra_info('ssl_object')
        digest = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
        self.leaf = 'origin' if digest == self.args.origin_leaf else 'mitm'
        return (time.monotonic()-start)*1000

    async def request(self):
        held_header='X-Bench-Held-Key: '+self.args.held_key+'\r\n' if self.args.held_key else ''
        self.writer.write(('GET /cbv?bytes=%d HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\nConnection: keep-alive\r\n%s\r\n'
                          % (self.args.body_bytes, self.args.host,held_header)).encode('ascii'))
        await self.writer.drain()
        header = await self.reader.readuntil(b'\r\n\r\n')
        lines = header.decode('iso-8859-1').split('\r\n')
        status = int(lines[0].split()[1])
        headers = dict(line.lower().split(':', 1) for line in lines[1:] if ':' in line)
        length = int(headers.get('content-length', '-1'))
        if not 0 <= length <= 65536:
            raise ValueError('invalid response length')
        body = await self.reader.readexactly(length)
        parsed = json.loads(body)
        self.origin_connection = parsed.get('conn')
        cred = parsed.get('cred')
        cred_class = 'absent' if cred == 'absent' else 'expected' if cred == self.args.expect_cred else 'other'
        expected_headers = [] if self.args.expect_cred == 'absent' else ['x-api-key']
        good = (self.args.body_bytes != 65536 or length == 65536) and parsed.get('credential_headers') == expected_headers and status == 200 and self.leaf == self.args.expect_leaf and cred_class == ('absent' if self.args.expect_cred == 'absent' else 'expected')
        return good, cred_class

    async def close(self):
        if self.writer:
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), 2)
            except (OSError, asyncio.TimeoutError):
                pass
            self.writer = None


async def gate_request(args, operation):
    from urllib.parse import urlsplit
    url=urlsplit(args.gate_url)
    reader,writer=await asyncio.open_connection(url.hostname,url.port)
    writer.write(('GET /%s/%s/%s HTTP/1.0\r\nHost: fixture\r\n\r\n' %
                  (operation,args.gate_key,args.participant)).encode())
    await writer.drain()
    data=await asyncio.wait_for(reader.read(),300)
    writer.close();await writer.wait_closed()
    head,body=data.split(b'\r\n\r\n',1)
    if b' 200 ' not in head.split(b'\r\n')[0]:
        raise RuntimeError('fixture gate failed')
    return json.loads(body)


def memory_available():
    if Path('/proc/meminfo').exists():
        values={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines()}
        return values['MemAvailable']
    # Local disposable TLS fixtures also run on macOS.
    import subprocess,re
    output=subprocess.check_output(['/usr/bin/vm_stat'],text=True)
    page=int(re.search(r'page size of (\d+) bytes',output)[1])
    return sum(int(re.search(r'^'+label+r':\s+(\d+)',output,re.M)[1]) for label in
               ('Pages free','Pages inactive','Pages speculative'))*page


def memory_preflight(concurrency, available):
    # Stage-one observed ~226 KiB/connection; 384 KiB includes TLS/task margin.
    per_connection=384*1024
    reserve=64*1024*1024
    required=concurrency*per_connection+reserve
    return dict(status='OK' if available>=required else 'INVALID',available_bytes=available,
                required_bytes=required,bytes_per_connection=per_connection,reserve_bytes=reserve,concurrency=concurrency)


async def execute(args):
    if args.mode in ('burst','fill','memory-check'):
        preflight=memory_preflight(args.concurrency,memory_available())
        if preflight['status']!='OK' or args.mode=='memory-check':
            result=dict(v=1,participant=args.participant,status=preflight['status'],memory_preflight=preflight,attempted=0,success=0,failed=0,contradictions=0)
            save(args.out,result)
            if args.ready_file:save(args.ready_file,result)
            return result
    else:preflight=None
    ctx = ssl.create_default_context(cafile=args.cafile)
    ctx.set_alpn_protocols(['http/1.1'])
    result = dict(v=1, participant=args.participant, attempted=0, success=0, failed=0, verified=0, connections=0, contradictions=0,
                  errors={}, leaf={'origin': 0, 'mitm': 0, 'none': 0}, cred={'expected': 0, 'absent': 0, 'other': 0},
                  request_ms=[], handshake_ms=[], concurrency=args.concurrency, connection=args.connection,
                  body_bytes=args.body_bytes, bound_percent=args.bound_percent, max_requests=args.max_requests, released_alive=0)
    if preflight:result['memory_preflight']=preflight
    start, cpu = time.monotonic(), time.process_time()
    gate = asyncio.Event()
    held = []
    request_sequence = 0
    minute_windows = {}
    hist = {}
    long_run = args.duration > 120

    async def once(session):
        result['attempted'] += 1
        t0 = time.monotonic()
        minute = int((t0-start)//60)
        window = minute_windows.setdefault(minute, {'minute': minute, 'success': 0, 'failed': 0, 'request_ms': []})
        for old_minute, old in minute_windows.items():
            if old_minute < minute-1 and 'latency_ms' not in old:
                old['latency_ms'] = summarize(old.pop('request_ms'))
        phase = 'handshake'
        try:
            if session.writer is None:
                result['handshake_ms'].append(await session.connect())
                result['connections'] += 1
            phase = 'recv'
            good, cred = await asyncio.wait_for(session.request(), args.timeout)
            result['leaf'][session.leaf] += 1
            result['cred'][cred] += 1
            if not good:
                result['contradictions'] += 1
            result['success'] += 1
            result['verified'] += int(good)
            latency = round((time.monotonic()-t0)*1000, 3)
            window['success'] += 1
            window['request_ms'].append(latency)
            if long_run:
                bin_ms = str(round(latency, 1))
                hist[bin_ms] = hist.get(bin_ms, 0)+1
            else:
                result['request_ms'].append(latency)
            return good
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
            key = error_kind(exc, phase)
            result['errors'][key] = result['errors'].get(key, 0)+1
            result['failed'] += 1
            window['failed'] += 1
            await session.close()
            return False

    async def worker(index):
        sessions = {}
        session = Session(args, ctx)
        await gate.wait()
        try:
            if args.mode == 'burst':
                if await once(session):
                    held.append(session)
                    return
            else:
                count = 0
                while time.monotonic()-start < args.duration and (not args.max_requests or result['attempted']<args.max_requests):
                    nonlocal request_sequence
                    bound = request_sequence % 100 < args.bound_percent
                    request_sequence += 1
                    path = 'bound' if bound else 'unbound'
                    if path not in sessions:
                        selected = copy.copy(args)
                        if not bound and args.unbound_host:
                            selected.host = args.unbound_host
                            selected.expect_cred = 'absent'
                            selected.expect_leaf = args.unbound_leaf
                        sessions[path] = Session(selected, ctx)
                    session = sessions[path]
                    await once(session)
                    count += 1
                    if args.connection == 'new' or (args.churn_every and count % args.churn_every == 0):
                        for current in sessions.values():
                            await current.close()
                    if args.rate:
                        # Per-worker fixed offered rate, no catch-up bursts.
                        await asyncio.sleep(args.concurrency/args.rate)
        finally:
            for current in list(sessions.values())+[session]:
                if current not in held:
                    await current.close()
    tasks = [] if args.mode == 'fill' else [asyncio.create_task(worker(i)) for i in range(args.concurrency)]
    if args.gate_url:
        release = await gate_request(args,'wait')
        await asyncio.sleep(max(0,release['start_at_s']-release['server_now_s']))
        mark = await gate_request(args,'started')
        result.update(scheduled_start_s=release['start_at_s'],start_at_s=mark['marked_at_s'],
                      start_lag_s=mark['marked_at_s']-release['start_at_s'])
    start, cpu = time.monotonic(), time.process_time()
    gate.set()
    await asyncio.gather(*tasks)
    if args.mode == 'fill':
        limit=args.concurrency*(1+args.fill_max_retries)
        fill=dict(batch_size=args.fill_batch_size,batch_interval_s=args.fill_interval_s,
                  max_retries=args.fill_max_retries,attempt_limit=limit,batches=[])
        result['fill']=fill
        retryable={'handshake/timeout','handshake/reset','handshake/tls_closed','handshake/tls_error',
                   'handshake/io_error','handshake/refused','recv/timeout','recv/reset','recv/eof','recv/io_error'}
        async def add_one():
            session=Session(args,ctx)
            if await once(session):held.append(session)
            else:await session.close()
        async def verify_held():
            alive=[]
            async def verify(session):
                try:
                    good,_=await asyncio.wait_for(session.request(),args.timeout)
                    result['contradictions']+=int(not good)
                    if good:alive.append(session);return
                except (OSError,ValueError,asyncio.TimeoutError,asyncio.IncompleteReadError):
                    pass
                await session.close()
            for offset in range(0,len(held),args.fill_batch_size):
                await asyncio.gather(*(verify(s) for s in held[offset:offset+args.fill_batch_size]))
            held[:]=alive
            return len(alive)
        while result['attempted']<limit:
            n=min(args.fill_batch_size,args.concurrency-len(held),limit-result['attempted'])
            before={k:result[k] for k in ('attempted','verified','failed')};errors=dict(result['errors'])
            await asyncio.gather(*(add_one() for _ in range(n)))
            fill['batches'].append(dict({k:result[k]-before[k] for k in before},held=len(held),
                errors={k:v-errors.get(k,0) for k,v in result['errors'].items() if v>errors.get(k,0)}))
            if result['contradictions'] or set(result['errors'])-retryable:
                result['fill_reason']='non_retryable_failure';break
            if len(held)==args.concurrency and await verify_held()==args.concurrency:
                result['fill_reason']='capacity_reached';break
            # Persist partial progress without declaring readiness for probes.
            save(str(args.out)+'.progress',dict(result,held=len(held)))
            await asyncio.sleep(args.fill_interval_s)
        result.update(held=len(held),boundary_verified=len(held) if len(held)==args.concurrency else 0,
                      fill_status='FULL' if len(held)==args.concurrency else 'PARTIAL')
        result['boundary_origin_connections']=len({s.origin_connection for s in held if isinstance(s.origin_connection,str) and s.origin_connection})
        result.setdefault('fill_reason','retry_limit_reached')
    if args.mode in ('burst','fill'):
        if args.ready_file:
            save(args.ready_file, dict(result, held=len(held)))
        deadline = time.monotonic()+args.hold_s
        while time.monotonic() < deadline and args.release_file and not Path(args.release_file).exists():
            await asyncio.sleep(.05)
        async def release(session):
            try:
                good, _ = await asyncio.wait_for(session.request(), args.timeout)
                result['released_alive'] += int(good)
                result['contradictions'] += int(not good)
            except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                pass
            finally:
                await session.close()
        if args.mode=='fill':
            for offset in range(0,len(held),args.fill_batch_size):
                await asyncio.gather(*(release(s) for s in held[offset:offset+args.fill_batch_size]))
        else:
            for session in held:await release(session)
    result['wall_s'] = time.monotonic()-start
    result['cpu_s'] = time.process_time()-cpu
    if args.gate_url:
        result['end_at_s'] = (await gate_request(args,'finished'))['marked_at_s']
    result['minute_windows'] = [dict(minute=w['minute'], success=w['success'], failed=w['failed'], latency_ms=w.get('latency_ms') or summarize(w.get('request_ms', []))) for w in minute_windows.values()]
    if long_run:
        result['request_histogram_ms'] = hist
        result['latency_resolution_ms'] = .1
    save(args.out, result)
    return result


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('mode', choices=['load', 'burst', 'fill', 'memory-check'])
    p.add_argument('--fill-batch-size',type=int,default=32)
    p.add_argument('--fill-interval-s',type=float,default=.25)
    p.add_argument('--fill-max-retries',type=int,default=3)
    p.add_argument('--held-key',default='')
    for key in ['host', 'ip', 'cafile', 'origin-leaf', 'expect-leaf', 'expect-cred', 'out']:
        p.add_argument('--'+key, required=True)
    p.add_argument('--gate-url',default='')
    p.add_argument('--gate-key',default='')
    p.add_argument('--participant',default='guest')
    p.add_argument('--bound-percent', type=int, choices=[0, 5, 100], default=100)
    p.add_argument('--unbound-host', default='')
    p.add_argument('--unbound-leaf', choices=['origin', 'mitm'], default='origin')
    p.add_argument('--port', type=int, default=443)
    p.add_argument('--duration', type=float, default=60)
    p.add_argument('--concurrency', type=int, default=1)
    p.add_argument('--connection', choices=['new', 'keep-alive'], default='new')
    p.add_argument('--body-bytes', type=int, choices=[0, 65536], default=0)
    p.add_argument('--max-requests',type=int,default=0)
    p.add_argument('--churn-every', type=int, default=0)
    p.add_argument('--rate', type=float, default=0)
    p.add_argument('--timeout', type=float, default=20)
    p.add_argument('--hold-s', type=float, default=60)
    p.add_argument('--ready-file', default='')
    p.add_argument('--release-file', default='')
    a = p.parse_args(argv)
    if not 1 <= a.concurrency <= 5000 or a.duration <= 0 or a.timeout <= 0 or a.rate < 0 or a.churn_every < 0 or a.max_requests < 0:
        p.error('invalid load bounds')
    if not 1<=a.fill_batch_size<=2048 or not math.isfinite(a.fill_interval_s) or a.fill_interval_s<0 or not 0<=a.fill_max_retries<=10:
        p.error('invalid fill bounds')
    if a.held_key and (a.mode!='fill' or len(a.held_key)>128 or any(not(c.isascii() and (c.isalnum() or c=='-')) for c in a.held_key)):
        p.error('invalid held key')
    return a


if __name__ == '__main__':
    args = parse_args()
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = max(soft, args.concurrency*2+256)
    resource.setrlimit(resource.RLIMIT_NOFILE, (want if hard == resource.RLIM_INFINITY else min(want, hard), hard))
    asyncio.run(execute(args))
