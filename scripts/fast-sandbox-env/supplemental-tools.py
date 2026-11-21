#!/usr/bin/env python3
# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0
"""Private runner glue: validation, path classification and log projection."""
import importlib.util
import datetime
import shutil
import subprocess
import json
import os
from pathlib import Path
import re
import sys

spec = importlib.util.spec_from_file_location('supplemental_report', Path(__file__).with_name('supplemental-report.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def segments(text):
    # Both records must belong to the same subject. IDs are discarded here.
    records = {}
    for line in text.splitlines():
        m = re.search(r'subject (\S+): SET_BINDING applied .*total=(\d+)ms .*policyCommit=(\d+)ms', line)
        if m:
            records.setdefault(m[1], {}).update(total=int(m[2]), policy_commit=int(m[3]))
        m = re.search(r'subject (\S+): data-plane-ready, policy active applyPolicy=(\d+)ms', line)
        if m:
            records.setdefault(m[1], {}).update(apply_policy=int(m[2]))
    complete = [v for v in records.values() if len(v) == 3]
    return {'matched_subjects': len(complete), 'incomplete_subjects': len(records)-len(complete),
            'unit': 'ms, integer log precision',
            'paired_timings_ms': complete, 'distributions': {k: r.quantiles([v[k] for v in complete]) for k in ('total', 'policy_commit', 'apply_policy')}}


def make_origin_certificate(ca_dir, out_dir, host):
    """Backdate fixture leafs for guests resumed from an older warm snapshot."""
    ca, out = Path(ca_dir), Path(out_dir)
    out.mkdir(exist_ok=True)
    shutil.copyfile(str(ca/'tls.crt'), str(out/'tls.crt'))
    (out/'index').write_text('')
    (out/'serial').write_text('01\n')
    config = out/'ca.cnf'
    config.write_text('[ca]\ndefault_ca=bench\n[bench]\ndatabase=%s\nnew_certs_dir=%s\nserial=%s\ncertificate=%s\nprivate_key=%s\ndefault_md=sha256\npolicy=policy\nunique_subject=no\n[policy]\ncommonName=supplied\n[leaf]\nsubjectAltName=DNS:%s,DNS:unbound.%s\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n' %
                      (out/'index', out, out/'serial', ca/'tls.crt', ca/'tls.key', host, host))
    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now-datetime.timedelta(days=2)).strftime('%y%m%d%H%M%SZ')
    end = (now+datetime.timedelta(days=2)).strftime('%y%m%d%H%M%SZ')
    commands = [
        ['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(out/'echo.key'), '-out', str(out/'echo.csr'), '-subj', '/CN='+host],
        ['openssl', 'ca', '-batch', '-notext', '-config', str(config), '-in', str(out/'echo.csr'), '-out', str(out/'echo.crt'), '-startdate', start, '-enddate', end, '-extensions', 'leaf']]
    for command in commands:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def create_inputs(spec_file):
    payload = json.loads(Path(spec_file).read_text())
    values = []
    for row in payload.get('rounds', []):
        report = r.base.load_json(row.get('report')) or {}
        values.extend(a['ready_seconds']*1000 for a in report.get('attempts', []) if a.get('success'))
    return values


def budget_denials(text):
    # launch.go consumes tls-admission-v1 into telemetry, while it forwards
    # the closed tls-decision deny line to the egress container log.
    return len(re.findall(r'credential proxy: tls decision deny reason=registry_exhausted(?=["\s]|$)', text))


def m5_cases(env):
    return [(int(mix),int(body)) for mix in (5,100) for body in env['SUP_BODY_BYTES'].split()
            if mix==5 or body=='0']


def lifetime_seconds(env, measurement):
    # Per-point 120 s control allowance, plus 30 min creation/cleanup margin.
    warm, recovery = int(env['SUP_WARMUP_S']), int(env['SUP_RECOVERY_S'])
    if measurement=='m5':
        points=len(env['SUP_CONCURRENCIES'].split())*2*len(m5_cases(env))*int(env['SUP_REPEATS'])
        return max(21600,points*(int(env['SUP_LOAD_S'])+warm+120)+1800)
    if measurement=='m9':
        return 21600
    if measurement=='m8':
        return max(10800,int(env['SUP_SOAK_S'])+warm+recovery+1800)
    return max(7200,int(env['SUP_CHURN_S'])+3*warm+recovery+1800)


def lifetime_readback(payload, required, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    expires = datetime.datetime.fromisoformat(payload['expires_at'].replace('Z','+00:00'))
    remaining = (expires-now).total_seconds()
    if remaining <= required:
        raise ValueError('guest API lifetime is shorter than measurement group')
    return dict(expires_at=expires.isoformat(),read_at=now.isoformat(),remaining_s=remaining,
                required_s=required,api_readback=True)


def gate_call(url, operation, key, participant='host'):
    import urllib.request
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url+'/'+operation+'/'+key+'/'+participant,timeout=300) as response:
        return json.load(response)


def validate(env):
    positive = ['SUP_REPEATS', 'SUP_LOAD_S', 'SUP_WARMUP_S', 'SUP_IDLE_S', 'SUP_CHURN_S', 'SUP_SOAK_S',
                'SUP_SOAK_CONCURRENCY', 'SUP_RECOVERY_S', 'SUP_SCALE_PROBES', 'SUP_CLIENT_ATTEMPTS',
                'SUP_BURST_REPEATS','SUP_RESOURCE_RECOVERY_S','SUP_RESOURCE_INTERVAL_S']
    for k in positive:
        if not env[k].isdigit() or int(env[k]) < 1:
            raise ValueError(k)
    if env['SUP_SMOKE']=='true':
        cap=env.get('SUP_OVERFLOW_SMOKE_CAPACITY','8')
        if not cap.isdigit() or not 1<=int(cap)<=2048:raise ValueError('overflow smoke capacity')
    if not 2 <= int(env.get('SUP_BURST_GUESTS','6')) <= 6:
        raise ValueError('burst guests')
    if not 1 <= int(env['SUP_LOAD_GUESTS']) <= 6:
        raise ValueError('load guests')
    if 'm8' in env['SUP_MEASUREMENTS'].split() and env['SUP_SMOKE']=='false' and any(float(env[k])<=0 for k in ('SUP_SOAK_RATE_ALL','SUP_SOAK_RATE_CB')):
        raise ValueError('M8 requires positive calibrated SUP_SOAK_RATE_ALL and SUP_SOAK_RATE_CB')
    if env['SUP_SMOKE'] not in ('true', 'false') or not 1 <= int(env['SUP_BLOCKS']) <= 8:
        raise ValueError('smoke/blocks')
    for k in ['SUP_CONCURRENCIES', 'SUP_BURSTS', 'SUP_SUBJECT_STEPS']:
        xs = [int(x) for x in env[k].split()]
        if not xs or any(x <= 0 for x in xs) or xs != sorted(set(xs)):
            raise ValueError(k)
    if max(map(int, env['SUP_SUBJECT_STEPS'].split())) > 4097:
        raise ValueError('subject limit')
    if any(x not in ('0', '65536') for x in env['SUP_BODY_BYTES'].split()):
        raise ValueError('body bytes')
    if any(x not in ('500m', '2') for x in env['SUP_CPU_LIMITS'].split()):
        raise ValueError('CPU limit')
    if any(x not in r.BUILDERS for x in env['SUP_MEASUREMENTS'].split()):
        raise ValueError('measurement')
    if not env['SUP_SOAK_ANALYSIS_S'].isdigit() or int(env['SUP_SOAK_ANALYSIS_S']) >= int(env['SUP_SOAK_S']):
        raise ValueError('analysis window')


def m7_pool(pool, sandboxes):
    import math
    def quantity(value):
        match=re.fullmatch(r"([0-9.]+)(Ki|Mi|Gi|Ti)?",str(value))
        if not match:raise ValueError("unexpected memory quantity")
        return int(float(match[1])*dict(Ki=1024,Mi=1024**2,Gi=1024**3,Ti=1024**4).get(match[2],1))
    spec=pool["spec"];policy=spec["sandboxResources"];ratio=float(policy["overcommitRatio"]["memory"])
    default=quantity(policy["memory"]);slots=spec["maxSandboxesPerPod"]
    def cpu(value):return float(str(value)[:-1]) if str(value).endswith("m") else float(value)*1000
    cpu_ratio=float(policy["overcommitRatio"].get("cpu","2"));default_cpu=cpu(policy.get("cpu","1"))
    cpu_budget=max(default_cpu,math.ceil(default_cpu/cpu_ratio)*slots)
    budget=max(default,math.ceil(default/ratio)*slots)
    rows=[]
    for item in sandboxes["items"]:
        limit=quantity(item["spec"]["resources"]["limits"]["memory"])
        rows.append(dict(limit_bytes=limit,request_bytes=math.ceil(limit/ratio),cpu_request_milli=math.ceil(cpu(item["spec"]["resources"]["limits"].get("cpu","1"))/cpu_ratio),running=item.get("status",{}).get("runtime",{}).get("state")=="Ready" and any(c.get("type")=="Ready" and c.get("status")=="True" for c in item.get("status",{}).get("conditions",[])),
                         pod_uid=item["status"]["placement"]["fastletPodUID"]))
    committed=sum(x["request_bytes"] for x in rows)
    return dict(mode=policy["mode"],default_memory_bytes=default,memory_overcommit_ratio=ratio,max_sandboxes_per_pod=slots,
                per_fastlet_memory_budget_bytes=budget,sandbox_limit_memory_bytes=max(x["limit_bytes"] for x in rows),
                committed_bytes=committed,per_fastlet_cpu_budget_milli=cpu_budget,committed_cpu_milli=sum(x["cpu_request_milli"] for x in rows),
                budget_sufficient=committed<=budget and sum(x["cpu_request_milli"] for x in rows)<=cpu_budget,
                scheduled=all(x["running"] for x in rows) and len({x["pod_uid"] for x in rows})==1,
                calculation="derived from live Pool policy and each live Sandbox resource limit",sandboxes=rows)


def main(argv):
    command, *a = argv
    if command == 'm7-pool':
        print(json.dumps(m7_pool(json.loads(Path(a[0]).read_text()),json.loads(Path(a[1]).read_text()))))
    elif command == 'lifetime':
        print(lifetime_seconds(os.environ,a[0]))
    elif command == 'lifetime-readback':
        print(json.dumps(lifetime_readback(json.load(sys.stdin),int(a[0]))))
    elif command == 'gate':
        print(json.dumps(gate_call(*a)))
    elif command == 'sample-check':
        path=Path(a[0]); current=json.load(sys.stdin)
        previous=json.loads(path.read_text()) if path.exists() else None
        status=r.resource_status(([previous] if previous else [])+[current])
        path.write_text(json.dumps(current))
        if status=='INVALID':
            Path(a[1]).write_text(json.dumps(dict(status='INVALID',reason='resource lifecycle or counter regression')))
            raise SystemExit(1)
        print(json.dumps(current))
    elif command == 'validate':
        validate(os.environ)
    elif command == 'budget-denials':
        print(budget_denials(sys.stdin.read()))
    elif command == 'certificate':
        make_origin_certificate(*a)
    elif command == 'classify':
        raw, origin, leaf, cred = a
        print(r.base.classify_run(json.loads(Path(raw).read_text()), origin, leaf, cred)['contradictions'])
    elif command == 'create-inputs':
        Path(a[1]).write_text(json.dumps(create_inputs(a[0])))
    elif command == 'segments':
        src, out = a
        Path(out).write_text(json.dumps(segments(Path(src).read_text())))
    elif command == 'm9-probes':
        src, directory, origin, code = a
        payload = json.loads(Path(src).read_text())
        probes = []
        for point in payload['points']:
            for path in ('u', 'b'):
                raw = r.base.load_json(str(Path(directory)/('m9-%s-%d.json' % (path, point['target']))))
                if raw is None:
                    probes.append({'scale': point['target'], 'path': path, 'status': 'MISSING'})
                    continue
                classified = r.base.classify_run(raw, origin, 'origin' if path=='u' else 'mitm', 'absent' if path=='u' else code)
                probes.append({'scale': point['target'], 'path': path,
                               'status': 'INVALID' if classified['contradictions'] else 'FAILED' if not raw.get('ok') else 'PARTIAL' if raw.get('failed') else 'OK',
                               'latency_ms': raw.get('handshake_ms', {}), 'latency_inputs': {'handshake_ms': raw.get('handshake_ms_raw', [])}, 'success': raw.get('ok', 0)})
        payload['real_connections'] = {'status': r.base.worst([p['status'] for p in probes]),
                                      'topology': 'two real colocated guests, synthetic deny-first attachments have no VM or veth',
                                      'independent_netns': 'NOT_RUN', 'probes': probes}
        Path(src).write_text(json.dumps(payload))
    else:
        raise ValueError('unknown command')


if __name__ == '__main__':
    main(sys.argv[1:])
