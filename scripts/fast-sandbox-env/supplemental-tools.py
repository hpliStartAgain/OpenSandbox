#!/usr/bin/env python3
# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0
"""Private runner glue: validation, path classification and log projection."""
import importlib.util
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
            'distributions': {k: r.quantiles([v[k] for v in complete]) for k in ('total', 'policy_commit', 'apply_policy')}}


def validate(env):
    positive = ['SUP_REPEATS', 'SUP_LOAD_S', 'SUP_WARMUP_S', 'SUP_IDLE_S', 'SUP_CHURN_S', 'SUP_SOAK_S',
                'SUP_SOAK_CONCURRENCY', 'SUP_RECOVERY_S', 'SUP_SCALE_PROBES', 'SUP_CLIENT_ATTEMPTS']
    for k in positive:
        if not env[k].isdigit() or int(env[k]) < 1:
            raise ValueError(k)
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


def main(argv):
    command, *a = argv
    if command == 'validate':
        validate(os.environ)
    elif command == 'classify':
        raw, origin, leaf, cred = a
        print(r.base.classify_run(json.loads(Path(raw).read_text()), origin, leaf, cred)['contradictions'])
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
                               'latency_ms': raw.get('handshake_ms', {}), 'success': raw.get('ok', 0)})
        payload['real_connections'] = {'status': r.base.worst([p['status'] for p in probes]),
                                      'topology': 'two real colocated guests, synthetic deny-first attachments have no VM or veth',
                                      'independent_netns': 'NOT_RUN', 'probes': probes}
        Path(src).write_text(json.dumps(payload))
    else:
        raise ValueError('unknown command')


if __name__ == '__main__':
    main(sys.argv[1:])
