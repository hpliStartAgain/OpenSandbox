# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0
"""Stage-one measurement validity regressions."""
import asyncio
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_supplemental_v2 import module
r=module('supplemental-report')
c=module('supplemental-client')


def paths():
    return [dict(mode=m,target=t,pod_uid=str(i),process_identity=str(i),fresh_baseline=dict(anon=64e6,memory_current=70e6),
                 mode_baseline=dict(anon=64e6,memory_current=70e6),
                 points=[dict(k=k,held=k,alive=k,anon=64e6+k*1000,memory_current=70e6+k*1000,same_process=True) for k in (0,2,4)])
            for i,(m,t) in enumerate((m,t) for m in ('all','credential-bound') for t in ('unbound','bound'))]


class Validity(unittest.TestCase):
    def test_four_fresh_paths_allow_mixtures(self):
        out=r.build_m3x(dict(paths=paths()))
        self.assertEqual(out['status'],'OK');self.assertEqual(len(out['mixtures']),10)

    def test_reused_process_invalidates_path_and_all_mixtures(self):
        ps=paths();ps[1].update(pod_uid=ps[0]['pod_uid'],process_identity=ps[0]['process_identity'])
        out=r.build_m3x(dict(paths=ps))
        self.assertEqual(out['status'],'INVALID');self.assertEqual(out['mixtures'],[])

    def test_contaminated_kzero_invalidates_path(self):
        ps=paths();ps[1]['points'][0].update(anon=694e6,memory_current=700e6)
        out=r.build_m3x(dict(paths=ps));self.assertEqual(out['status'],'INVALID');self.assertFalse(out['mixtures'])

    def test_baseline_threshold_boundary_and_missing_identity(self):
        ps=paths();ps[1]['points'][0]['anon']+=32*1024*1024
        self.assertEqual(r.build_m3x(dict(paths=ps))['status'],'OK')
        ps[1]['points'][0]['anon']+=1
        self.assertEqual(r.build_m3x(dict(paths=ps))['status'],'INVALID')
        ps=paths();del ps[1]['pod_uid']
        self.assertNotEqual(r.build_m3x(dict(paths=ps))['status'],'OK')

    def test_local_resource_failure_is_classified(self):
        import errno
        self.assertEqual(c.error_kind(OSError(errno.EMFILE,'fixture'),'handshake'),'client/resource_exhausted')

    def test_classified_rejections_preserve_unknown(self):
        out=r.burst_rejections({'recv/timeout':1162,'handshake/timeout':3,'handshake/refused':2,'client/memory':1,'handshake/reset':4},2)
        self.assertEqual(out['response_timeout'],1162);self.assertEqual(out['handshake_timeout'],3)
        self.assertEqual(out['connection_refused'],2);self.assertEqual(out['client_failure'],1)
        self.assertEqual(out['budget'],2);self.assertEqual(out['unattributed'],2)

    def test_churn_drift_stays_inside_each_concurrency_segment(self):
        runs=[dict(group=i,concurrency=n,minute_windows=[dict(minute=0,latency_ms=dict(n=1,p50=a)),dict(minute=1,latency_ms=dict(n=1,p50=b))]) for i,(n,a,b) in enumerate([(1,10,11),(4,40,44),(16,100,110)])]
        out=r.build_time(dict(runs=runs))
        self.assertNotIn('latency_p50_drift_percent',out)
        self.assertEqual([x['p50_drift_percent'] for x in out['latency_segments']],[10,10,10])
        runs[0]['minute_windows']=runs[0]['minute_windows'][:1]
        self.assertIsNone(r.build_time(dict(runs=runs))['latency_segments'][0]['p50_drift_percent'])

    def test_low_memory_does_not_start_connections_or_gate(self):
        with tempfile.TemporaryDirectory() as d:
            args=c.parse_args(['burst','--host','fixture','--ip','127.0.0.1','--cafile','missing','--origin-leaf','x','--expect-leaf','origin','--expect-cred','absent','--out',d+'/out.json','--concurrency','2000'])
            with patch.object(c,'memory_available',return_value=300*1024*1024),patch.object(c.Session,'connect') as connect,patch.object(c,'gate_request') as gate:
                result=asyncio.run(c.execute(args))
            self.assertEqual(result['status'],'INVALID');self.assertEqual(result['attempted'],0)
            connect.assert_not_called();gate.assert_not_called()

    def test_split_memory_capacity(self):
        self.assertEqual(c.memory_preflight(342,300*1024*1024)['status'],'OK')
        self.assertEqual(c.memory_preflight(2000,300*1024*1024)['status'],'INVALID')


if __name__=='__main__':unittest.main()

from test_credential_bound import ShellCase
from test_supplemental_v2 import burst


class DistributedReports(unittest.TestCase):
    def test_distributed_budget_and_synchronization(self):
        s=burst();a=s['runs'][0]
        a.update(attempted=2,success=1,verified=1,failed=1,released_alive=1,errors={'handshake/tls_closed':1},
                 scheduled_start_s=100,start_lag_s=.01,memory_preflight=c.memory_preflight(2,300*1024*1024))
        s['runs']=[a,dict(a)];s['tiers'][0].update(allocations=[2,2],budget=dict(admission_enabled=True,per_subject=1,process=8,available=2))
        out=r.build_m7(s);self.assertEqual(out['status'],'OK');self.assertTrue(out['tiers'][0]['synchronized_start'])
        s['runs'][1]['scheduled_start_s']=101
        self.assertEqual(r.build_m7(s)['status'],'PARTIAL')
        s['runs'][1]['scheduled_start_s']=100;s['runs'][1]['memory_preflight']={'status':'INVALID'}
        self.assertNotEqual(r.build_m7(s)['status'],'OK')


class ShellPreflight(ShellCase):
    def test_insufficient_memory_aborts_before_burst_launch(self):
        result=self.sourced(r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_DIR="$WORK/report"; SUP_RAW="$SUP_DIR/raw"; mkdir -p "$SUP_RAW"
SUP_BURSTS=2000; SUP_BURST_REPEATS=1; SUP_SEQ=0; SUP_GATE_URL=unused
BENCH_B=b; BENCH_POD=p; RESOURCE_NS=x
sup_spec() { :; };sup_pool() { BENCH_LEG="$1"; };sup_pair() { :; }
sup_burst_guests() { SUP_BURST_IDS=(b b2); }
bench_ns() { echo 1; }
kubectl() { echo '{"spec":{"containers":[{"name":"egress","env":[]}]}}'; }
sup_start() { printf '%s\n' "${8}" >> "$WORK/launches"; }
sup_fetch() { echo '{"status":"INVALID","memory_preflight":{"status":"INVALID"}}' > "$SUP_RAW/$2.json"; }
if (sup_m7); then exit 3; fi
cat "$SUP_DIR/m7.json"
cat "$WORK/launches"
''',OCI_STACK='0')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('"INVALID"',result.stdout)
        self.assertEqual(result.stdout.strip().splitlines()[-1],'memory-check')
