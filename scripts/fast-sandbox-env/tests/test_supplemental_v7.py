# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0
"""Gradual single-subject fill and boundary evidence gates."""
import asyncio
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_supplemental_v2 import module, burst
from test_supplemental_v6 import overflow
from test_credential_bound import ShellCase
import test_supplemental_bench as fixtures
c=module('supplemental-client');r=module('supplemental-report');tools=module('supplemental-tools')


def filled(mode='credential-bound'):
    s=overflow();s.update(gradual_fill=True,mode=mode)
    a=s['runs'][0];a.update(mode=mode,attempted=2,success=2,failed=0,errors={},held=2,
        memory_preflight=c.memory_preflight(2,2*1024**3),boundary_verified=2,boundary_origin_connections=2,fill_status='FULL',fill_reason='capacity_reached',
        fill=dict(batch_size=1,batch_interval_s=.1,max_retries=2,attempt_limit=6,
                  batches=[dict(attempted=1,verified=1,failed=0,held=1,errors={}),dict(attempted=1,verified=1,failed=0,held=2,errors={})]))
    s['tiers'][0].update(server_held=dict(source='origin_live_connections',established=2),
        probe_denials_before=0,probe_denials_after=1,probe_server_budget_denials=1,probe_sent=True,server_budget_denials=1)
    s['tiers'][0]['budget']['admission_enabled']=mode=='credential-bound'
    if mode=='all':
        s['overflow_probes']['new_bound']=dict(participant='probe-bound',attempted=1,success=1,verified=1,failed=0,contradictions=0,errors={})
        s['tiers'][0]['probe_server_budget_denials']=0;s['tiers'][0]['probe_denials_after']=0
    return s


class Report(unittest.TestCase):
    def test_production_capacity_2048(self):
        s=filled();s['smoke']=False;a=s['runs'][0];t=s['tiers'][0]
        for k in ('attempted','success','verified','released_alive','held','boundary_verified','boundary_origin_connections'):a[k]=2048
        a['memory_preflight']=c.memory_preflight(2048,2*1024**3)
        a['fill'].update(batch_size=32,attempt_limit=6144,batches=[dict(attempted=32,verified=32,failed=0,held=n,errors={}) for n in range(32,2049,32)])
        t['budget']['per_subject']=2048;t['server_held'].update(established=2048)
        self.assertEqual(r.build_m7(s)['status'],'OK')
    def test_full_and_two_mode_expectations(self):
        for mode in ('all','credential-bound'):
            out=r.build_m7(filled(mode));self.assertEqual(out['status'],'OK')
            self.assertEqual(out['single_subject_overflow']['expected'],
                'budget_rejection' if mode=='credential-bound' else 'no_per_subject_budget')

    def test_partial_cannot_claim_boundary(self):
        s=filled();s['runs'][0].update(held=1,boundary_verified=1,fill_status='PARTIAL')
        s['tiers'][0]['probe_sent']=False;s['overflow_probes']={}
        self.assertEqual(r.build_m7(s)['status'],'PARTIAL')

    def test_successful_bound_probe_and_missing_server_denial_fail(self):
        for mode in ('all','credential-bound'):
            s=filled(mode);s['overflow_probes']['new_bound']=copy.deepcopy(filled('all' if mode=='credential-bound' else 'credential-bound')['overflow_probes']['new_bound'])
            self.assertNotEqual(r.build_m7(s)['status'],'OK')
        s=filled();s['tiers'][0]['probe_server_budget_denials']=0
        self.assertNotEqual(r.build_m7(s)['status'],'OK')

    def test_server_fill_and_survival_required(self):
        for field,value in [('held',1),('boundary_verified',1),('released_alive',1),('attempted',9)]:
            s=filled();s['runs'][0][field]=value;self.assertNotEqual(r.build_m7(s)['status'],'OK',field)
        s=filled();s['tiers'][0]['server_held']['established']=1
        self.assertNotEqual(r.build_m7(s)['status'],'OK')

    def test_retry_accounting_and_guest_preflight(self):
        s=filled();a=s['runs'][0];a.update(attempted=3,failed=1,errors={'recv/io_error':1})
        a['fill']['batches'].insert(0,dict(attempted=1,verified=0,failed=1,held=0,errors={'recv/io_error':1}))
        self.assertEqual(r.build_m7(s)['status'],'OK')
        s['large_guest']={};self.assertNotEqual(r.build_m7(s)['status'],'OK')


class FillClient(unittest.TestCase):
    def execute(self, failures=0):
        state={'calls':0,'active':0,'peak':0}
        class Writer:
            def get_extra_info(self,key):return ('192.0.2.1',10000+state['calls'])
        class Session:
            def __init__(self,*args):self.writer=None
            async def connect(self):
                state['calls']+=1;state['active']+=1;state['peak']=max(state['peak'],state['active'])
                await asyncio.sleep(0);state['active']-=1
                if state['calls']<=failures:raise ConnectionResetError()
                self.writer=Writer();self.leaf='mitm';self.origin_connection='origin-'+str(state['calls']);return 1
            async def request(self):return True,'expected'
            async def close(self):self.writer=None
        with tempfile.TemporaryDirectory() as d:
            args=c.parse_args(['fill','--host','fixture','--ip','127.0.0.1','--cafile','unused','--origin-leaf','x',
                '--expect-leaf','mitm','--expect-cred','fake','--out',d+'/out.json','--ready-file',d+'/ready.json',
                '--concurrency','4','--fill-batch-size','1','--fill-interval-s','0','--fill-max-retries','1','--hold-s','.001'])
            with patch.object(c,'Session',Session),patch.object(c.ssl,'create_default_context'),patch.object(c,'memory_available',return_value=2*1024**3):
                out=asyncio.run(c.execute(args));ready=json.loads(Path(d+'/ready.json').read_text())
        return out,ready,state

    def test_gradual_success(self):
        out,ready,state=self.execute();self.assertEqual(ready['held'],4);self.assertEqual(ready['boundary_verified'],4)
        self.assertEqual(out['released_alive'],4);self.assertEqual(state['peak'],1)

    def test_retry_completes_and_is_bounded(self):
        out,ready,state=self.execute(2);self.assertEqual(ready['fill_status'],'FULL');self.assertEqual(out['failed'],2)
        out,ready,state=self.execute(100);self.assertEqual(ready['fill_status'],'PARTIAL')
        self.assertEqual(out['attempted'],8);self.assertEqual(state['calls'],8)



class FillOrchestration(ShellCase):
    def test_asynchronous_denial_log_wait_is_bounded(self):
        out=self.sourced(r"""
source "$SCRIPT_DIR/supplemental-bench.sh"
printf '0' > "$WORK/reads"
sup_m7_denial_count() {
 local n; n=$(cat "$WORK/reads"); n=$((n+1)); echo "$n" > "$WORK/reads"
 if ((n>=3)); then echo 1; else echo 0; fi
}
sleep() { :; }; sup_start() { echo REPLAYED; }
test "$(sup_m7_probe_denials 0 credential-bound)" = 1
test "$(cat "$WORK/reads")" = 3
printf '0' > "$WORK/reads"
sup_m7_denial_count() { local n; n=$(cat "$WORK/reads"); echo "$((n+1))" > "$WORK/reads"; echo 0; }
test "$(sup_m7_probe_denials 0 credential-bound)" = 0
test "$(cat "$WORK/reads")" = 30
echo BOUNDED
""",OCI_STACK='0')
        self.assertIn('BOUNDED',out.stdout);self.assertNotIn('REPLAYED',out.stdout)

    def test_incomplete_fill_never_launches_probes(self):
        for held,server in ((1,1),(2,1)):
            out=self.sourced(r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_DIR="$WORK/report"; SUP_RAW="$SUP_DIR/raw"; mkdir -p "$SUP_RAW"
> "$WORK/starts"
SUP_SEQ=0; SUP_RESOURCE_RECOVERY_S=1; SUP_RESOURCE_INTERVAL_S=1; SUP_CLIENT_ATTEMPTS=1
SUP_FILL_BATCH_SIZE=1; SUP_FILL_INTERVAL_S=0; SUP_FILL_MAX_RETRIES=1
BENCH_B=b; BENCH_POD=p; RESOURCE_NS=x; CB_GUEST_DIR=/guest; SUP_CODE=fixture
printf '{}' > "$SUP_RAW/m7-spec.json"
bench_ns() { echo 1; }; bench_elapsed_ms() { echo 1000; }
sup_sample() { echo '{}'; }; cb_until() { :; }; osb_api() { :; }
sup_start() { echo "$2" >> "$WORK/starts"; }
bench_wait() {
 jq -n --argjson held "$HELD" '{fill_status:"FULL",held:$held,boundary_verified:$held,held_endpoints:[["192.0.2.1",12345]]}' > "$SUP_RAW/$3-ready.json"
}
sup_gate() { echo '{"source":"origin_live_connections","established":1}'; }
sup_fetch() { echo '{"attempted":2,"success":1,"failed":1,"verified":1}' > "$SUP_RAW/$2.json"; }
sup_m7_resources_ready() { return 0; }
sup_m7_fill_tier credential-bound 2
test "$(wc -l < "$WORK/starts" | tr -d ' ')" = 1
jq -e '.probe_sent==false' "$SUP_RAW/m7-tier.json"
''',OCI_STACK='0',HELD=str(held))
            self.assertIn('true',out.stdout)


class FillTLS(fixtures.OriginFixture):
    def test_real_tls_fill_verifies_and_releases_all(self):
        out=fixtures.SupplementalClientTest.probe(self,'fill',concurrency=4,fill_batch_size=2,fill_interval_s=.01,fill_max_retries=1,hold_s=.01)
        self.assertEqual(out['fill_status'],'FULL');self.assertEqual(out['boundary_verified'],4)
        self.assertEqual(out['released_alive'],4);self.assertEqual(len(out['fill']['batches']),2)


class OriginCounter(unittest.TestCase):
    def test_live_counter_counts_distinct_open_connections_and_cleans(self):
        import http.client,threading,time
        origin=module('supplemental-origin')
        server=origin.OriginServer(('127.0.0.1',0),origin.Handler);server.daemon_threads=True
        gate=origin.build_gate_server(0,'127.0.0.1')
        for srv in (server,gate):threading.Thread(target=srv.serve_forever,daemon=True).start()
        clients=[]
        def count():
            c=http.client.HTTPConnection(*gate.server_address,timeout=2)
            c.request('GET','/held/test-fill/host');q=json.loads(c.getresponse().read());c.close();return q
        try:
            for _ in range(2):
                c=http.client.HTTPConnection(*server.server_address,timeout=2);clients.append(c)
                for i in range(2):
                    c.request('GET','/cbv',headers={'X-Bench-Held-Key':'test-fill'});c.getresponse().read()
            self.assertEqual(count(),dict(source='origin_live_connections',established=2))
            for c in clients:c.close()
            for _ in range(100):
                if count()['established']==0:break
                time.sleep(.01)
            self.assertEqual(count()['established'],0)
            self.assertFalse(origin._HELD)
        finally:
            for c in clients:c.close()
            for srv in (server,gate):srv.shutdown();srv.server_close()


if __name__=='__main__':unittest.main()
