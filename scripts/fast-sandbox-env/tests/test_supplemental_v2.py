# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0
"""Regression cases for CR-01 through CR-06 and O2."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
import tempfile

ROOT = Path(__file__).resolve().parents[1]
def module(name):
    s = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT/(name+'.py'))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
    return m
r = module('supplemental-report')

def sample(t=0):
    return dict(t_s=t, captured_at_s=100+t, memory_current=100, anon=50, fd=10, conntrack=2,
                usage_usec=int(t*500000), nr_throttled=int(t), throttled_usec=int(t*100),
                origin_cpu_usec=int(t*1000000), oom_kill=0, restarts=0, identity='same')

def run():
    return dict(attempted=4, success=2, failed=2, verified=2, errors={'handshake/tls_closed':2},
                contradictions=0, released_alive=2, request_ms=[1,2], cpu_s=60, wall_s=60,
                group=0, concurrency=1, total_concurrency=1, cpu_limit='500m', mode='credential-bound',
                start_at_s=100, end_at_s=160)

def burst():
    return dict(recovered=True,passthrough_ok=True,server_budget_denials=2,established_alive=0,runs=[run()], tiers=[dict(group=0, budget=dict(admission_enabled=True,per_subject=2, process=8, available=2),
        expected_success=[2,2], expected_rejections=[2,2], server_budget_denials=2,
        passthrough_ok=True, same_subject_passthrough_ok=True, recovered=True, injection_recovery_ms=1,
        resource_samples=[dict(sample(), phase='baseline'),dict(sample(1), phase='held'),dict(sample(2), phase='released')],
        resource_tolerances=dict(memory_current=10, anon=10, fd=0, conntrack=0), resource_timeout_s=5)])

class Regressions(unittest.TestCase):
    def test_low_budget_all_rejected_fails(self):
        s=burst(); s['runs'][0].update(success=0, verified=0, failed=4, released_alive=0, errors={'handshake/tls_closed':4})
        s['tiers'][0]['server_budget_denials']=4; s['server_budget_denials']=4
        self.assertNotEqual(r.build_m7(s)['status'], 'OK')

    def test_no_held_connection_cannot_pass(self):
        s=burst(); del s['runs'][0]['released_alive']
        self.assertNotEqual(r.build_m7(s)['status'], 'OK')

    def test_unattributed_errors_degrade_independently(self):
        s=burst(); s['runs'][0].update(failed=0, errors={'handshake/tls_closed':3})
        self.assertNotEqual(r.build_m7(s)['status'], 'OK')

    def test_expected_budget_refusals_and_resources_pass(self):
        self.assertEqual(r.build_m7(burst())['status'], 'OK')

    def test_burst_resource_leak_and_restart(self):
        s=burst(); s['tiers'][0]['resource_samples'][-1]['fd']=30
        self.assertEqual(r.build_m7(s)['status'], 'PARTIAL')
        s['tiers'][0]['resource_samples'][-1]['restarts']=1
        self.assertEqual(r.build_m7(s)['status'], 'INVALID')

    def test_fixed_control_delay_does_not_dilute_cpu(self):
        a=run(); a.update(success=60, verified=60, failed=0, errors={})
        s=dict(runs=[a],resource_windows=[dict(group=0,wall_s=60,control_wall_s=70,
            egress_start=sample(),egress_end=sample(60),origin_cpu_s=60)])
        out=r.build_m5(s)
        self.assertEqual(out['status'],'OK')
        self.assertEqual(out['groups'][0]['cpu_bottleneck_candidates'],['egress','origin','client'])
        self.assertEqual(out['groups'][0]['client_cpu_cores'],1)

    def test_resource_regression_identity_and_missing(self):
        a=run(); a.update(success=60,verified=60,failed=0,errors={})
        s=dict(runs=[a],resource_windows=[dict(group=0,wall_s=60,egress_start=sample(),egress_end=sample(60),origin_cpu_s=60)])
        for key,value in [('usage_usec',-1),('oom_kill',1),('restarts',1),('identity','changed')]:
            bad=copy.deepcopy(s); bad['resource_windows'][0]['egress_end'][key]=value
            out=r.build_m5(bad); self.assertEqual(out['status'],'INVALID',key)
            self.assertFalse(out['groups'][0]['cpu_bottleneck_candidates']); self.assertFalse(out['saturation'])
        del s['resource_windows'][0]['egress_end']['usage_usec']
        self.assertEqual(r.build_m5(s)['status'],'PARTIAL')

    def test_nonoverlapping_guests_degrade(self):
        a=run(); a.update(success=60,verified=60,failed=0,errors={})
        b=dict(a,start_at_s=160,end_at_s=220)
        s=dict(runs=[a,b],resource_windows=[dict(group=0,wall_s=60,egress_start=sample(),egress_end=sample(60),origin_cpu_s=60)])
        self.assertEqual(r.build_m5(s)['status'],'PARTIAL')

    def test_time_counter_rollback_is_invalid(self):
        rows=[sample(),sample(10),sample(20)]; rows[1]['usage_usec']=-1
        self.assertEqual(r.build_time(dict(samples=rows,duration_s=20))['status'],'INVALID')

    def test_time_trend_excludes_control_tail(self):
        rows=[sample(t) for t in (0,10,20,30)];rows[-1]['memory_current']=10000
        out=r.build_time(dict(samples=rows,duration_s=20))
        self.assertEqual(out['status'],'OK')
        self.assertEqual(out['trend']['memory_current']['slope'],0)
        self.assertEqual(out['trend']['memory_current']['n'],3)

    def test_time_recovery_uses_idle_gate_snapshot(self):
        rows=[dict(sample(t),memory_current=150) for t in (1,10)]
        recovery=dict(sample(20),memory_current=105)
        out=r.build_time(dict(samples=rows,recovery=recovery,duration_s=10,
                             resource_windows=[dict(egress_start=sample())]))
        self.assertEqual(out['recovery_delta']['memory_current'],5)

    def test_m9_cost_requires_external_driver(self):
        s=dict(points=[dict(target=4,registered=4,acked=4,active=4,memory_current=20,anon=10)],cleanup_ok=True)
        self.assertNotIn('per_subject_fit',r.build_m9(s))
        s['resource_scope']='egress_only_external_driver'
        self.assertIn('egress_per_subject_fit',r.build_m9(s))

    def test_m9_sample_rollback_invalidates_point(self):
        a=dict(target=4,registered=4,acked=4,active=4,memory_current=100,anon=50,resource_sample=sample(10))
        b=dict(a,target=8,registered=8,acked=8,active=8,resource_sample=sample(1))
        out=r.build_m9(dict(points=[a,b],cleanup_ok=True,resource_scope='egress_only_external_driver'))
        self.assertEqual(out['status'],'INVALID')
        self.assertEqual(out['egress_per_subject_fit']['anon']['n'],1)

    def test_full_group_lifetime_exceeds_hour(self):
        tools=module('supplemental-tools')
        env=dict(SUP_CONCURRENCIES='1 16 64 256',SUP_REPEATS='3',SUP_BODY_BYTES='0 65536',SUP_LOAD_S='60',SUP_WARMUP_S='10',SUP_SOAK_S='7200',SUP_RECOVERY_S='30',SUP_CHURN_S='1800',SUP_IDLE_S='20')
        self.assertGreater(tools.lifetime_seconds(env,'m5'),72*70)
        self.assertGreater(tools.lifetime_seconds(env,'m8'),7200)
        self.assertGreater(tools.lifetime_seconds(env,'m9'),4*3600)


from test_credential_bound import ShellCase

class Orchestration(ShellCase):
    def test_default_hour_and_supplemental_ttl_hook(self):
        body=r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
CB_TEMPLATE_ID=template; CB_CLIENT_SRC=/tmp/client; CB_GUEST_DIR=/tmp; CB_SANDBOXES=()
wait_for() { :; }
cb_sandbox_uid() { echo uid; }
osb_api() {
 case "$*" in
  *'sandbox create'*) printf '%s\n' "$*" >> "$CALLS"; printf '{"id":"id"}';;
  *'command run'*version*) echo 'CBV-CLIENT 1';;
 esac
}
cb_create_sandbox base /tmp/policy
CB_SANDBOX_TIMEOUT=22200s
CB_CREATE_READBACK_HOOK=check_hook
check_hook() { echo "readback $1" >> "$CALLS"; }
cb_create_sandbox supplement /tmp/policy
'''
        self.sourced(body,OCI_STACK='0')
        calls=self.calls_made()
        self.assertIn('--timeout 1h ',calls)
        self.assertIn('--timeout 22200s ',calls)
        self.assertEqual(calls.count('readback id'),1)

    def test_matrix_is_288_actual_load_calls(self):
        body=r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_RAW="$WORK";SUP_CPU_LIMITS='500m 2';SUP_CONCURRENCIES='1 16 64 256';SUP_BODY_BYTES='0 65536';SUP_REPEATS=3;SUP_LOAD_S=60
sup_spec() { :; };sup_pair() { :; };sup_load_guests() { :; };sup_report() { :; };bench_json_set() { :; }
sup_pool() { BENCH_LEG="$1"; }
sup_load_pair() { printf '%s\n' "$BENCH_LEG|$7|$2|$3|$8|$5|$6" >> "$CALLS"; }
sup_m5
'''
        self.sourced(body,OCI_STACK='0')
        rows=self.calls_made().splitlines()
        expected={'|'.join(map(str,(m,cpu,c,conn,mix,body,rep)))
                  for m in ('all','credential-bound') for cpu in ('500m','2') for c in (1,16,64,256)
                  for conn in ('new','keep-alive') for mix,body in ((5,0),(5,65536),(100,0)) for rep in (1,2,3)}
        self.assertEqual(len(rows),288)
        self.assertEqual(set(rows),expected)

    def test_sampler_failure_terminates_owner(self):
        body=r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_OWNER_PID=123;SUP_RAW="$WORK";SUP_DIR="$WORK"
sup_sample() { return 1; }
kill() { printf '%s\n' "$*" >> "$CALLS"; }
if sup_sample_loop m8 1 "$WORK/absent-stop" 1; then exit 2; fi
'''
        self.sourced(body,OCI_STACK='0')
        self.assertIn('-TERM 123',self.calls_made())

    def test_gate_sampling_precedes_result_collection(self):
        body=r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_DIR="$WORK/report";SUP_RAW="$SUP_DIR/raw";mkdir -p "$SUP_RAW"
SUP_SMOKE=true;SUP_LOAD_GUESTS=2;SUP_LOAD_S=2;SUP_IDLE_S=1;SUP_WARMUP_S=1;SUP_RATE_B=0;SUP_CHURN_EVERY=0;SUP_SEQ=0
SUP_SAMPLE_ID=same;SUP_CLIENT_ATTEMPTS=1;SUP_LOAD_IDS=(a b);BENCH_B=a;BENCH_POD=pod;SUP_GATE_URL=http://fixture;SUP_CRED=x;SUP_CODE=x;BENCH_LEG=all
sup_spec m5
sup_start() { echo "start $2" >> "$CALLS"; }
sup_fetch() { echo "fetch $2" >> "$CALLS";printf '{"success":1,"verified":1,"failed":0,"wall_s":2,"cpu_s":2,"start_at_s":100,"end_at_s":102}' > "$SUP_RAW/$2.json"; }
bench_wait() { echo ready >> "$CALLS"; }
sup_gate() { echo "$1" >> "$CALLS";printf '{"start_at_s":100}'; }
bench_egress_identity() { echo same; }
bench_egress_restarts() { echo 0; }
kubectl() { cat "$SAMPLER_JSON"; }
docker() { cat "$SAMPLER_JSON"; }
SUP_TIME_KEY=m5;SUP_TIME_OFFSET=0;SUP_TIME_INTERVAL=1
sup_sample_loop() { printf '{"t_s":1}\n{"t_s":3}\n' > "$SUP_RAW/$1-samples.jsonl"; }
sup_load_pair m5 2 keep-alive 2 0 1 500m 5
cat "$SUP_RAW/m5-spec.json"
'''
        snapshots=dict(start=sample(),end=sample(2),scheduled_start_s=100)
        f=Path(self.tmp)/'sampler.json';f.write_text(json.dumps(snapshots))
        out=self.sourced(body,OCI_STACK='0',SAMPLER_JSON=str(f))
        spec=json.loads(out.stdout)
        self.assertEqual(spec['resource_windows'][0]['wall_s'],2)
        self.assertEqual(len(spec['runs']),2)
        self.assertEqual([x['t_s'] for x in spec['samples']],[1,2])
        calls=self.calls_made().splitlines()
        release=calls.index('release',calls.index('release')+1)
        self.assertTrue(all(i>release for i,v in enumerate(calls) if v.startswith('fetch m5-measured')))

class Readback(unittest.TestCase):
    def test_api_expiry_readback_rejects_short_lifetime(self):
        import datetime
        tools=module('supplemental-tools'); now=datetime.datetime(2026,1,1,tzinfo=datetime.timezone.utc)
        self.assertTrue(tools.lifetime_readback(dict(expires_at='2026-01-01T06:10:00Z'),21600,now)['api_readback'])
        with self.assertRaises(ValueError):tools.lifetime_readback(dict(expires_at='2026-01-01T01:00:00Z'),21600,now)

    def test_matrix_has_exactly_288_points(self):
        tools=module('supplemental-tools');cases=tools.m5_cases(dict(SUP_BODY_BYTES='0 65536'))
        self.assertEqual(cases,[(5,0),(5,65536),(100,0)])
        self.assertEqual(2*2*4*2*len(cases)*3,288)
        source=(ROOT/'supplemental-bench.sh').read_text()
        self.assertIn('SUP_CONCURRENCIES:-1 16 64 256',source)
        self.assertIn('seq 1 "$SUP_BURST_REPEATS"',source)

    def test_fixture_gate_uses_direct_transport(self):
        import os,threading
        from unittest.mock import patch
        origin=module('supplemental-origin');tools=module('supplemental-tools')
        server=origin.build_gate_server(0,host='127.0.0.1');thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with patch.dict(os.environ,{'http_proxy':'http://127.0.0.1:9','HTTP_PROXY':'http://127.0.0.1:9','no_proxy':'','NO_PROXY':''}):
                result=tools.gate_call('http://127.0.0.1:'+str(server.server_address[1]),'status','test')
                self.assertEqual(result['ready'],0)
        finally:server.shutdown();server.server_close();thread.join(5)

    def test_sampler_handles_exited_process_and_marks_missing_fd(self):
        from unittest.mock import Mock
        sampler=module('supplemental-sampler')
        alive=Mock();alive.iterdir.return_value=iter([1,2])
        exited=Mock();exited.iterdir.side_effect=FileNotFoundError
        self.assertEqual(sampler.descriptor_count([exited,alive]),2)
        denied=Mock();denied.iterdir.side_effect=PermissionError
        self.assertIsNone(sampler.descriptor_count([denied]))

    def test_sample_guard_writes_invalid_and_stops(self):
        import subprocess,sys
        with tempfile.TemporaryDirectory() as d:
            last=Path(d)/'last';invalid=Path(d)/'invalid'
            last.write_text(json.dumps(sample(10)))
            proc=subprocess.run([sys.executable,str(ROOT/'supplemental-tools.py'),'sample-check',str(last),str(invalid)],
                input=json.dumps(sample(1)),text=True,capture_output=True)
            self.assertNotEqual(proc.returncode,0)
            self.assertEqual(json.loads(invalid.read_text())['status'],'INVALID')

    def test_m9_driver_has_no_product_sampler(self):
        source=(ROOT/'supplemental-subjects.py').read_text()
        self.assertNotIn('/sys/fs/cgroup',source)
        self.assertNotIn('nft',source)
        shell=(ROOT/'supplemental-bench.sh').read_text()
        self.assertIn('python3 "$SUP_SELF_DIR/supplemental-subjects.py"',shell)
        self.assertIn('port-forward --address 127.0.0.1',shell)
        self.assertIn('usage_excluding_prior_enumeration_usec',shell)

if __name__=='__main__': unittest.main()
