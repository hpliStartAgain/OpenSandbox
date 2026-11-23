# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0
"""Path contradiction stop gates and recovery evidence."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from test_supplemental_lifecycle_resources import module, sample, burst
from test_credential_bound import ShellCase

r = module('supplemental-report')

class Reports(unittest.TestCase):
    def test_recovery_requires_final_sample_in_tolerance(self):
        s=burst(); tier=s['tiers'][0]
        tier['resource_samples'].append(dict(sample(3),phase='released',fd=100))
        out=r.build_m7(s)
        self.assertEqual(out['status'],'PARTIAL')
        self.assertFalse(out['tiers'][0]['resource_recovery']['recovered'])
        self.assertIsNone(out['tiers'][0]['resource_recovery']['recovery_s'])

    def test_null_or_missing_errors_degrade(self):
        for errors in (None, [], 'missing'):
            s=burst(); s['runs'][0]['errors']=errors
            self.assertIn(r.build_m7(s)['status'],('MISSING','PARTIAL'))
        s=burst(); del s['runs'][0]['errors']
        self.assertIn(r.build_m7(s)['status'],('MISSING','PARTIAL'))

    def test_positive_leak_survives_sampler_overhead(self):
        mib=1024*1024
        idle=dict(sample(),memory_current=100*mib,anon=60*mib)
        window=dict(sample(1),memory_current=116*mib,anon=76*mib)
        rows=[window,dict(sample(10),memory_current=124*mib,anon=84*mib)]
        recovery=dict(sample(20),memory_current=108*mib,anon=68*mib)
        s=dict(samples=rows,duration_s=10,recovery=recovery,idle_baseline=idle,
               resource_windows=[dict(egress_start=window)])
        for key in ('m6','m8'):
            out=r.build(key,s)
            self.assertEqual(out['recovery_delta']['memory_current'],8*mib)
            self.assertEqual(out['recovery_delta']['anon'],8*mib)
        del s['idle_baseline']
        out=r.build_time(s)
        self.assertNotEqual(out['status'],'OK')
        self.assertEqual(out['recovery_delta'],{})

    def test_expected_subject_overflow(self):
        from test_supplemental_capacity_plateau import overflow_spec
        s=overflow_spec('SET')
        out=r.build_m9(s)
        self.assertEqual(out['status'],'OK')
        self.assertEqual(out['points'][0]['outcome'],'expected_overflow')
        for field,value in [('capacity_rejections',0),('capacity_rejections',2),('rejections',[]),('acked',4095)]:
            bad=copy.deepcopy(s);bad['points'][0][field]=value
            self.assertNotEqual(r.build_m9(bad)['status'],'OK')
        s['recovery_ok']=False
        self.assertNotEqual(r.build_m9(s)['status'],'OK')

    def test_m7_null_tier_evidence_degrades(self):
        for field in ('resource_samples','resource_tolerances','budget','expected_success','expected_rejections'):
            s=burst(); s['tiers'][0][field]=None
            self.assertNotEqual(r.build_m7(s)['status'],'OK')
        for field in ('success','failed','attempted'):
            s=burst(); s['runs'][0][field]=None
            self.assertNotEqual(r.build_m7(s)['status'],'OK')

    def test_overflow_retries_rejected_identity(self):
        from test_supplemental_capacity_plateau import Capacity
        out,_,_=Capacity().drive(set_rejection=True)
        self.assertTrue(out['recovery_ok'])
        self.assertEqual(out['recovery']['object_index'],2)

    def test_staged_entry_calibrates_m8_after_m5(self):
        tools=module('supplemental-tools')
        env={k:'1' for k in ('SUP_REPEATS','SUP_LOAD_S','SUP_WARMUP_S','SUP_IDLE_S','SUP_CHURN_S','SUP_SOAK_S',
            'SUP_SOAK_CONCURRENCY','SUP_RECOVERY_S','SUP_SCALE_PROBES','SUP_CLIENT_ATTEMPTS','SUP_BURST_REPEATS',
            'SUP_RESOURCE_RECOVERY_S','SUP_RESOURCE_INTERVAL_S','SUP_LOAD_GUESTS','SUP_BLOCKS')}
        env.update(SUP_MEASUREMENTS='m10 m3x m5 m6 m7 m9',SUP_SMOKE='false',SUP_BODY_BYTES='0',SUP_CPU_LIMITS='500m',
                   SUP_CONCURRENCIES='1',SUP_BURSTS='2',SUP_SUBJECT_STEPS='4',SUP_SOAK_ANALYSIS_S='0',
                   SUP_SOAK_RATE_ALL='0',SUP_SOAK_RATE_CB='0')
        tools.validate(env)
        env['SUP_MEASUREMENTS']='m8'
        with self.assertRaises(ValueError):tools.validate(env)
        env.update(SUP_SOAK_RATE_ALL='100',SUP_SOAK_RATE_CB='200')
        tools.validate(env)
        self.assertIn('SUP_MEASUREMENTS:-m10 m3x m5 m6 m7 m9}',(Path(tools.__file__).parent/'supplemental-bench.sh').read_text())

    def test_m8_reports_actual_target_ratio(self):
        s=dict(samples=[sample(),sample(10)],duration_s=10,settings=dict(rate_rps=20),
               runs=[dict(success=80,wall_s=10)],idle_baseline=sample(),recovery=sample(20))
        out=r.build('m8',s)
        self.assertEqual(out['actual_rps'],8)
        self.assertEqual(out['actual_to_target_rate_ratio'],.4)

class StopGate(ShellCase):
    def test_first_warm_or_measured_contradiction_stops_matrix_and_cleans(self):
        for phase in ('warm','measured'):
            Path(self.calls).write_text('')
            body=r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_DIR="$WORK/report-PHASE";SUP_RAW="$SUP_DIR/raw";mkdir -p "$SUP_RAW"
SUP_SMOKE=true;SUP_LOAD_GUESTS=1;SUP_LOAD_S=2;SUP_IDLE_S=1;SUP_WARMUP_S=1;SUP_RATE_B=0;SUP_CHURN_EVERY=0;SUP_SEQ=0
SUP_SAMPLE_ID=same;SUP_CLIENT_ATTEMPTS=1;BENCH_B=a;BENCH_POD=pod;SUP_GATE_URL=http://fixture
SUP_CRED=x;SUP_CODE=x;SUP_CPU_LIMITS=500m;SUP_CONCURRENCIES='1 2';SUP_BODY_BYTES=0;SUP_REPEATS=1
sup_pool() { BENCH_LEG="$1"; };sup_pair() { :; };sup_load_guests() { SUP_LOAD_IDS=(a); }
sup_start() { echo "start $2" >> "$CALLS"; }
bench_guest_fetch() { local bad=0; [[ "$2" != *'-PHASE-'* ]] || bad=1; printf '{"success":1,"contradictions":%s}' "$bad" > "$3"; }
bench_wait() { shift; "$@"; }
sup_gate_ready() { return 0; }
sup_gate() { printf '{"start_at_s":100}'; }
bench_egress_identity() { echo same; };bench_egress_restarts() { echo 0; }
kubectl() { cat "$SAMPLER_JSON"; };docker() { cat "$SAMPLER_JSON"; }
SUP_ORIGINAL_MODE=all;SUP_ORIGINAL_WARM=1
cb_cleanup() { echo cleaned >> "$CALLS"; }
bench_pool_restore() { echo restored >> "$CALLS"; }
trap 'sup_cleanup' EXIT
sup_m5
echo continued >> "$CALLS"
'''.replace('PHASE',phase)
            f=Path(self.tmp)/'sampler.json';f.write_text(json.dumps(dict(start=sample(),end=sample(2),scheduled_start_s=100)))
            out=self.sourced(body,check=False,OCI_STACK='0',SAMPLER_JSON=str(f))
            self.assertNotEqual(out.returncode,0)
            calls=self.calls_made()
            self.assertIn('cleaned',calls)
            self.assertIn('restored',calls)
            self.assertNotIn('continued',calls)
            self.assertEqual(calls.count('start '),1 if phase=='warm' else 2)
            report=json.loads((Path(self.work)/('report-'+phase)/'m5.json').read_text())
            self.assertEqual(report['status'],'INVALID')
            self.assertTrue(list((Path(self.work)/('report-'+phase)/'raw').glob('*'+phase+'*.json')))

    def test_all_measurement_result_gates_stop_and_preserve(self):
        for key in ('m3x','m6','m7','m8','m9'):
            body=r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_DIR="$WORK/KEY";SUP_RAW="$SUP_DIR/raw";mkdir -p "$SUP_RAW"
printf '{"contradictions":1}' > "$SUP_RAW/result.json"
trap 'echo cleaned >> "$CALLS"' EXIT
sup_path_check KEY "$SUP_RAW/result.json"
echo continued >> "$CALLS"
'''.replace('KEY',key)
            out=self.sourced(body,check=False,OCI_STACK='0')
            self.assertNotEqual(out.returncode,0)
            self.assertEqual(json.loads((Path(self.work)/key/(key+'.json')).read_text())['status'],'INVALID')
            self.assertNotIn('continued',self.calls_made())

    def test_time_recovery_uses_same_sampler_path(self):
        body=r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_DIR="$WORK/time";SUP_RAW="$SUP_DIR/raw";mkdir -p "$SUP_RAW"
SUP_SMOKE=true;SUP_LOAD_GUESTS=1;SUP_LOAD_S=2;SUP_IDLE_S=1;SUP_CHURN_S=3;SUP_SOAK_S=5;SUP_SOAK_ANALYSIS_S=0;SUP_RECOVERY_S=1
SUP_SOAK_RATE_ALL=10;SUP_SOAK_RATE_CB=10;SUP_SOAK_CONCURRENCY=1
sup_pool() { BENCH_LEG="$1"; };sup_pair() { :; };sleep() { :; }
sup_sample() { echo sample >> "$CALLS"; printf '{"memory_current":100}'; }
sup_load_pair() { echo load >> "$CALLS"; }
sup_report() { printf '{}' > "$SUP_DIR/$1.json"; }
sup_time m6
sup_time m8
cat "$SUP_RAW/m8-all-spec.json"
'''
        out=self.sourced(body,OCI_STACK='0')
        spec=json.loads(out.stdout)
        self.assertEqual(spec['idle_baseline'],spec['recovery'])
        self.assertEqual(self.calls_made().splitlines(),['sample','load','load','load','sample']*2+['sample','load','sample']*2)

    def test_restart_start_reading_is_not_overwritten(self):
        body=r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_DIR="$WORK/report";SUP_RAW="$SUP_DIR/raw";mkdir -p "$SUP_RAW"
SUP_SMOKE=true;SUP_LOAD_GUESTS=1;SUP_LOAD_S=2;SUP_IDLE_S=1;SUP_WARMUP_S=1;SUP_RATE_B=0;SUP_CHURN_EVERY=0;SUP_SEQ=0
SUP_SAMPLE_ID=same;SUP_CLIENT_ATTEMPTS=1;SUP_LOAD_IDS=(a);BENCH_B=a;BENCH_POD=pod;SUP_GATE_URL=http://fixture;SUP_CRED=x;SUP_CODE=x;BENCH_LEG=all
sup_spec m5
sup_start() { :; }
bench_guest_fetch() { printf '{"success":1,"contradictions":0}' > "$3"; }
bench_wait() { shift; "$@"; };sup_gate_ready() { return 0; }
sup_gate() { printf '{"start_at_s":100}'; }
bench_egress_identity() { echo same; }
bench_egress_restarts() { if [[ -e "$WORK/read" ]]; then echo 1; else touch "$WORK/read";echo 0;fi; }
kubectl() { cat "$SAMPLER_JSON"; };docker() { cat "$SAMPLER_JSON"; }
trap 'echo cleaned >> "$CALLS"' EXIT
sup_load_pair m5 1 keep-alive 2 0 1 500m 5
'''
        f=Path(self.tmp)/'sampler.json';f.write_text(json.dumps(dict(start=sample(),end=sample(2),scheduled_start_s=100)))
        out=self.sourced(body,check=False,OCI_STACK='0',SAMPLER_JSON=str(f))
        self.assertNotEqual(out.returncode,0)
        self.assertEqual(json.loads((Path(self.work)/'report/invalid-resource.json').read_text())['status'],'INVALID')

if __name__=='__main__': unittest.main()
