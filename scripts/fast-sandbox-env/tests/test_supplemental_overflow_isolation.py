# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0
"""M7 subject isolation, overflow coverage and terminal gate handling."""
import copy
import unittest
from test_supplemental_lifecycle_resources import module, burst
from test_credential_bound import ShellCase
r=module('supplemental-report');c=module('supplemental-client')


def distributed(successes=(1,1), per=1, process=8):
    s=burst();s['runs']=[];t=s['tiers'][0]
    t.update(allocations=[2,2],members=[dict(participant='guest-'+str(i),allocation=2) for i in range(2)],
             budget=dict(admission_enabled=True,per_subject=per,process=process,available=min(2*min(2,per),process)))
    expected=t['budget']['available'];t.update(expected_success=[expected,expected],expected_rejections=[4-expected,4-expected],server_budget_denials=4-sum(successes))
    for i,n in enumerate(successes):
        s['runs'].append(dict(participant='guest-'+str(i),group=0,attempted=2,success=n,failed=2-n,verified=n,released_alive=n,
            errors={'handshake/tls_closed':2-n} if n<2 else {},contradictions=0,request_ms=[1]*n,
            scheduled_start_s=100,start_lag_s=.01,memory_preflight=c.memory_preflight(2,300*1024*1024)))
    return s


class Members(unittest.TestCase):
    def test_per_subject_distribution_and_reordering(self):
        s=distributed();self.assertEqual(r.build_m7(s)['status'],'OK')
        s['runs'].reverse();self.assertEqual(r.build_m7(s)['status'],'OK')
        self.assertNotEqual(r.build_m7(distributed((2,0)))['status'],'OK')

    def test_process_constraint_preserves_subject_bounds(self):
        self.assertEqual(r.build_m7(distributed((2,0),per=2,process=2))['status'],'OK')
        self.assertNotEqual(r.build_m7(distributed((2,0),per=1,process=2))['status'],'OK')

    def test_each_counter_is_checked(self):
        for field,value in [('attempted',3),('failed',0),('verified',0),('released_alive',0),('success',-1)]:
            s=distributed();s['runs'][0][field]=value
            self.assertNotEqual(r.build_m7(s)['status'],'OK',(field,value))
        s=distributed();s['runs'][0]['errors']={'handshake/tls_closed':2}
        self.assertNotEqual(r.build_m7(s)['status'],'OK')

    def test_anonymous_member_identity_is_required_and_unique(self):
        for value in (None,'guest-1','unknown'):
            s=distributed();s['runs'][0]['participant']=value
            self.assertNotEqual(r.build_m7(s)['status'],'OK')

    def test_overflow_coverage_gate(self):
        s=distributed();s['require_single_subject_overflow']=True
        self.assertNotEqual(r.build_m7(s)['status'],'OK')
        s['overflow_spec']=dict(runs=[],tiers=[],single_subject_overflow=True)
        self.assertNotEqual(r.build_m7(s)['status'],'OK')


class GateRace(ShellCase):
    def test_second_memory_check_invalid_stops_gate_and_cleans(self):
        result=self.sourced(r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_DIR="$WORK/report"; SUP_RAW="$SUP_DIR/raw"; mkdir -p "$SUP_RAW"
SUP_CLIENT_ATTEMPTS=3; CB_GUEST_DIR=/guest; SUP_M7_IDS=(b b2); SUP_M7_NAMES=(first second)
trap 'touch "$WORK/cleaned"' EXIT
printf '{"v":1,"status":"INVALID","memory_preflight":{"status":"INVALID"}}' > "$SUP_RAW/second-ready.json"
bench_guest_fetch() { return 1; }
sup_gate_ready() { return 1; }
sleep() { echo SLEPT; }
if (trap 'touch "$WORK/cleaned"' EXIT; sup_m7_wait_gate gate 2); then exit 3; fi
test -f "$WORK/cleaned"
cat "$SUP_DIR/m7.json"
''',OCI_STACK='0')
        self.assertIn('"INVALID"',result.stdout);self.assertNotIn('SLEPT',result.stdout)



def overflow():
    s=burst();a=s['runs'][0]
    a.update(mode='credential-bound',participant='guest-0',attempted=3,success=2,verified=2,failed=1,released_alive=2,errors={'handshake/tls_closed':1},scheduled_start_s=100,start_lag_s=0,memory_preflight=c.memory_preflight(3,2*1024**3))
    t=s['tiers'][0];t.update(allocations=[3],members=[dict(participant='guest-0',allocation=3)],server_budget_denials=2,expected_rejections=[1,1])
    s.update(single_subject_overflow=True,smoke=True,large_guest=dict(mem_total_bytes=2*1024**3,pool=dict(scheduled=True,sandbox_limit_memory_bytes=2*1024**3,budget_sufficient=True),full_boundary_preflight=c.memory_preflight(2049,2*1024**3)),
        overflow_probes=dict(target_participant='guest-0',unbound=dict(participant='probe-unbound',attempted=1,success=1,verified=1,failed=0,contradictions=0),new_bound=dict(participant='probe-bound',attempted=1,success=0,failed=1,contradictions=0,errors={'handshake/tls_closed':1})))
    return s


class Overflow(unittest.TestCase):
    def test_positive_and_coverage_propagation(self):
        self.assertEqual(r.build_m7(overflow())['status'],'OK')
        s=distributed();s.update(require_single_subject_overflow=True,overflow_spec=overflow())
        self.assertEqual(r.build_m7(s)['status'],'OK')
        s['overflow_spec']['runs'][0]['released_alive']=1
        self.assertNotEqual(r.build_m7(s)['status'],'OK')

    def test_guest_feasibility_and_separate_probes_required(self):
        for key,value in [('mem_total_bytes',512*1024**2),('full_boundary_preflight',{})]:
            s=overflow();s['large_guest'][key]=value;self.assertNotEqual(r.build_m7(s)['status'],'OK')
        s=overflow();s['overflow_probes']['new_bound']['participant']='guest-0'
        self.assertNotEqual(r.build_m7(s)['status'],'OK')
        s=overflow();s['overflow_probes']['new_bound']['errors']={'recv/timeout':1}
        self.assertNotEqual(r.build_m7(s)['status'],'OK')
        s=overflow();s['smoke']=False
        self.assertNotEqual(r.build_m7(s)['status'],'OK')

    def test_live_pool_derived_budget(self):
        tools=module('supplemental-tools')
        pool=dict(spec=dict(sandboxResources=dict(mode='ResourceAware',memory='512Mi',overcommitRatio=dict(memory='2')),maxSandboxesPerPod=8))
        items=[dict(spec=dict(resources=dict(limits=dict(memory='2Gi'))),status=dict(runtime=dict(state='Ready'),conditions=[dict(type='Ready',status='True')],placement=dict(fastletPodUID='same'))) for _ in range(2)]
        p=tools.m7_pool(pool,dict(items=items));self.assertTrue(p['budget_sufficient']);self.assertTrue(p['scheduled'])
        self.assertEqual(p['per_fastlet_memory_budget_bytes'],2*1024**3)
        items.append(copy.deepcopy(items[0]));self.assertFalse(tools.m7_pool(pool,dict(items=items))['budget_sufficient'])


class OrchestrationRace(ShellCase):
    def test_preflight_passes_burst_recheck_invalid_no_gate_release(self):
        result=self.sourced(r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_DIR="$WORK/report"; SUP_RAW="$SUP_DIR/raw"; mkdir -p "$SUP_RAW"
SUP_BURST_IDS=(b b2); SUP_SEQ=0; SUP_GATE_URL=fixture; CB_GUEST_DIR=/guest; BENCH_B=b
BENCH_POD=p; RESOURCE_NS=x; SUP_CLIENT_ATTEMPTS=3; SUP_RESOURCE_RECOVERY_S=1
bench_ns() { echo 1000000000; }; sup_sample() { echo '{}'; }
kubectl() { echo '{"spec":{"containers":[{"name":"egress","env":[]}]}}'; }
sup_fetch() { echo '{"v":1,"status":"OK"}' > "$SUP_RAW/$2.json"; }
sup_start() {
 echo "$8" >> "$WORK/starts"
 if [[ "$8" == burst && "$1" == b2 ]]; then echo '{"v":1,"status":"INVALID","memory_preflight":{"status":"INVALID"}}' > "$SUP_RAW/$2-ready.json"; fi
}
bench_guest_fetch() { return 1; }; sup_gate_ready() { return 1; }
sup_gate() { echo RELEASED; }; sleep() { echo SLEPT; }
if (trap 'touch "$WORK/cleaned"' EXIT; sup_m7_tier credential-bound 4 1); then exit 3; fi
test -f "$WORK/cleaned"; cat "$SUP_DIR/m7.json"; cat "$WORK/starts"
''',OCI_STACK='0')
        self.assertIn('"INVALID"',result.stdout);self.assertNotIn('SLEPT',result.stdout);self.assertNotIn('RELEASED',result.stdout)
        self.assertEqual(result.stdout.count('memory-check'),2);self.assertEqual(result.stdout.count('burst'),2)



class AdditionalGates(ShellCase):
    def test_client_terminal_file_stops_gate(self):
        result=self.sourced(r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_DIR="$WORK/report"; SUP_RAW="$SUP_DIR/raw"; mkdir -p "$SUP_RAW"
SUP_CLIENT_ATTEMPTS=3; CB_GUEST_DIR=/guest; SUP_M7_IDS=(b); SUP_M7_NAMES=(one)
echo '{"v":1,"status":"FAILED"}' > "$SUP_RAW/one.json"
bench_guest_fetch() { return 1; }; sup_gate_ready() { return 1; }; sleep() { echo SLEPT; }
if (sup_m7_wait_gate gate 1); then exit 3; fi
cat "$SUP_DIR/m7.json"
''',OCI_STACK='0')
        self.assertIn('"INVALID"',result.stdout);self.assertNotIn('SLEPT',result.stdout)


class MixedShape(unittest.TestCase):
    def test_large_bound_small_probe_fit_live_default_pool(self):
        tools=module('supplemental-tools')
        pool=dict(spec=dict(sandboxResources=dict(mode='ResourceAware',cpu='1',memory='512Mi',overcommitRatio=dict(cpu='2',memory='2')),maxSandboxesPerPod=5))
        items=[dict(spec=dict(resources=dict(limits=dict(cpu='1',memory=m))),status=dict(runtime=dict(state='Ready'),conditions=[dict(type='Ready',status='True')],placement=dict(fastletPodUID='same'))) for m in ('512Mi','2Gi')]
        out=tools.m7_pool(pool,dict(items=items));self.assertTrue(out['budget_sufficient'])
        self.assertEqual(out['sandbox_limit_memory_bytes'],2*1024**3)
        self.assertEqual(out['committed_bytes'],out['per_fastlet_memory_budget_bytes'])
        items[1]['status']['conditions'][0]['status']='False'
        self.assertFalse(tools.m7_pool(pool,dict(items=items))['scheduled'])


if __name__=='__main__':unittest.main()
