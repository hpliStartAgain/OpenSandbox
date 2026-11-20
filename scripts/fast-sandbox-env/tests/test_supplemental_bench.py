"""Supplemental statistics and evidence classification, no live services."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('supplemental_report', ROOT / 'supplemental-report.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class Reports(unittest.TestCase):
    def test_statuses(self):
        for key in r.BUILDERS:
            self.assertEqual(r.build(key, {'not_run': True})['status'], 'NOT_RUN')
            self.assertEqual(r.build(key, {})['status'], 'MISSING')

    def test_pair_ci_uses_blocks(self):
        blocks = [{'mode': mode, 'p50_ms': value} for mode, value in
                  zip('ABBAABBA', [10, 12, 14, 10, 20, 26, 28, 20])]
        out = r.paired_blocks(blocks)
        self.assertEqual(out['differences_ms'], [2, 4, 6, 8])
        self.assertEqual(out['n_pairs'], 4)
        self.assertAlmostEqual(out['mean_ms'], 5)
        self.assertAlmostEqual(out['ci95_ms'][1], 9.1085, places=3)
        self.assertIsNone(r.paired_blocks(blocks[:2])['ci95_ms'])

    def test_wrong_sequence_invalid(self):
        self.assertEqual(r.build('m10', {'blocks': [{'mode': 'B', 'p50_ms': 1}]})['status'], 'INVALID')

    def test_m10_live_mode_mismatch_is_invalid(self):
        out = r.build('m10', {'blocks': [{'mode': 'A', 'p50_ms': 1, 'live_mode': 'credential-bound'}]})
        self.assertEqual(out['status'], 'INVALID')

    def test_soak_slope_window(self):
        rows = [{'t_s': t, 'memory_current': 100 + t * 2, 'anon': 50 + t,
                 'fd': 10, 'oom_kill': 0, 'restarts': 0} for t in [0, 1800, 3600, 7200]]
        out = r.build('m8', {'samples': rows, 'analysis_start_s': 1800, 'duration_s': 7200})
        self.assertEqual(out['status'], 'OK')
        self.assertEqual(out['trend']['memory_current']['slope'], 2)
        self.assertEqual(out['trend']['memory_current']['n'], 3)

    def test_oom_is_invalid(self):
        rows = [{'t_s': i, 'memory_current': i, 'anon': i, 'fd': 1, 'oom_kill': i, 'restarts': 0} for i in range(2)]
        self.assertEqual(r.build('m6', {'samples': rows, 'duration_s': 1})['status'], 'INVALID')

    def test_short_soak_partial(self):
        rows = [{'t_s': i, 'memory_current': 1, 'anon': 1, 'fd': 1, 'oom_kill': 0, 'restarts': 0} for i in range(2)]
        self.assertEqual(r.build('m8', {'samples': rows, 'duration_s': 7200})['status'], 'PARTIAL')

    def test_budget_needs_server_evidence(self):
        self.assertEqual(r.burst_rejections({'handshake/tls_closed': 5}, 0), {'budget': 0, 'unattributed': 5})
        self.assertEqual(r.burst_rejections({'handshake/tls_closed': 5}, 3), {'budget': 3, 'unattributed': 2})
        self.assertEqual(r.burst_rejections({'connect/timeout': 5}, 8), {'budget': 0, 'unattributed': 5})

    def test_burst_recovery_required(self):
        out = r.build('m7', {'runs': [{'attempted': 2, 'success': 2, 'failed': 0,
                         'request_ms': [1, 2], 'errors': {}, 'contradictions': 0}], 'recovered': False})
        self.assertEqual(out['status'], 'PARTIAL')

    def test_m9_counts_ack_separately(self):
        point = {'target': 4096, 'registered': 4096, 'acked': 4000, 'active': 4000}
        out = r.build('m9', {'points': [point], 'cleanup_ok': True})
        self.assertEqual(out['status'], 'PARTIAL')
        self.assertEqual(out['points'][0]['acked'], 4000)
        self.assertEqual(r.build('m9', {'points': [dict(point, acked=4097)], 'cleanup_ok': True})['status'], 'INVALID')

    def test_m9_capacity_4097(self):
        points = [{'target': 4096, 'registered': 4096, 'acked': 4096, 'active': 4096},
                  {'target': 4097, 'registered': 4097, 'acked': 4096, 'active': 4096, 'capacity_rejections': 1}]
        self.assertEqual(r.build('m9', {'points': points, 'cleanup_ok': True})['status'], 'OK')

    def test_m5_quantiles_and_failure(self):
        run = {'attempted': 4, 'success': 4, 'failed': 0, 'wall_s': 2,
               'request_ms': [1, 2, 3, 4], 'errors': {}, 'contradictions': 0}
        out = r.build('m5', {'runs': [run]})
        self.assertEqual(out['status'], 'OK')
        self.assertEqual(out['runs'][0]['rps'], 2)
        self.assertEqual(out['runs'][0]['latency_ms']['p99_9'], 4)
        self.assertEqual(r.build('m5', {'runs': [dict(run, contradictions=1)]})['status'], 'INVALID')
        self.assertEqual(r.build('m5', {'runs': [dict(run, success=0, failed=4)]})['status'], 'FAILED')

    def test_closed_report_fields(self):
        out = r.build('m5', {'runs': [{'success': 1, 'attempted': 1, 'failed': 0,
                 'wall_s': 1, 'request_ms': [1], 'secret': 'DO_NOT_COPY', 'contradictions': 0}]})
        self.assertNotIn('DO_NOT_COPY', json.dumps(out))

    def test_memory_fit_and_mix(self):
        path = {'mode': 'all', 'target': 'bound', 'points': [
                {'k': k, 'held': k, 'alive': k, 'anon': 100 + 20*k,
                 'memory_current': 200 + 30*k, 'same_process': True} for k in [0, 5, 10]]}
        out = r.build('m3x', {'paths': [path]})
        self.assertEqual(out['status'], 'OK')
        self.assertEqual(out['paths'][0]['fit']['anon']['slope'], 20)
        self.assertEqual(r.memory_mix(10, 20, .25), 12.5)

    def test_memory_bad_release_excluded(self):
        path = {'mode': 'all', 'target': 'unbound', 'points': [
                {'k': k, 'held': k, 'alive': k-1, 'anon': k, 'memory_current': k, 'same_process': True} for k in [1, 2]]}
        out = r.build('m3x', {'paths': [path]})
        self.assertEqual(out['status'], 'PARTIAL')
        self.assertIsNone(out['paths'][0]['fit']['anon']['slope'])

# Real TLS fixtures: exercise the supplemental client on disposable loopback.
import os
import subprocess
import sys
import time
from test_credential_bound_helpers import OriginFixture, der_sha256, wait_json
from test_credential_bound import ShellCase


class SupplementalClientTest(OriginFixture):
    def probe(self, mode='load', **kwargs):
        out = os.path.join(self.tmp, 'supplemental-out.json')
        args = [sys.executable, str(ROOT/'supplemental-client.py'), mode, '--host', 'echo.test',
                '--ip', '127.0.0.1', '--port', str(self.port), '--cafile', self.ca,
                '--origin-leaf', der_sha256(self.leaf), '--expect-leaf', 'origin',
                '--expect-cred', 'absent', '--out', out, '--duration', '.2', '--timeout', '2']
        for k, v in kwargs.items():
            args += ['--'+k.replace('_', '-'), str(v)]
        proc = subprocess.run(args, capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(Path(out).read_text())

    def test_new_connections_and_keepalive(self):
        for connection in ['new', 'keep-alive']:
            out = self.probe(connection=connection, concurrency=2)
            self.assertGreater(out['success'], 0)
            self.assertEqual(out['verified'], out['success'])
            self.assertEqual(out['failed'], 0)
            if connection == 'new':
                self.assertEqual(out['connections'], out['success'])
            else:
                self.assertEqual(out['connections'], 2)

    def test_burst_release_uses_the_held_connections(self):
        out = self.probe(mode='burst', concurrency=4, hold_s=.1)
        self.assertEqual(out['attempted'], 4)
        self.assertEqual(out['success'], 4)
        self.assertEqual(out['released_alive'], 4)

    def test_wrong_leaf_invalid_and_bad_ca_is_classified(self):
        out = self.probe(expect_leaf='mitm')
        self.assertGreater(out['contradictions'], 0)
        out = self.probe(cafile=self.other_ca)
        self.assertEqual(out['success'], 0)
        self.assertGreater(out['errors']['handshake/verify_failed'], 0)

    def test_mixed_hostnames_are_selected_and_classified(self):
        out = self.probe(bound_percent=0, unbound_host='echo.test', unbound_leaf='origin')
        self.assertGreater(out['success'], 0)
        self.assertEqual(out['contradictions'], 0)


class SupplementalShellTest(ShellCase):
    def test_source_does_not_change_default_pool_render(self):
        body = 'TEMPLATE_ID=tpl-1; render_pool; cp "$GEN_DIR/$POOL_PROFILE.yaml" "$WORK/before"; source "$SCRIPT_DIR/supplemental-bench.sh"; render_pool; cmp "$WORK/before" "$GEN_DIR/$POOL_PROFILE.yaml"'
        self.assertEqual(self.sourced(body, OCI_STACK='0').returncode, 0)

    def test_cpu_limit_override_preserves_requests(self):
        body = r'''
TEMPLATE_ID=tpl-1
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_CRED=unused; SUP_CODE=unused; SUP_IDLE_S=1
sup_scan() { :; }
bench_pool_apply() { cat "$1"; }
kubectl() { printf '{"items":[{"spec":{"containers":[{"name":"egress","env":[{"name":"OPENSANDBOX_EGRESS_FSB_INTERCEPTION_MODE","value":"all"}],"resources":{"limits":{"cpu":"2"}}}]}}]}'; }
wait_for() { :; }
sleep() { :; }
sup_pool all 2
'''
        import yaml
        out = self.sourced(body, OCI_STACK='0', WARM_IMAGES='0').stdout
        doc = yaml.safe_load(out)
        containers = doc['spec']['fastletTemplate']['spec']['containers']
        egress = next(c for c in containers if c['name']=='egress')
        self.assertEqual(egress['resources']['limits']['cpu'], 2)
        self.assertEqual(egress['resources']['requests']['cpu'], '100m')

    def test_m10_shell_assembles_a_block_report(self):
        body = r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_DIR="$WORK/report"; SUP_RAW="$SUP_DIR/raw"; mkdir -p "$SUP_RAW"
BENCH_DIR="$SUP_DIR"; BENCH_RAW="$SUP_RAW"
SUP_BLOCKS=2; SUP_SEQUENCE=ABBAABBA; SUP_SMOKE=true; SUP_LOAD_GUESTS=1; SUP_LOAD_S=1; SUP_IDLE_S=1
bench_ns() { echo 1000000000; }
bench_elapsed_ms() { echo 1; }
sup_pool() { BENCH_LEG="$1"; }
bench_m1() { printf '{"status":"OK","pooled_latency_ms":{"p50":2}}' > "$BENCH_DIR/m1-create.json"; }
kubectl() {
  case "$*" in
    *logs*) echo 'subject s-test: SET_BINDING applied (state=ready) total=2ms denyFirstInstall=1ms policyCommit=1ms';;
    *jsonpath*) printf 'pod-%s' "$BENCH_LEG";;
    *) printf '{"items":[{"spec":{"containers":[{"name":"egress","env":[{"name":"OPENSANDBOX_EGRESS_FSB_INTERCEPTION_MODE","value":"%s"}]}]}}]}' "$BENCH_LEG";;
  esac
}
sup_m10
cat "$SUP_DIR/m10.json"
'''
        result = self.sourced(body, OCI_STACK='0')
        self.assertEqual(result.returncode, 0, result.stderr)
        # The report writer pretty-prints JSON after its one status line.
        out = json.loads(result.stdout[result.stdout.index('{'):])
        self.assertEqual(out['status'], 'PARTIAL')
        self.assertEqual(out['paired']['n_pairs'], 1)

    def test_m7_shell_projects_the_unbound_probe(self):
        body = r'''
source "$SCRIPT_DIR/supplemental-bench.sh"
SUP_DIR="$WORK/report"; SUP_RAW="$SUP_DIR/raw"; mkdir -p "$SUP_RAW"
SUP_SMOKE=true; SUP_LOAD_GUESTS=1; SUP_LOAD_S=1; SUP_IDLE_S=1; SUP_BURSTS=2; SUP_SEQ=0; SUP_CLIENT_ATTEMPTS=1
SUP_CRED=unused; SUP_CODE=unused; CB_ORIGIN_LEAF=origin; SUP_SINCE=unused; RESOURCE_NS=unused; CB_GUEST_DIR=/tmp
sup_pool() { BENCH_LEG="$1"; }
sup_pair() { BENCH_B=b; BENCH_U=u; BENCH_POD=p; }
sup_start() { :; }
bench_wait() { :; }
bench_ns() { echo 1; }
bench_elapsed_ms() { echo 1; }
cb_until() { :; }
osb_api() { :; }
kubectl() { :; }
cb_guest_once() {
 CB_RC=0; leaf=mitm; [[ "$BENCH_LEG" != credential-bound ]] || leaf=origin
 CB_RESULT="$(printf '{"ok":true,"leaf_sha256":"%s","last":{"status":200,"origin":{"cred":"absent"}}}' "$leaf")"
}
sup_fetch() { printf '{"success":2,"attempted":2,"failed":0,"contradictions":0,"released_alive":2,"errors":{},"request_ms":[1,2]}' > "$SUP_RAW/$2.json"; }
sup_m7
cat "$SUP_DIR/m7-credential-bound.json"
'''
        result = self.sourced(body, OCI_STACK='0')
        self.assertEqual(result.returncode, 0, result.stderr)
        out = json.loads(result.stdout[result.stdout.index('{'):])
        self.assertEqual(out['status'], 'OK')
        self.assertTrue(out['passthrough_ok'])

    def test_measurements_are_opt_in(self):
        workflow = (ROOT.parents[1]/'.github/workflows/fast-sandbox-test.yml').read_text()
        self.assertNotIn('bench-supplemental', workflow)
        source = (ROOT/'integration-env.sh').read_text()
        self.assertIn('bench-supplemental)', source)


class SupplementalGlueTest(unittest.TestCase):
    def test_segments_pair_by_subject_and_discard_identity(self):
        sp = importlib.util.spec_from_file_location('supplemental_tools', ROOT/'supplemental-tools.py')
        tools = importlib.util.module_from_spec(sp); sp.loader.exec_module(tools)
        out = tools.segments('subject s-private: SET_BINDING applied (state=ready) total=8ms denyFirstInstall=3ms policyCommit=5ms\nsubject s-private: data-plane-ready, policy active applyPolicy=4ms\nsubject s-other: data-plane-ready, policy active applyPolicy=99ms')
        self.assertEqual(out['matched_subjects'], 1)
        self.assertEqual(out['incomplete_subjects'], 1)
        self.assertEqual(out['distributions']['total']['p50'], 8)
        self.assertNotIn('s-private', json.dumps(out))

    def test_synthetic_identity_uniqueness_and_fences(self):
        sp = importlib.util.spec_from_file_location('supplemental_subjects', ROOT/'supplemental-subjects.py')
        m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
        a, b = m.envelope('run', 0, 'SET_BINDING'), m.envelope('run', 1, 'SET_BINDING')
        self.assertNotEqual(a['sandbox']['uid'], b['sandbox']['uid'])
        self.assertNotEqual(a['attachment']['network']['ip'], b['attachment']['network']['ip'])
        self.assertNotEqual(a['revision']['attachmentId'], b['revision']['attachmentId'])

class AdditionalStatistics(unittest.TestCase):
    def test_histogram_nearest_rank(self):
        out = r.histogram_summary({'1.0': 2, '10.0': 1})
        self.assertEqual(out['p50'], 1)
        self.assertEqual(out['p99_9'], 10)
        self.assertEqual(out['mean'], 4)

    def test_plateau_requires_a_concurrency_increase(self):
        groups = [dict(mode='all', cpu_limit='500m', connection='new', body_bytes=0, bound_percent=100,
                       concurrency=c, rps=v, cpu_bottleneck_candidates=['egress']) for c, v in [(1, 100), (4, 400), (16, 410)]]
        out = r.saturation_points(groups)
        self.assertEqual(out[0]['status'], 'OBSERVED_PLATEAU')
        self.assertEqual(out[0]['concurrency'], 4)
        self.assertEqual(out[0]['bottleneck'], ['egress'])

    def test_m9_real_contradiction_propagates(self):
        out = r.build('m9', {'points': [{'target': 4, 'registered': 4, 'acked': 4, 'active': 4}],
                             'cleanup_ok': True, 'real_connections': {'status': 'INVALID'}})
        self.assertEqual(out['status'], 'INVALID')

    def test_expected_burst_denial_and_release_failure(self):
        run = dict(attempted=4, success=2, failed=2, errors={'handshake/tls_closed': 2},
                   contradictions=0, released_alive=2, request_ms=[1, 2])
        s = dict(runs=[run], recovered=True, passthrough_ok=True, server_budget_denials=2)
        self.assertEqual(r.build('m7', s)['status'], 'OK')
        run['released_alive'] = 1
        self.assertEqual(r.build('m7', s)['status'], 'PARTIAL')


if __name__ == '__main__':
    unittest.main()
