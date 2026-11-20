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


if __name__ == '__main__':
    unittest.main()
