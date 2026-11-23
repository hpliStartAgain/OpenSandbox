# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0
"""Product-contract capacity recovery and sustained plateau regressions."""
import argparse
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_supplemental_lifecycle_resources import module

r=module('supplemental-report')
driver=module('supplemental-subjects')

def groups(curve):
    return [dict(mode='all',cpu_limit='500m',connection='keep-alive',body_bytes=0,bound_percent=5,
                 concurrency=c,rps=value,cpu_bottleneck_candidates=[],repeat=rep,status='OK')
            for c,values in zip((1,16,64,256),curve)
            for rep,value in enumerate(values if isinstance(values,list) else [values],1)]

def overflow_spec(stage='ready'):
    refusal=dict(object_index=4094,phase='initial',stage=stage,set_status=200 if stage=='ready' else 503,
        ready_status=503 if stage=='ready' else None,ready_attempt_statuses=[503] if stage=='ready' else [],
        reason='subject_capacity_exhausted',capacity_before=False,capacity_after=True,
        attribution='isolated_serial_action_status_transition')
    return dict(points=[dict(target=4097,registered=4097 if stage=='ready' else 4096,acked=4096,active=4096,
        rejections=[refusal],capacity_rejections=1,initial_capacity_log_count=1,recovery_capacity_log_count=0)],
        cleanup_ok=True,recovery_ok=True,recovery=dict(object_index=4094,released_object_index=0,release_confirmed=True,
        release_attempts=[dict(remove_status=200,ready_status=409)],attempts=[dict(set_status=200,ready_status=200)],
        final_counts=dict(registered=4096,acked=4096,active=4096)))

class Plateau(unittest.TestCase):
    def test_sustained_plateau(self):
        out=r.saturation_points(groups([100,[198,200,202],[203,205,207],[204,207,210]]))[0]
        self.assertEqual(out['status'],'OBSERVED_PLATEAU')
        self.assertEqual(out['concurrency'],16)
        self.assertEqual(out['rps'],200)

    def test_local_stall_then_growth_is_not_plateau(self):
        self.assertEqual(r.saturation_points(groups([100,200,205,400]))[0]['status'],'NOT_ESTABLISHED')

    def test_drop_then_growth_is_not_plateau(self):
        self.assertEqual(r.saturation_points(groups([100,200,50,400]))[0]['status'],'NOT_ESTABLISHED')

    def test_growth_is_not_plateau(self):
        self.assertEqual(r.saturation_points(groups([100,200,400,800]))[0]['status'],'NOT_ESTABLISHED')

    def test_single_bad_repeat_revokes_plateau(self):
        for values in ([50,205,207],[205,207,400],[50,275,275]):
            self.assertEqual(r.saturation_points(groups([100,200,values,207]))[0]['status'],'NOT_ESTABLISHED')
        rows=groups([100,200,205,207]);rows[-1]['status']='PARTIAL'
        self.assertFalse(any(x['status']=='OBSERVED_PLATEAU' for x in r.saturation_points(rows)))

class Capacity(unittest.TestCase):
    def drive(self, delayed=False, set_rejection=False, confirm=True):
        state=dict(blocked=False,removed=False,after_release=0)
        events=[]
        def request(url,p):
            i=int(p['sandbox']['uid'].rsplit('-',1)[1]);op=p['operation']
            events.append((i,op))
            if op=='REMOVE_BINDING':state['removed']=True;return 200
            if op=='LIFECYCLE_HOOK' and i==0 and state['removed']:
                return 409 if confirm else 200
            if i==2:
                if op=='SET_BINDING':
                    state['blocked']=True
                    if state['removed']:state['after_release']+=1
                    if set_rejection and (not state['removed'] or delayed and state['after_release']==1):return 503
                if op=='LIFECYCLE_HOOK' and (not state['removed'] or delayed and state['after_release']==1):return 503
            return 200
        def reasons(url):return ['subject_capacity_exhausted'] if state['blocked'] else []
        with tempfile.TemporaryDirectory() as d, patch.object(driver,'request',request),patch.object(driver,'status_reasons',reasons,create=True),patch.object(driver.time,'sleep'):
            out=driver.run(argparse.Namespace(steps=[4097],real_subjects=4094,retries=1,url='fixture',control_dir='',out=str(Path(d)/'out')))
        return out,state,events

    def test_set_success_ready_rejection_recovers_same_object(self):
        out,state,events=self.drive()
        self.assertEqual([out['points'][0][k] for k in ('registered','acked','active')],[4097,4096,4096])
        self.assertTrue(out['recovery_ok'])
        self.assertEqual(out['points'][0]['rejections'][0]['stage'],'ready')
        self.assertEqual(out['recovery']['object_index'],2)
        self.assertTrue(out['recovery']['release_confirmed'])
        self.assertIn((0,'LIFECYCLE_HOOK'),events)

    def test_first_recovery_still_rejected_second_succeeds(self):
        for set_rejection in (False,True):
            out,state,_=self.drive(delayed=True,set_rejection=set_rejection)
            self.assertTrue(out['recovery_ok'])
            self.assertEqual(state['after_release'],2)
            self.assertEqual(len(out['recovery']['attempts']),2)
            p=out['points'][0]
            p.update(initial_capacity_log_count=1,recovery_capacity_log_count=1)
            report=r.build_m9(out)
            self.assertEqual(report['status'],'OK')
            self.assertEqual(report['points'][0]['outcome'],'expected_overflow')
            self.assertEqual(report['points'][0]['capacity_rejections'],1)

    def test_unconfirmed_release_prevents_republish(self):
        out,state,_=self.drive(confirm=False)
        self.assertFalse(out['recovery_ok'])
        self.assertEqual(state['after_release'],0)

    def test_real_http_set200_hook503_and_delayed_retry(self):
        import http.server
        import subprocess
        import sys
        import threading
        state=dict(freed=False,sets_after_release=0,capacity=False,status_reads=0)
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                state['status_reads']+=1
                self.send_response(200);self.end_headers()
                self.wfile.write(json.dumps(dict(subjectLifecycleDegraded=['subject_capacity_exhausted'] if state['capacity'] else [])).encode())
            def do_POST(self):
                payload=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                index=int(payload['sandbox']['uid'].rsplit('-',1)[1]);op=payload['operation'];code=200
                if op=='REMOVE_BINDING' and index==0:state['freed']=True
                if op=='LIFECYCLE_HOOK' and index==0 and state['freed']:code=409
                if index==2:
                    if op=='SET_BINDING':
                        state['capacity']=True
                        if state['freed']:state['sets_after_release']+=1
                    if op=='LIFECYCLE_HOOK' and (not state['freed'] or state['sets_after_release']==1):code=503
                self.send_response(code);self.end_headers();self.wfile.write(b'{}')
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as d:
                dest=Path(d)/'out.json'
                subprocess.run([sys.executable,driver.__file__,'--url','http://127.0.0.1:'+str(server.server_port),
                    '--steps','4097','--real-subjects','4094','--retries','1','--out',str(dest)],check=True,timeout=10,capture_output=True)
                out=json.loads(dest.read_text())
            self.assertTrue(out['recovery_ok'])
            self.assertEqual(state['sets_after_release'],2)
            self.assertGreaterEqual(state['status_reads'],2)
            self.assertEqual(out['points'][0]['registered'],4097)
            self.assertEqual(out['points'][0]['rejections'][0]['reason'],'subject_capacity_exhausted')
        finally:
            server.shutdown();server.server_close();thread.join(5)

    def test_overflow_needs_object_stage_and_reason(self):
        out,_,_=self.drive();p=out['points'][0]
        p.update(initial_capacity_log_count=1,recovery_capacity_log_count=0)
        self.assertEqual(r.build_m9(out)['status'],'OK')
        for field,value in [('reason',None),('stage','unknown'),('object_index',-1),('capacity_before',True)]:
            bad=copy.deepcopy(out);bad['points'][0]['rejections'][0][field]=value
            self.assertNotEqual(r.build_m9(bad)['status'],'OK')
        bad=copy.deepcopy(out);bad['recovery']['object_index']=99
        self.assertNotEqual(r.build_m9(bad)['status'],'OK')

if __name__=='__main__':unittest.main()
