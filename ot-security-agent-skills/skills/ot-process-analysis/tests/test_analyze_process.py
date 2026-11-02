import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('analyze_process',ROOT/'scripts'/'analyze_process.py')
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

SAMPLE={'case_id':'demo','observations':[{'id':'1','source':'demo.pcap frame 42','asset':'PLC1','target':'HR100','operation':'setpoint_write','value':920,'evidence_stage':'command_observed'}]}

class ProcessTests(unittest.TestCase):
    def test_summary(self):
        r=mod.analyze(SAMPLE)
        self.assertEqual(r['summary']['observation_count'],1)
        self.assertEqual(r['summary']['assets']['PLC1'],['1'])
    def test_command_not_success(self):
        r=mod.analyze(SAMPLE)
        self.assertTrue(any('does not prove' in x for x in r['findings'][0]['limitations']))
    def test_units_not_inferred(self):
        r=mod.analyze(SAMPLE)
        self.assertNotIn('unit',r['findings'][0])
        self.assertIn('Units/scaling',r['findings'][0]['limitations'][0])
    def test_ack_not_effect(self):
        d=json.loads(json.dumps(SAMPLE));d['observations'][0]['evidence_stage']='protocol_acknowledged'
        r=mod.analyze(d)
        self.assertTrue(any('does not prove physical effect' in x for x in r['findings'][0]['limitations']))
    def test_duplicate(self):
        d=json.loads(json.dumps(SAMPLE));d['observations'].append(d['observations'][0])
        with self.assertRaises(mod.InputError):mod.analyze(d)
    def test_invalid_stage(self):
        d=json.loads(json.dumps(SAMPLE));d['observations'][0]['evidence_stage']='guaranteed_attack'
        with self.assertRaises(mod.InputError):mod.analyze(d)
    def test_cli(self):
        with tempfile.TemporaryDirectory() as td:
            f=Path(td)/'in.json';f.write_text(json.dumps(SAMPLE),encoding='utf-8')
            p=subprocess.run([sys.executable,str(ROOT/'scripts'/'analyze_process.py'),str(f)],capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(json.loads(p.stdout)['summary']['observation_count'],1)

if __name__=='__main__':unittest.main()
