import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from normalize_evidence import normalize,utc,detect
class NormalizerTests(unittest.TestCase):
    def test_utc(self):
        self.assertEqual(utc('2026-09-08T05:17:00+03:00'),'2026-09-08T02:17:00Z')
        self.assertIsNone(utc('2026-09-08T02:17:00'))
    def test_modbus(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'modbus.json'
            p.write_text(json.dumps({'file':'capture.pcap','decoded_pdus':1,'write_candidates':[{'frame':3,'time_utc':'2026-09-08T02:17:00Z','src':'10.0.0.1','dst':'10.0.0.2','direction':'request','function':6,'write_candidate':True,'address':100}],'events':[]}),encoding='utf8')
            summary,chain,process=normalize([p]);self.assertEqual(summary['events_written'],1);self.assertEqual(process['observations'][0]['operation'],'setpoint_write');self.assertEqual(chain['events'][0]['evidence'][0]['frame'],3)
    def test_bacnet_duplicate(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'bacnet.json';e={'frame':8,'utc':'2026-09-08T02:17:00Z','src':'1.1.1.1','dst':'2.2.2.2','kind':'confirmed-request','service_id':17,'service':'deviceCommunicationControl'}
            p.write_text(json.dumps({'capture':'x.pcap','bacnet_packets':2,'sample_events':[e],'state_change_candidates':[e]}))
            s,c,pr=normalize([p]);self.assertEqual(s['events_written'],1);self.assertEqual(pr['observations'][0]['operation'],'communications_control')
    def test_s7_iec(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'s7.json';p.write_text(json.dumps({'skill':'siemens-s7-forensics','captures':[{'file':'x.pcap','events':[{'frame':2,'time_utc':'2026-09-08T02:17:00Z','function_name':'Write Var','state_change_candidate':True}]}]}))
            q=Path(t)/'iec.json';q.write_text(json.dumps({'skill':'iec104-forensics','captures':[{'file':'y.pcap','events':[{'frame':4,'time_utc':'2026-09-08T02:17:01Z','control_command_candidate':True,'asdu':{'type_id':48,'type_name':'setpoint'}}]}]}))
            s,c,pr=normalize([p,q]);self.assertEqual(s['events_written'],2);self.assertEqual(len(pr['observations']),2)
    def test_skip_missing_timestamp_and_unknown(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'a.json';p.write_text(json.dumps({'events':[{'action':'unknown'}]}))
            q=Path(t)/'b.json';q.write_text(json.dumps({'surprise':1}))
            s,c,pr=normalize([p,q]);self.assertEqual(s['events_written'],0);self.assertEqual(len(s['warnings']),2)
    def test_app(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'app.json';p.write_text(json.dumps({'file':'flow.json','sha256':'a','findings':[{'type':'configuration','line':4}]}))
            s,c,pr=normalize([p]);self.assertEqual(s['events_written'],0);self.assertTrue(s['warnings'])
if __name__=='__main__':unittest.main()
