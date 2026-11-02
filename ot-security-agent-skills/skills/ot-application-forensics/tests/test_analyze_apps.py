import importlib.util,json,tempfile,unittest
from pathlib import Path
p=Path(__file__).resolve().parents[1]/'scripts'/'analyze_apps.py'
spec=importlib.util.spec_from_file_location('analyze_apps',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class AppTests(unittest.TestCase):
 def artifact(self,s,suffix):
  d=tempfile.TemporaryDirectory();self.addCleanup(d.cleanup);p=Path(d.name)/('test'+suffix);p.write_text(s,encoding='utf-8');return p
 def test_nodered(self):
  x=m.inspect_file(self.artifact(json.dumps([{'type':'function','id':'n1','func':'return msg;'}]),'.json'))
  self.assertTrue(any(f['kind']=='nodered_node' for f in x['findings']))
 def test_secret_redaction(self):
  x=m.inspect_file(self.artifact('{"password":"SHOULD_NOT_LEAK"}', '.json'))
  self.assertNotIn('SHOULD_NOT_LEAK',json.dumps(x))
  self.assertEqual(x['findings'][0]['detail']['value'],'<redacted>')
 def test_endpoint_scrub(self):
  x=m.inspect_file(self.artifact('{"url":"http://user:pass@192.0.2.20:8086/query?token=secret"}', '.json'))
  s=json.dumps(x);self.assertIn('http://192.0.2.20:8086',s);self.assertNotIn('user:pass',s);self.assertNotIn('token=secret',s)
 def test_grafana(self):
  x=m.inspect_file(self.artifact('{"title":"Plant","panels":[]}', '.json'))
  self.assertTrue(any(f['kind']=='grafana_dashboard' for f in x['findings']))
 def test_sql(self):
  x=m.inspect_file(self.artifact('CREATE TABLE plc_logs (id INT);\nINSERT INTO plc_logs VALUES (1);','.sql'))
  self.assertEqual(sum(f['kind']=='sql_statement' for f in x['findings']),2)
 def test_influx(self):
  x=m.inspect_file(self.artifact('temperature,unit=1 value=21.5 1600000000000000000','.lp'))
  self.assertTrue(any(f['kind']=='influx_line_protocol' for f in x['findings']))
 def test_invalid_json(self):
  x=m.inspect_file(self.artifact('{bad','.json'));self.assertTrue(x['warnings'])
 def test_hash(self):
  x=m.inspect_file(self.artifact('abc','.txt'));self.assertEqual(x['sha256'],m.sha256(b'abc'))
 def test_missing(self):
  with self.assertRaises(ValueError):m.inspect_file(Path('/does-not-exist'))
 def test_code_hash_not_content(self):
  x=m.inspect_file(self.artifact('{"func":"return secret()"}', '.json'))
  self.assertNotIn('return secret()',json.dumps(x))
if __name__=='__main__':unittest.main()
