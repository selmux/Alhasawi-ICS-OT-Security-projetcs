import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('chain', ROOT / 'scripts' / 'reconstruct_chain.py')
chain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chain)

class ChainTests(unittest.TestCase):
    def fixture(self):
        return [{"id":"later","timestamp":"2026-09-08T03:00:00+01:00","action":"write attempted","stage":"impair_process_control","related_to":["earlier"],"evidence":[{"source":"a.pcap","frame":42}]},
                {"id":"earlier","timestamp":"2026-09-08T01:00:00Z","action":"login","stage":"initial_access","evidence":[{"source":"a.log","line":2}]}]
    def test_utc_and_sort(self):
        evs = [chain.valid_event(x,i,'events.json') for i,x in enumerate(self.fixture(),1)]
        out = chain.reconstruct(sorted(evs,key=lambda e:e['timestamp']), [])
        self.assertEqual([e['id'] for e in out['events']], ['earlier','later'])
        self.assertEqual(out['events'][1]['timestamp'],'2026-09-08T02:00:00Z')
    def test_link_assertion(self):
        evs = [chain.valid_event(x,i,'events.json') for i,x in enumerate(self.fixture(),1)]
        out = chain.reconstruct(evs,[])
        self.assertEqual(out['asserted_links'][0]['type'], 'analyst_asserted')
    def test_missing_evidence(self):
        bad=self.fixture()[0].copy(); bad['evidence']=[]
        with self.assertRaisesRegex(ValueError,'evidence'):
            chain.valid_event(bad,1,'bad')
    def test_unzoned_time(self):
        bad=self.fixture()[0].copy();bad['timestamp']='2026-09-08T02:00:00'
        with self.assertRaisesRegex(ValueError,'timezone'):
            chain.valid_event(bad,1,'bad')
    def test_missing_link_warning(self):
        ev=chain.valid_event(self.fixture()[0],1,'a'); out=chain.reconstruct([ev],[])
        self.assertEqual(len(out['warnings']),1)
    def test_unknown_stage(self):
        bad=self.fixture()[0].copy(); bad['stage']='magic'
        with self.assertRaisesRegex(ValueError,'unknown stage'):
            chain.valid_event(bad,1,'bad')
    def test_file_input_and_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp)/'events.json';p.write_text(json.dumps({'events':self.fixture()}),encoding='utf-8')
            events,inventory=chain.load_events([p]); self.assertEqual(len(events),2)
            self.assertEqual(len(inventory[0]['sha256']),64)
    def test_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp)/'events.json';d=self.fixture();d[1]['id']=d[0]['id'];p.write_text(json.dumps(d),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'unique'):
                chain.load_events([p])
    def test_markdown(self):
        events=[chain.valid_event(self.fixture()[0],1,'a')]
        self.assertIn('write attempted',chain.to_markdown(chain.reconstruct(events,[])))

if __name__=='__main__': unittest.main()
