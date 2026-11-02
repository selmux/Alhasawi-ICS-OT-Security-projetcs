import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
from analyze_modbus import pdus,parse_pdu,analyze
ROOT=pathlib.Path('/mnt/data')
class TestModbus(unittest.TestCase):
 def test_write_single_register(self):
  pdu=bytes.fromhex('0600641234');raw=bytes.fromhex('00010000000601')+pdu
  result,warnings=pdus(raw)
  self.assertFalse(warnings);self.assertEqual(len(result),1)
  d=parse_pdu(result[0][2],False)
  self.assertEqual((d['address'],d['value']), (100,0x1234))
 def test_write_multiple_coils(self):
  d=parse_pdu(bytes.fromhex('0f000a000a020103'),False)
  self.assertEqual((d['address'],d['quantity'],d['data_hex']), (10,10,'0103'))
 def test_register_response(self):
  d=parse_pdu(bytes.fromhex('0304006400c8'),True)
  self.assertEqual(d['register_values'],[100,200])
 def test_exception(self):
  d=parse_pdu(bytes.fromhex('8302'),True)
  self.assertEqual(d['exception_code'],2)
 def test_truncated(self):
  raw=bytes.fromhex('0001000000060103')
  self.assertTrue(pdus(raw)[1])
 def test_real_capture(self):
  p=ROOT/'stage9_live.pcap'
  if not p.exists():self.skipTest('Previous capture unavailable')
  r=analyze(p,limit=3)
  self.assertGreater(r['decoded_pdus'],0)
  self.assertGreater(r['write_candidate_count'],0)
if __name__=='__main__':unittest.main()
