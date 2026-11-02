import os,sys,unittest
sys.path.insert(0,os.path.join(os.path.dirname(__file__),'..','scripts'))
from analyze_s7 import parse_s7,decode_tpkt,parse_var_items,analyze
class TestS7(unittest.TestCase):
 def wrap(self,app):
  cotp=b'\x02\xf0\x80';n=4+len(cotp)+len(app)
  return b'\x03\x00'+n.to_bytes(2,'big')+cotp+app
 def s7(self,param,data=b'',ros=1):
  return b'\x32'+bytes([ros])+b'\0\0\x00\x02'+len(param).to_bytes(2,'big')+len(data).to_bytes(2,'big')+(b'\0\0' if ros in (2,3) else b'')+param+data
 def test_setup(self):
  v=parse_s7(self.s7(b'\xf0\x00\x00\x01\x00\x01\x01\xe0'))
  self.assertEqual(v['function_name'],'Setup Communication')
 def test_write_var(self):
  item=bytes.fromhex('120a10020001004d84000000')
  v=parse_s7(self.s7(b'\x05\x01'+item,b'\x00'))
  self.assertTrue(v['state_change_candidate']);self.assertEqual(v['items'][0]['db_number'],77)
  self.assertEqual(v['items'][0]['area'],'Data Block')
 def test_stop(self):
  self.assertEqual(parse_s7(self.s7(b'\x29'))['function_name'],'PLC Stop')
 def test_split(self):
  _,warnings=decode_tpkt(self.wrap(self.s7(b'\x29'))[:-2]);self.assertTrue(warnings)
 def test_multiple_tpkt(self):
  x=self.wrap(self.s7(b'\x29'));a,w=decode_tpkt(x+x)
  self.assertEqual(len(a),2);self.assertFalse(w)
 def test_response(self):
  v=parse_s7(self.s7(b'\x04\x01',ros=3))
  self.assertEqual(v['rosctr_name'],'Ack_Data');self.assertEqual(v['error_code'],0)
if __name__=='__main__':unittest.main()
