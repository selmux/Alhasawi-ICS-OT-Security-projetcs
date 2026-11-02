import pathlib,sys,unittest,tempfile,struct
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
from analyze_iec104 import parse_apdu,parse_asdu,scan_payload,analyze

def I(asdu,send=0,recv=0):return b'\x68'+bytes([4+len(asdu)])+struct.pack('<HH',send<<1,recv<<1)+asdu
class IEC104Tests(unittest.TestCase):
 def test_single_command(self):
  asdu=bytes([45,1,6,0,1,0,0x39,0x30,0,1]);a=parse_apdu(I(asdu,send=3,recv=2));self.assertEqual(a['send_seq'],3);self.assertEqual(a['recv_seq'],2);self.assertTrue(a['control_command_candidate']);self.assertEqual(a['asdu']['information_objects'][0]['ioa'],12345)
 def test_measurement(self):
  asdu=bytes([1,1,3,0,2,0,3,0,0,1]);a=parse_apdu(I(asdu));self.assertEqual(a['asdu']['information_objects'][0]['state'],1);self.assertFalse(a['control_command_candidate'])
 def test_s_and_u(self):
  self.assertEqual(parse_apdu(b'\x68\x04\x01\x00\x04\x00')['recv_seq'],2)
  self.assertEqual(parse_apdu(b'\x68\x04\x07\x00\x00\x00')['u_function'],'STARTDT act')
 def test_multiple_apdus(self):
  raw=b'\x68\x04\x07\x00\x00\x00'*2
  events,errors=scan_payload(raw);self.assertEqual(len(events),2);self.assertEqual(errors,[])
 def test_fragment(self):
  events,issues=scan_payload(b'\x68\x07\x00\x00');self.assertEqual(len(events),0);self.assertIn('Split',issues[0]['reason'])
 def test_sequential_ioas(self):
  a=parse_asdu(bytes([1,0x82,3,0,1,0,5,0,0,1,0]));self.assertEqual([x['ioa'] for x in a['information_objects']],[5,6])
 def test_offline_pcap(self):
  frame=I(bytes([45,1,6,0,1,0,1,0,0,1]));tcp=struct.pack('!HHIIHHHH',40000,2404,1,0,0x5018,8192,0,0)+frame
  ip=bytearray(20);ip[0]=0x45;ip[2:4]=struct.pack('!H',20+len(tcp));ip[8]=64;ip[9]=6;ip[12:16]=bytes([10,0,0,1]);ip[16:20]=bytes([10,0,0,2]);eth=b'\x00'*12+b'\x08\x00'+bytes(ip)+tcp
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'test.pcap';p.write_bytes(b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,65535,1)+struct.pack('<IIII',1,10,len(eth),len(eth))+eth)
   r=analyze([str(p)])['captures'][0];self.assertEqual(r['decoded_apdus'],1);self.assertEqual(r['control_command_candidate_count'],1);self.assertEqual(r['events'][0]['frame'],1)
if __name__=='__main__':unittest.main()
