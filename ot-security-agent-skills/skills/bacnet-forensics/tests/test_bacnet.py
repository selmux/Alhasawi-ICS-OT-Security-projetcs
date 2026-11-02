import importlib.util, pathlib, struct, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('analyze_bacnet',ROOT/'scripts'/'analyze_bacnet.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class BACnetTests(unittest.TestCase):
    def test_device_communication_control(self):
        x=bytes.fromhex('810a001a01040244a51119002d0c006d61696e74336e616e6365')
        p=m.bacnet(x);self.assertEqual(p['service'],'deviceCommunicationControl');self.assertEqual(p['service_id'],17)
    def test_read_property(self):
        x=bytes.fromhex('810a001001040244a50c0c000000011955')
        p=m.bacnet(x);self.assertEqual(p['service'],'readProperty')
    def test_object_tag(self):
        tags=m.parse_tags(bytes.fromhex('0c004000051955'))
        self.assertEqual(tags['object']['type'],'analogOutput');self.assertEqual(tags['object']['instance'],5);self.assertEqual(tags['property_id'],85)
    def test_unconfirmed(self):
        self.assertEqual(m.bacnet(bytes.fromhex('810a000801001008'))['service'],'whoIs')
    def test_invalid(self):
        self.assertIsNone(m.bacnet(b'not-bacnet'))
if __name__=='__main__':unittest.main()
