"""Tests for read-only stock clock/storage evidence; never flash a device."""
import importlib.util,json,os,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('recover_platform',ROOT/'tools/recover_platform.py')
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)

class PlatformTests(unittest.TestCase):
    def test_thumb_immediate_expansion(self):
        self.assertEqual(mod.expand_imm12(0xE80),1024)
        self.assertEqual(mod.expand_imm12(0xE00),2048)
        self.assertEqual(mod.expand_imm12(0xD80),4096)
        self.assertEqual(mod.expand_imm12(0xD00),8192)
        self.assertEqual(mod.expand_imm12(0x1AB),0x00AB00AB)
    def test_immediate_range(self):
        for n in (-1,4096):
            with self.assertRaises(ValueError):mod.expand_imm12(n)
    def test_unknown_image_rejected(self):
        for raw in (b'',bytes(512),b'not a firmware'):
            with self.assertRaises(ValueError):mod.recover(raw)
    def test_recorded_physical_uncertainty(self):
        for e in json.loads((ROOT/'docs/platform-evidence.json').read_text()):
            self.assertFalse(e['physical_mcu_verified']);self.assertFalse(e['oscillator_measured'])
            self.assertIsNone(e['physical_flash_capacity']);self.assertFalse(e['flash_ready'])
    def test_raw_keymap_growth(self):
        for e in json.loads((ROOT/'docs/platform-evidence.json').read_text()):
            self.assertEqual(e['raw_keymap_bytes'],{'four_layers':384,'six_layers':576,'increase':192})

@unittest.skipUnless(os.environ.get('FAVE40H_STOCK_ZIP'),'Private manufacturer ZIP not provided')
class PlatformStockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw=mod.load(Path(os.environ['FAVE40H_STOCK_ZIP']))
        cls.results=[mod.recover(raw) for _,raw in cls.raw]
    def test_both_stock_builds_match_report(self):
        self.assertEqual(self.results,json.loads((ROOT/'docs/platform-evidence.json').read_text()))
    def test_clock_configurations_agree(self):
        self.assertEqual(len(self.results),2)
        for e in self.results:
            self.assertEqual(e['pll'],{'m':16,'n':192,'p':4,'q':4,'source':'HSE'})
    def test_sector_before_application(self):
        for e in self.results:
            s=e['stock_storage']
            self.assertEqual(int(s['start'],16)+s['erase_sector_bytes'],0x08010000)
            self.assertLessEqual(s['backing_bytes'],s['erase_sector_bytes'])
    def test_mutation_rejected(self):
        for _,raw in self.raw:
            bad=bytearray(raw);bad[-20]^=1
            with self.assertRaises(ValueError):mod.recover(bad)

if __name__=='__main__':unittest.main()
