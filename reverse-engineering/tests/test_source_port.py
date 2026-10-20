"""Source geometry checks plus C grammar check; not device or QMK runtime tests."""
import json,re,shutil,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
KB=ROOT/'keyboards/fave40h'
class SourcePortTests(unittest.TestCase):
    def setUp(self):
        self.info=json.loads((KB/'keyboard.json').read_text())
        self.layers=json.loads((ROOT/'docs/example-keymap.json').read_text())['layers']
        self.physical={tuple(k['matrix']) for k in self.info['layouts']['LAYOUT']['layout']}
    def test_42_distinct_physical_keys(self):self.assertEqual(len(self.physical),42)
    def test_geometry_in_matrix(self):self.assertTrue(all(0<=r<4 and 0<=c<12 for r,c in self.physical))
    def test_six_full_layers(self):
        self.assertEqual(len(self.layers),6)
        for l in self.layers:
            self.assertEqual(len(l),4)
            self.assertTrue(all(len(r)==12 for r in l))
    def test_unpopulated_positions_remain_disabled(self):
        for l in self.layers:
            for r in range(4):
                for c in range(12):
                    if (r,c) not in self.physical:self.assertEqual(l[r][c],'KC_NO')
    def test_upper_layer_keys_are_transparent(self):
        for l in self.layers[1:]:
            for r,c in self.physical:
                if r==3:self.assertEqual(l[r][c],'KC_TRNS')
    def test_all_five_upper_layers_accessible(self):
        b=' '.join(self.layers[0][3])
        for name in ['_NUM','_SYM','_NAV','_MEDIA','_EXTRA']:self.assertIn(name,b)
    def test_no_reset_or_erase_keycodes(self):
        self.assertNotRegex(str(self.layers),r'QK_BOOT|QK_CLEAR_EEPROM|EE_CLR|RESET')
    def test_configuration_is_volatile(self):
        self.assertIn('EEPROM_DRIVER = transient',(KB/'rules.mk').read_text())
        self.assertIn('#define TRANSIENT_EEPROM_SIZE 4096',(KB/'config.h').read_text())
    def test_build_requires_explicit_opt_in(self):
        self.assertIn('#ifndef FAVE40H_EXPERIMENTAL_BUILD',(KB/'config.h').read_text())
        self.assertIn('$(error Inspection-only',(KB/'rules.mk').read_text())
    def test_correct_dynamic_count(self):
        self.assertIn('#define DYNAMIC_KEYMAP_LAYER_COUNT 6',(KB/'keymaps/vial/config.h').read_text())
    def test_vial_definition_omits_unimplemented_features(self):
        v=json.loads((KB/'keymaps/vial/vial.json').read_text())
        self.assertEqual(v['matrix'],{'rows':4,'cols':12})
        self.assertNotIn('customKeycodes',v);self.assertNotIn('menus',v)
    def test_header_matches_example_data(self):
        src=(KB/'keymaps/six_layers.h').read_text()
        for layer in self.layers:
            for row in layer:self.assertIn('{ '+', '.join(row)+' }',src)
    def test_host_c_grammar_only(self):
        cc=shutil.which('cc') or shutil.which('clang')
        if not cc:self.skipTest('No host C compiler')
        # This stub checks C grammar/array shapes, NOT real QMK keycode encodings.
        src=(KB/'keymaps/six_layers.h').read_text();names=sorted(set(re.findall(r'\bKC_[A-Z0-9_]+\b',src)))
        header='#include <stdint.h>\n#define PROGMEM\n#define MATRIX_ROWS 4\n#define MATRIX_COLS 12\n'
        header+='\n'.join(f'#define {name} {i}' for i,name in enumerate(names))
        header+='\n#define S(k) (0x200u | (k))\n#define MO(l) (0x5200u | (l))\n#define LT(l,k) (0x4000u | ((l)<<8) | (k))\n'
        with tempfile.TemporaryDirectory() as d:
            Path(d,'qmk_stub.h').write_text(header)
            for keymap in ['default','vial']:
                subprocess.run([cc,'-std=c11','-Wall','-Wextra','-Werror','-fsyntax-only','-I',d,'-DQMK_KEYBOARD_H="qmk_stub.h"',str(KB/f'keymaps/{keymap}/keymap.c')],check=True,capture_output=True)
if __name__=='__main__':unittest.main()
