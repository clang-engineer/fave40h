#!/usr/bin/env python3
"""Read-only, stock-build-specific clock/storage evidence checker. Not a decompiler."""
from __future__ import annotations
import argparse, hashlib, json, struct, zipfile
from pathlib import Path

BASE = 0x08010000
PROFILES = {
    'a545e1a6bafc4eedec9ffa676d9e7245254ef1a7a185c98986928c9c06ec9d22': {
        'name':'VIA', 'early_init':0x08015310, 'pll_ldr':0x080153C8, 'cfgr_ldr':0x080153E4,
        'heap_ldr':0x08018176, 'timer_ldr':0x080195A0, 'first_sector':0x0801835C,
        'backing_cmp':0x0801834A, 'logical_cmp':0x080183B2,
        'offset_call':0x0801835E, 'offset_fn':0x08013B46,
        'size_call':0x08018344, 'size_fn':0x08013B60, 'descriptors':0x0801AFE8,
    },
    'd5e680fa2507534b63b316a3e67a5d7457af4bdfa65189f464d4e1b029692431': {
        'name':'Vial', 'early_init':0x0801B034, 'pll_ldr':0x0801B0EC, 'cfgr_ldr':0x0801B108,
        'heap_ldr':0x08018536, 'timer_ldr':0x08013A00, 'first_sector':0x0801871C,
        'backing_cmp':0x0801870A, 'logical_cmp':0x08018772,
        'offset_call':0x0801871E, 'offset_fn':0x0801B49C,
        'size_call':0x08018704, 'size_fn':0x0801B4B6, 'descriptors':0x0801DE24,
    },
}


def expand_imm12(value: int) -> int:
    """ARM Thumb modified-immediate expansion (not an instruction decoder)."""
    if not 0 <= value < 4096:
        raise ValueError('Invalid 12-bit immediate')
    if value >> 10 == 0:
        v = value & 255
        return (v, v | (v << 16), (v << 8) | (v << 24), v * 0x01010101)[value >> 8]
    v, shift = 128 | (value & 127), value >> 7
    return ((v >> shift) | (v << (32 - shift))) & 0xFFFFFFFF


def recover(raw: bytes) -> dict:
    digest = hashlib.sha256(raw).hexdigest()
    if digest not in PROFILES:
        raise ValueError('Unknown/modified stock image; refusing fixed analysis offsets')
    p = PROFILES[digest]
    chunks = []
    for n, off in enumerate(range(0, len(raw), 512)):
        b = raw[off:off+512]
        h = struct.unpack_from('<8I', b)
        if h[:3] != (0x0A324655, 0x9E5D5157, 0x2000) or h[3:6] != (BASE+n*256, 256, n):
            raise ValueError('Unexpected UF2 header')
        if h[6:] != (len(raw)//512, 0x57755A57) or struct.unpack_from('<I', b, 508)[0] != 0x0AB16F30:
            raise ValueError('Unexpected UF2 metadata')
        chunks.append(b[32:288])
    data = b''.join(chunks)
    def read(addr: int, size: int) -> bytes:
        off = addr-BASE
        if off < 0 or off+size > len(data): raise ValueError('Read outside stock payload')
        return data[off:off+size]
    def u32(addr): return struct.unpack('<I', read(addr,4))[0]
    def witness(addr, value):
        if read(addr,len(value)) != value: raise ValueError(f'Instruction witness differs at {addr:#x}')
    def ldr(addr):
        h, = struct.unpack('<H',read(addr,2))
        if h & 0xF800 != 0x4800: raise ValueError('Expected Thumb T1 LDR literal')
        return u32(((addr+4)&~3)+(h&255)*4)
    def bl(addr):
        h1,h2=struct.unpack('<2H',read(addr,4))
        if h1&0xF800 != 0xF000 or h2&0xD000 != 0xD000:raise ValueError('Expected Thumb BL')
        s=(h1>>10)&1; i1=1^((h2>>13)&1)^s; i2=1^((h2>>11)&1)^s
        imm=(s<<24)|(i1<<23)|(i2<<22)|((h1&1023)<<12)|((h2&2047)<<1)
        return addr+4+imm-(1<<25 if s else 0)
    def cmp_imm(addr, rn):
        h1,h2=struct.unpack('<2H',read(addr,4))
        if h1&0xFBF0 != 0xF1B0 or h2&0x8F00 != 0x0F00 or h1&15 != rn:
            raise ValueError('Expected inspected CMP.W register/immediate')
        return expand_imm12((((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&255))
    if bl(0x08010248) != p['early_init']:raise ValueError('Startup call differs')
    pll,cfgr=ldr(p['pll_ldr']),ldr(p['cfgr_ldr'])
    witness(p['pll_ldr']+2,bytes.fromhex('5a60'))  # store to RCC + 4
    witness(p['cfgr_ldr']+2,bytes.fromhex('9a60')) # store to RCC + 8
    witness(p['first_sector'],bytes.fromhex('0321')) # MOVS R1, #3
    if bl(p['offset_call'])!=p['offset_fn'] or bl(p['size_call'])!=p['size_fn']:
        raise ValueError('Sector helper call differs')
    witness(p['offset_fn']+14,bytes.fromhex('53f83400')) # offset table[index*8]
    witness(p['size_fn']+14,bytes.fromhex('03ebc4035868')) # size table[index*8+4]
    logical,backing=cmp_imm(p['logical_cmp'],8),cmp_imm(p['backing_cmp'],10)
    geometries=[]
    for i in range(4):
        a,prog,count,table,uniform,flash,total=struct.unpack('<7I',read(p['descriptors']+28*i,28))
        sectors=[struct.unpack('<2I',read(table+8*j,8)) for j in range(count)]
        if (a,prog,count,uniform,flash)!=(3,4,5+i,0,0x08000000):raise ValueError('Descriptor differs')
        if sectors[3]!=(0xC000,0x4000) or sum(n for _,n in sectors)!=total:raise ValueError('Sector geometry differs')
        geometries.append(total)
    m,n,divp,q=pll&63,(pll>>6)&511,2*(((pll>>16)&3)+1),(pll>>24)&15
    timer=ldr(p['timer_ldr']); heap=ldr(p['heap_ldr'])
    if (pll,cfgr,timer,heap)!=(0x04413010,0x38881000,48000000,0x20020000):raise ValueError('Clock/RAM evidence differs')
    return {
        'firmware':p['name'], 'uf2_sha256':digest,
        'pll_register':hex(pll), 'clock_dividers_register':hex(cfgr),
        'pll':{'m':m,'n':n,'p':divp,'q':q,'source':'HSE'},
        'inferred_hse_hz':16000000, 'inferred_sysclk_hz':48000000,
        'oscillator_measured':False, 'timer_clock_constant_hz':timer,
        'software_heap_end':hex(heap), 'mcu_candidate':'STM32F411', 'physical_mcu_verified':False,
        'supported_flash_descriptors_bytes':geometries, 'physical_flash_capacity':None,
        'stock_storage':{'logical_bytes':logical,'backing_bytes':backing,'first_sector':3,
                         'start':hex(0x0800C000),'erase_sector_bytes':16384,'sector_end_exclusive':hex(BASE)},
        'raw_keymap_bytes':{'four_layers':384,'six_layers':576,'increase':192},
        'flash_ready':False,
    }


def load(path: Path):
    if path.suffix.lower()!='.zip':return [(path.name,path.read_bytes())]
    with zipfile.ZipFile(path) as archive:
        members=[i for i in archive.infolist() if i.filename.lower().endswith('.uf2')]
        if not members or any(i.file_size>2**20 for i in members):raise ValueError('No images or oversized ZIP member')
        return [(i.filename,archive.read(i)) for i in members]


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('stock',type=Path);a=parser.parse_args()
    try:print(json.dumps([recover(raw) for _,raw in load(a.stock)],indent=2))
    except (ValueError,OSError,zipfile.BadZipFile,struct.error) as e:parser.exit(1,f'error: {e}\n')
