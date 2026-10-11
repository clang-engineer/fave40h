#!/usr/bin/env python3
"""Inspect a newly linked ARM ELF, not a UF2 or device. Never flashes."""
from __future__ import annotations
import argparse,json,struct
from pathlib import Path

def inspect(path:Path)->dict:
    b=path.read_bytes()
    if b[:7]!=b'\x7fELF\x01\x01\x01':raise ValueError('Expected ELF32 little endian')
    (_,machine,_,entry,phoff,shoff,_,_,phentsize,phnum,shentsize,shnum,shstr)=struct.unpack_from('<HHIIIIIHHHHHH',b,16)
    if machine!=40:raise ValueError('Not ARM ELF')
    if not 0x08010000 <= (entry&~1) < 0x08020000:raise ValueError('Entry outside inspection application window')
    loads=[]
    for i in range(phnum):
        kind,off,vma,lma,filesz,memsz,flags,align=struct.unpack_from('<8I',b,phoff+i*phentsize)
        if kind==1 and filesz:
            if not (0x08010000<=lma and lma+filesz<=0x08020000):raise ValueError(f'Load segment outside application window: {lma:#x}')
            loads.append((lma,filesz))
    if not loads:raise ValueError('No loadable application bytes')
    sections=[struct.unpack_from('<10I',b,shoff+i*shentsize) for i in range(shnum)]
    keymap_sizes=[]
    for s in sections:
        if s[1]!=2:continue
        strings=sections[s[6]];names=b[strings[4]:strings[4]+strings[5]]
        for pos in range(s[4],s[4]+s[5],s[9]):
            name,value,size,info,other,ndx=struct.unpack_from('<IIIBBH',b,pos)
            symbol=names[name:].split(b'\0',1)[0]
            if symbol==b'keymaps':keymap_sizes.append(size)
    if keymap_sizes != [576]:raise ValueError(f'Expected keymaps symbol size 576, found {keymap_sizes}')
    return {'elf':path.name,'machine':'ARM','entry':hex(entry),'load_start':hex(min(a for a,n in loads)),
            'load_end_exclusive':hex(max(a+n for a,n in loads)),'load_bytes':sum(n for a,n in loads),
            'keymaps_bytes':576,'layers':6,'physical_device_tested':False,'flash_ready':False,
            'storage':'transient RAM only; custom bootloader callbacks are no-ops'}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('elf',type=Path);a=p.parse_args()
    try:print(json.dumps(inspect(a.elf),indent=2))
    except (ValueError,OSError,struct.error) as e:p.exit(1,f'error: {e}\n')
