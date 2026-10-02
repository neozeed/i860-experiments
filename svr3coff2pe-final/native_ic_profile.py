#!/usr/bin/env python3
"""Exact native-SVR3 profile for recovered Intel i860 compiler stage `ic`.
Relocation discovery is deterministic and fingerprint-gated. R4O disables
heuristic IC operand relocation for unknown binaries.
"""
import hashlib, re, struct, subprocess, tempfile
from pathlib import Path
IC_SHA256='b03d634d16ffdd724d752d5aeb12831ba81423a9ab35e7216256bcb909b3ddab'
OLD_TEXT=0x000000d0; OLD_ENTRY=0x000000d4; OLD_DATA=0x00400a4c; OLD_BSS=0x00442b38
TEXT_SIZE=0x000a097c; DATA_SIZE=0x000420ec; BSS_SIZE=0x00001db4
NEW_TEXT=0x00500000; DELTA=NEW_TEXT-OLD_TEXT; HEAP_LIMIT=0x004f0000; EXPECTED_GATES=14

# R4D: every data-resident dispatch table is derived from an actual decoded
# absolute indexed indirect jump in IC .text.  For each proven base, the exact
# table run consists only of consecutive aligned dwords that are valid historical
# .text addresses; discovery stops at the first non-text dword.  This is neither
# executable-byte pointer guessing nor a blanket scan of .data.

def _decoded_text(path):
    """Decode raw text without BFD's PE interpretation of SVR3 COFF symbols.

    GNU objdump on the COFF adds the section VA to already-absolute symbols;
    its -d also restarts decoding at those incorrect symbol boundaries.
    Raw binary disassembly avoids both effects. Never scan arbitrary byte windows.
    """
    blob=Path(path).read_bytes()
    nsec=struct.unpack_from('<H',blob,2)[0]
    sh=20+struct.unpack_from('<H',blob,16)[0]
    sections={}
    for i in range(nsec):
        off=sh+40*i
        name=blob[off:off+8].split(b'\0')[0]
        va,size,ptr=struct.unpack_from('<III',blob,off+12)
        sections[name]=(va,size,ptr)
    va,size,ptr=sections[b'.text']
    with tempfile.TemporaryDirectory() as td:
        rawpath=Path(td)/'text.bin';rawpath.write_bytes(blob[ptr:ptr+size])
        r=subprocess.run(['objdump','-D','-b','binary','-m','i386','-Mintel','-w',
                          '--adjust-vma='+hex(va),str(rawpath)],
                         capture_output=True,text=True,check=True)
    rows=[]
    for line in r.stdout.splitlines():
        m=re.match(r'^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*(.*)',line)
        if m: rows.append((int(m[1],16),bytes.fromhex(m[2]),m[3].strip()))
    return rows

def _decoded_data_jump_tables(path, data):
    bases=set()
    for va,raw,asm in _decoded_text(path):
        # FF /4, mod=00 r/m=SIB; SIB scale=4, no base, real index.
        if (len(raw)==7 and raw[:2]==b'\xff\x24' and
                raw[2]&0xc7==0x85 and (raw[2]>>3)&7 != 4):
            base=struct.unpack_from('<I',raw,3)[0]
            if OLD_DATA<=base<OLD_DATA+DATA_SIZE: bases.add(base)
    tables=[]
    for base in sorted(bases):
        off=base-OLD_DATA;n=0
        while off+4<=len(data):
            v=struct.unpack_from('<I',data,off)[0]
            if not OLD_TEXT<=v<OLD_TEXT+TEXT_SIZE: break
            n+=1;off+=4
        if n:tables.append((base,n))
    return tables

SYSCALL_NAMES={1:'exit',3:'read',4:'write',5:'open',6:'close',10:'unlink',13:'time',17:'brk',19:'lseek',20:'getpid',33:'access',43:'times',54:'ioctl'}
def sha256(b): return hashlib.sha256(b).hexdigest()
def matches(data,coff):
 return sha256(data)==IC_SHA256 and coff['magic']==0x14c and coff.get('optional_common') and coff['optional_common']['entry']==OLD_ENTRY and coff['optional_common']['text_start']==OLD_TEXT and coff['optional_common']['data_start']==OLD_DATA

def symbol_names(path, text_start=None, text_size=None):
    """Read SVR3 absolute n_value directly; reject debug/other-section symbols."""
    text_start=OLD_TEXT if text_start is None else text_start
    text_size=TEXT_SIZE if text_size is None else text_size
    blob=Path(path).read_bytes();ptr,count=struct.unpack_from('<II',blob,8)
    strings=blob[ptr+count*18:];out={};i=0
    while i<count:
        entry=blob[ptr+i*18:ptr+(i+1)*18]
        if len(entry)!=18:raise RuntimeError('truncated COFF symbol')
        value,section,typ,storage,aux=struct.unpack_from('<IhHBB',entry,8)
        if entry[:4]==b'\0'*4:
            at=struct.unpack_from('<I',entry,4)[0]
            name=strings[at:].split(b'\0')[0].decode('ascii',errors='replace')
        else:name=entry[:8].split(b'\0')[0].decode('ascii',errors='replace')
        if section==1 and storage in (2,3) and not name.startswith('.') and text_start<=value<text_start+text_size:
            out.setdefault(value,set()).add(name)
        i+=1+aux
    return out

def symbols(path):return set(symbol_names(path))

# R4O: audited pointer-producing operands, keyed by instruction address.
# These are callbacks passed to qsort/traversal functions, or stores to the
# allocator callback at 0x43d6c4. Mere equality with a symbol is NOT evidence.
IC_POINTER_OPERANDS = (
    (0x1b860,1,0x1b668,'qs_anno'),
    (0x49165,1,0x49ae0,'qscmp'),
    (0x6d3e2,6,0x4b1b4,'mkrtemp'),
    (0x738ea,6,0x740c0,'get_vtemp'),
    (0x87014,1,0x86ff0,'edge_func'),
    (0x8836a,1,0x89ab0,'rectangle'),
    (0x883a7,1,0x8869c,'trapezoid'),
    (0x94d4a,1,0x94b80,'distr_dv'),
    (0x96301,1,0x96124,'check_dv'),
    (0x97ce1,1,0x97944,'inv_func'),
    (0x98298,1,0x97fdc,'sinv_func'),
    (0x984ab,1,0x97fdc,'sinv_func'),
    (0x98530,1,0x97f94,'conf_func'),
    (0x98b06,1,0x98938,'int_func'),
)

def _disasm_operand_sites(path, syms):
    if sha256(Path(path).read_bytes())!=IC_SHA256:
        raise RuntimeError('R4O requires the audited IC fingerprint; heuristic operand relocation is disabled')
    rows={va:(raw,asm) for va,raw,asm in _decoded_text(path)}
    names=symbol_names(path);out=[]
    for va,k,target,name in IC_POINTER_OPERANDS:
        raw,asm=rows[va]
        prefix=b'\x68' if k==1 else bytes.fromhex('c7 05 c4 d6 43 00')
        if raw!=prefix+struct.pack('<I',target) or name not in names.get(target,set()):
            raise RuntimeError('audited operand/symbol mismatch at '+hex(va))
        out.append((va,k,target))
    return out

def discover_manifest(path, text, data):
 syms=symbols(path)
 ops=_disasm_operand_sites(path,syms)
 # Never range-guess tables in executable text. R4/R4A proved instruction
 # bytes can resemble low text pointers. Data-side dispatch tables are derived
 # only from actual decoded absolute indexed jumps.
 tt=[]
 dt=_decoded_data_jump_tables(path,data)
 # No unsourced data-symbol scan. R4N's two extra slots were numeric values
 # matching misinterpreted/debug symbols. Dispatch slots remain independently
 # derived from actual indirect-jump instructions.
 dsp=[]
 return {'operand_sites':ops,'text_tables':tt,'data_tables':dt,'data_symbol_ptrs':dsp,'symbol_count':len(syms)}

def relocate(path,text,data,gate7,gate15=None):
 from types import SimpleNamespace
 from native_relocation import relocate_exact
 return relocate_exact(SimpleNamespace(**globals()),path,text,data,gate7,gate15)

def trap_inventory(text):
 out=[]
 for i in range(len(text)-6):
  if text[i:i+5]==b'\x9a\0\0\0\0':
   sel=struct.unpack_from('<H',text,i+5)[0]; num=None
   if sel==7:
    for j in range(max(0,i-20),i):
     if text[j]==0xb8 and j+5<=i:num=struct.unpack_from('<I',text,j+1)[0]
   out.append({'pc':OLD_TEXT+i,'selector':sel,'syscall':num,'name':SYSCALL_NAMES.get(num,'unknown')})
 return out

def profile_info(data,coff,text,path=None):
 return {'id':'intel-ic-r30-native-svr3-i386','family':'native-static-svr3-i386','fingerprint_sha256':IC_SHA256,'layout':{'text_start':OLD_TEXT,'text_size':TEXT_SIZE,'entry':OLD_ENTRY,'data_start':OLD_DATA,'data_size':DATA_SIZE,'bss_start':OLD_BSS,'bss_size':BSS_SIZE},'relocation':{'new_text_va':NEW_TEXT,'delta':DELTA},'traps':trap_inventory(text)}

# Runtime layout, independent of the shared syscall implementation.
RUNTIME_BANNER="SVR3 IC R4O"
RUNTIME_BRK_MIN=0x00409960  # retain the live-proven IC runtime byte-for-byte
BRK_WORD=0x00442b34
ALLOC_WORDS=(0x00442b1c,0x00442b20,0x00442b24,0x00442b28,0x00442b2c,0x00442b34)
