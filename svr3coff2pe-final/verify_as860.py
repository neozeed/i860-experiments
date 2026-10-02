#!/usr/bin/env python3
"""Byte-preservation audit of the PGC assembler target; no Windows required."""
from pathlib import Path
import struct,hashlib,json,sys
root=Path(__file__).resolve().parent
exe=Path(sys.argv[1]) if len(sys.argv)>1 else root/'as860-pgc.exe'
b=exe.read_bytes();p=struct.unpack_from('<I',b,60)[0];n=struct.unpack_from('<H',b,p+6)[0];sh=p+24+struct.unpack_from('<H',b,p+20)[0];secs={};ranges=[]
for i in range(n):
 off=sh+40*i;name=b[off:off+8].split(b'\0')[0].decode();size,rva,rs,ptr=struct.unpack_from('<IIII',b,off+8)
 secs[name]=b[ptr:ptr+size];ranges.append((rva,size))
for (rva,size),(nextva,_) in zip(ranges,ranges[1:]):assert (rva+size+4095)&~4095==nextva
orig=secs['.orig386'];assert hashlib.sha256(orig).hexdigest()=='66c441db201bdc9f93f310b669ab3da22191004fcf5d70ec40187dbeed054288'
text=bytearray(orig[208:100608]);data=bytearray(orig[100608:138372]);delta=0x4fff30
# Only these complete instructions / operand locations are permitted to change.
gates=[0x110,0x15659,0x15ef1,0x15f79,0x15fbd,0x182d1,0x183a9,0x18801,0x18815,0x1884e,0x188b9,0x188cd,0x188f2]
meta=json.loads(secs['.meta']);target={p['target'] for p in meta['patches'] if p['kind']=='syscall_gate'};assert len(target)==1;gate=target.pop()
for va in gates:
 at=va-208;assert text[at:at+7]==bytes.fromhex('9a000000000700')
 text[at:at+7]=b'\xe8'+struct.pack('<I',(gate-(va+delta+5))&0xffffffff)+b'\x90\x90'
for va,old in [(0x42cc,0x44a0),(0x43af,0x44d4)]:
 at=va-208;assert text[at:at+5]==b'\x68'+struct.pack('<I',old)
 struct.pack_into('<I',text,at+1,old+delta)
assert text==secs['.svtext'],'unexpected instruction mutation'
count=0
for base,n in [(0x404ac8,271),(0x404aa4,9),(0x406378,8),(0x406398,18),(0x406900,13),(0x40913c,89)]:
 for k in range(n):
  at=base-0x400900+4*k;old=struct.unpack_from('<I',data,at)[0];assert 208<=old<100608
  struct.pack_into('<I',data,at,old+delta);count+=1
assert count==408
assert data==b[0x900:0x1000]+secs['.svmem'][:len(data)-0x700],'unexpected initialized data mutation'
assert struct.unpack_from('<I',data,0x409c80-0x400900)[0]==0x40b644
assert len(meta['patches'])==423
assert all(meta['output']['checks'].values()) if 'output' in meta else True
print('PASS: 13 gate patches, 2 callback immediates, 408 bounded dispatch slots')
print('PASS: all remaining text and initialized data preserved byte-for-byte')
print('PASS: original fingerprint, initial break, adjacent PE sections')
print('Native Windows assembler execution is not tested here.')
