#!/usr/bin/env python3
"""Independent byte accounting against the reviewed fixed SIM860 manifest."""
from pathlib import Path
import hashlib,json,struct
root=Path(__file__).resolve().parent
b=(root/'sim860-i386-pe.exe').read_bytes();original=(root/'sim860.coff').read_bytes()
assert hashlib.sha256(original).hexdigest()=='928de5a562d0307ef94df5bd5078b10e3180439f5ae65c73db4dc38f51c6cb9a'
pe=struct.unpack_from('<I',b,60)[0];sh=pe+24+struct.unpack_from('<H',b,pe+20)[0];sections={}
for i in range(struct.unpack_from('<H',b,pe+6)[0]):
 p=sh+40*i;name=b[p:p+8].split(b'\0')[0].decode();vs,va,rs,ro=struct.unpack_from('<IIII',b,p+8);sections[name]=(va,b[ro:ro+vs])
assert sections['.orig386'][1]==original
m=json.loads((root/'sim860-manifest.json').read_text());t=bytearray(original[208:163304]);d=bytearray(original[163304:232664]);delta=0x500000-208
actual=sections['.svtext'][1];gate_targets={}
for selector,key in [(7,'gates'),(15,'gate15')]:
 for va in m[key]:
  off=va-208;raw=actual[off:off+7]
  assert raw[0]==0xe8 and raw[5:]==b'\x90\x90'
  dest=0x500000+off+5+struct.unpack_from('<i',raw,1)[0]
  assert 0x400000+sections['.host'][0]<=dest<0x400000+sections['.host'][0]+len(sections['.host'][1])
  gate_targets.setdefault(selector,set()).add(dest);t[off:off+7]=raw
assert all(len(x)==1 for x in gate_targets.values())
for va,encoding,k,target in m['operands']:
 assert t[va-208:va-208+len(bytes.fromhex(encoding))]==bytes.fromhex(encoding)
 struct.pack_into('<I',t,va-208+k,target+delta)
slots=set()
for base,count in [(x[2],x[3]) for x in m['tables']]+m['dispatch']:
 for k in range(count):slots.add(base+4*k)
for va in slots:
 off=va-0x400de8;old=struct.unpack_from('<I',d,off)[0];assert 208<=old<163304;struct.pack_into('<I',d,off,old+delta)
# R4S adds three exact, whole-instruction compatibility hooks.
import sim_fp_runtime
for va,encoding,symbol,opcode in sim_fp_runtime.SITES:
 off=va-208;expected=bytes.fromhex(encoding)
 assert bytes(t[off:off+len(expected)])==expected
 patched=actual[off:off+len(expected)]
 assert patched[0]==opcode and patched[5:]==b'\x90'*(len(expected)-5)
 dest=0x500000+off+5+struct.unpack_from('<i',patched,1)[0]
 assert 0x400000+sections['.host'][0]<=dest<0x400000+sections['.host'][0]+len(sections['.host'][1])
 t[off:off+len(expected)]=patched
assert bytes(t)==actual
assert bytes(d)==b[0xde8:0x1000]+sections['.svmem'][1][:len(d)-(0x1000-0xde8)]
assert len(slots)==809 and len(m['operands'])==7 and len(m['gates'])==55 and len(m['gate15'])==1
print('PASS: preserved original; 55 syscall gates + 1 signal-return gate, 7 operands, 809 dispatch slots')
print('PASS: 3 exact precision-bridge hooks; every other historical text/data byte unchanged')
