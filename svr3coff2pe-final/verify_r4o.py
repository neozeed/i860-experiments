#!/usr/bin/env python3
"""Independent byte-preservation checks for the R4O IC conversion.
Optional second argument is the unmodified R4N reference PE.
"""
import sys,struct,json,hashlib
from pathlib import Path
HERE=Path(__file__).resolve().parent

def sections(blob):
 p=struct.unpack_from('<I',blob,0x3c)[0];n=struct.unpack_from('<H',blob,p+6)[0]
 sh=p+24+struct.unpack_from('<H',blob,p+20)[0];out={}
 for i in range(n):
  off=sh+40*i;name=blob[off:off+8].split(b'\0')[0].decode()
  size,va,rs,ptr=struct.unpack_from('<IIII',blob,off+8)
  out[name]=(va,blob[ptr:ptr+size])
 return out

exe=Path(sys.argv[1]) if len(sys.argv)>1 else HERE/'ic-pe-r4o.exe'
b=exe.read_bytes();s=sections(b);orig=s['.orig386'][1]
assert hashlib.sha256(orig).hexdigest()=='b03d634d16ffdd724d752d5aeb12831ba81423a9ab35e7216256bcb909b3ddab'
meta=json.loads(s['.meta'][1]);text=s['.svtext'][1]
expected=bytearray(orig[0xd0:0xa0a4c]);occupied=set();kinds={}
for p in meta['patches']:
 kind=p['kind'];kinds[kind]=kinds.get(kind,0)+1
 if kind=='syscall_gate':
  off=p['old_va']-0xd0;assert expected[off:off+7]==bytes.fromhex('9a000000000700')
  replacement=b'\xe8'+struct.pack('<I',(p['target']-(p['new_va']+5))&0xffffffff)+b'\x90\x90'
 elif kind=='absolute_text_operand':
  off=p['patch_offset'];assert struct.unpack_from('<I',expected,off)[0]==p['old']
  replacement=struct.pack('<I',p['new'])
 else:continue
 assert not occupied.intersection(range(off,off+len(replacement)))
 occupied.update(range(off,off+len(replacement)));expected[off:off+len(replacement)]=replacement
assert text==expected,'text changed outside authorized fields'
assert kinds=={'syscall_gate':14,'data_function_target':2173,'absolute_text_operand':14}
assert len(meta['profile']['discovered_manifest']['data_tables'])==156
# Whole initialized data comparison: only the decoded dispatch slots may change.
expected_data=bytearray(orig[0xa0a4c:0xe2b38])
for p in meta['patches']:
 if p['kind']=='data_function_target':
  off=p['va']-0x400a4c;assert struct.unpack_from('<I',expected_data,off)[0]==p['old']
  struct.pack_into('<I',expected_data,off,p['new'])
first=0x1000-0xa4c
actual=b[0xa4c:0x1000]+s['.svmem'][1][:len(expected_data)-first]
assert actual==expected_data,'unexpected data mutation'
# Regression: every boolean stack store and original stack-allocation instruction
# retains its entire encoding. These were vulnerable to the old byte scanner.
for pattern in [bytes.fromhex('c745fc01000000'),bytes.fromhex('81eca0010000'),bytes.fromhex('f746fc01000000')]:
 at=0;count=0
 while True:
  at=orig.find(pattern,at,0xa0a4c)
  if at<0:break
  if at>=0xd0:assert text[at-0xd0:at-0xd0+len(pattern)]==pattern;count+=1
  at+=1
 print('preserved',pattern.hex(),count)
assert text[0x1b861-0xd0:0x1b865-0xd0]==struct.pack('<I',0x1b668+0x4fff30)
# Symbol reader sanity: _start is 0xd4, not GNU BFD's 0x1a4.
import native_ic_profile as profile
assert '_start' in profile.symbol_names(HERE/'ic')[0xd4]
assert 'malloc' in profile.symbol_names(HERE/'ic')[0xa0538]
if len(sys.argv)>2:
 old=sections(Path(sys.argv[2]).read_bytes());om=json.loads(old['.meta'][1]);ot=old['.svtext'][1]
 oldslots={p['va']:p['new'] for p in om['patches'] if p['kind']=='data_function_target'}
 newslots={p['va']:p['new'] for p in meta['patches'] if p['kind']=='data_function_target'}
 assert len(oldslots)==2167 and all(newslots[k]==v for k,v in oldslots.items())
 false=next(p for p in om['patches'] if p['kind']=='absolute_text_operand' and p['va']==0x81fe)
 off=0x81fe-0xd0
 assert orig[0x81fe:0x8205]==bytes.fromhex('c745fc01000000')
 assert ot[off:off+7]==bytes.fromhex('c7452c01500000')
 assert text[off:off+7]==bytes.fromhex('c745fc01000000')
 print('R4N corrupt stack store reproduced; R4O restores original encoding')
 print('All 2167 previous dispatch slots preserved; 6 additional proven slots')
print('PASS: R4O static audit',kinds)
print('Native Windows execution has NOT been tested here.')
