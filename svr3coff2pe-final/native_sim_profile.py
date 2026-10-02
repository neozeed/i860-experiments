"""Fingerprint-locked Intel SIM860 1.1 native i386 profile; no pointer guessing."""
import hashlib,json,struct
from pathlib import Path
from types import SimpleNamespace
from native_ic_profile import _decoded_text
from native_relocation import relocate_exact
SHA256='928de5a562d0307ef94df5bd5078b10e3180439f5ae65c73db4dc38f51c6cb9a'
OLD_TEXT=0xd0; OLD_ENTRY=0xd4; TEXT_SIZE=163096
OLD_DATA=0x400de8; DATA_SIZE=69360; OLD_BSS=OLD_DATA+DATA_SIZE; BSS_SIZE=29040
NEW_TEXT=0x500000; DELTA=NEW_TEXT-OLD_TEXT; HEAP_LIMIT=0x4f0000; EXPECTED_GATES=55
RUNTIME_BANNER='SVR3 SIM860 i386 R4S'
RUNTIME_BRK_MIN=OLD_BSS+BSS_SIZE
BRK_WORD=0x411ad4
ALLOC_WORDS=(0x411abc,0x411ac0,0x411ac4,0x411ac8,0x411acc,BRK_WORD)
MANIFEST=json.loads(Path(__file__).with_name('sim860-manifest.json').read_text())
def matches(data,coff):return hashlib.sha256(data).hexdigest()==SHA256 and coff['magic']==0x14c

def discover_manifest(path,text,data):
 assert hashlib.sha256(Path(path).read_bytes()).hexdigest()==SHA256
 rows={v:r for v,r,a in _decoded_text(path)}; ops=[]; tables=[]
 for va,encoding,k,target in MANIFEST['operands']:
  assert rows[va]==bytes.fromhex(encoding) and target in rows
  ops.append((va,k,target))
 for va,encoding,base,count,cmpva,cmpencoding in MANIFEST['tables']:
  assert rows[va]==bytes.fromhex(encoding) and rows[cmpva]==bytes.fromhex(cmpencoding)
  assert struct.unpack_from('<I',bytes.fromhex(cmpencoding),1)[0]+1==count
  tables.append((base,count))
 # Opcode index is insn >> 26 (64 entries); FP subopcode 0x20..0x5f plus default (65).
 assert rows[0xddd]==bytes.fromhex('c1e81a')
 assert rows[0xe93]==bytes.fromhex('8b0485980e4000')
 assert rows[0x8663]==bytes.fromhex('3d5f000000')
 assert rows[0x866a]==bytes.fromhex('b840000000')
 assert rows[0x867b]==bytes.fromhex('2d20000000')
 assert rows[0x8680]==bytes.fromhex('8b048504114000')
 tables+=MANIFEST['dispatch']
 for base,count in tables:
  for k in range(count):
   target=struct.unpack_from('<I',data,base-OLD_DATA+4*k)[0]
   assert target in rows,(hex(base+4*k),hex(target))
 assert [v for v,r in rows.items() if r==bytes.fromhex('9a000000000700')]==MANIFEST['gates']
 assert [v for v,r in rows.items() if r==bytes.fromhex('9a000000000f00')]==MANIFEST['gate15']
 assert struct.unpack_from('<I',data,BRK_WORD-OLD_DATA)[0]==RUNTIME_BRK_MIN
 return {'operand_sites':ops,'text_tables':[],'data_tables':tables,'data_symbol_ptrs':[],'symbol_count':0}

def relocate(path,text,data,gate7,gate15=None):
 t,d,p,c,m=relocate_exact(SimpleNamespace(**globals()),path,text,data,gate7,gate15)
 t=bytearray(t)
 for va in MANIFEST['gate15']:
  off=va-OLD_TEXT;t[off:off+7]=b'\xe8'+struct.pack('<I',(gate15-(NEW_TEXT+off+5))&0xffffffff)+b'\x90\x90'
  p.append({'kind':'syscall_gate','selector':15,'old_va':va,'new_va':NEW_TEXT+off,'target':gate15})
 c[15]=len(MANIFEST['gate15']);return bytes(t),d,p,c,m

def trap_inventory(text):
 out=[]
 for va in MANIFEST['gates']:
  # EAX syscall load can precede signal-wrapper setup and branches.
  i=va-OLD_TEXT;num=1 if va==0x110 else None
  for k in range(i-5,max(-1,i-40),-1):
   if text[k]==0xb8:num=struct.unpack_from('<I',text,k+1)[0];break
  out.append({'pc':va,'selector':7,'syscall':num})
 out += [{'pc':v,'selector':15,'syscall':None} for v in MANIFEST['gate15']]
 return out

def profile_info(data,coff,text,path=None):
 return {'id':'intel-sim860-1.1-native-svr3-i386','family':'native-static-svr3-i386','fingerprint_sha256':SHA256,'layout':{'text_start':OLD_TEXT,'text_size':TEXT_SIZE,'entry':OLD_ENTRY,'data_start':OLD_DATA,'data_size':DATA_SIZE,'bss_start':OLD_BSS,'bss_size':BSS_SIZE},'relocation':{'new_text_va':NEW_TEXT,'delta':DELTA},'traps':trap_inventory(text)}
