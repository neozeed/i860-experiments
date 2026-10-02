"""Exact Portland Group native-i386 as860 profile. Shared PE/syscall runtime."""
import hashlib,struct
from pathlib import Path
from types import SimpleNamespace
from native_ic_profile import _decoded_text,symbol_names
from native_relocation import relocate_exact
SHA256='66c441db201bdc9f93f310b669ab3da22191004fcf5d70ec40187dbeed054288'
OLD_TEXT=0xd0;OLD_ENTRY=0xd4;TEXT_SIZE=100400
OLD_DATA=0x400900;DATA_SIZE=37764;OLD_BSS=0x409c84;BSS_SIZE=6592
NEW_TEXT=0x500000;DELTA=NEW_TEXT-OLD_TEXT;HEAP_LIMIT=0x4f0000;EXPECTED_GATES=13
RUNTIME_BANNER='SVR3 PGC AS860 R4P'
RUNTIME_BRK_MIN=OLD_BSS+BSS_SIZE
BRK_WORD=0x409c80
ALLOC_WORDS=(0x409c68,0x409c6c,0x409c70,0x409c74,0x409c78,BRK_WORD)
# Instruction PC, full expected dispatch encoding, table base, bounded count.
# Counts come from the preceding range checks, not a scan through adjacent data.
TABLES=(
 (0xe0a,'ff2485c84a4000',0x404ac8,271),
 (0xf30,'ff248da44a4000',0x404aa4,9),
 (0x52e5,'ff248578634000',0x406378,8),
 (0x5618,'ff248d98634000',0x406398,18),
 (0xfbf3,'ff248500694000',0x406900,13),
 (0x16c4a,'ff24853c914000',0x40913c,89),
)
OPERANDS=((0x42cc,0x44a0,'v_comp'),(0x43af,0x44d4,'p_comp'))
GATES=(0x110,0x15659,0x15ef1,0x15f79,0x15fbd,0x182d1,0x183a9,0x18801,0x18815,0x1884e,0x188b9,0x188cd,0x188f2)
NAMES={1:'exit',13:'time',33:'access',19:'lseek',10:'unlink',6:'close',54:'ioctl',5:'open',3:'read',17:'brk',4:'write',20:'getpid'}

def matches(data,coff):
 return hashlib.sha256(data).hexdigest()==SHA256 and coff['magic']==0x14c

def discover_manifest(path,text,data):
 if hashlib.sha256(Path(path).read_bytes()).hexdigest()!=SHA256:raise RuntimeError('as860 fingerprint mismatch')
 rows={va:raw for va,raw,asm in _decoded_text(path)}
 names=symbol_names(path,OLD_TEXT,TEXT_SIZE);ops=[]
 for va,target,name in OPERANDS:
  assert rows[va]==b'\x68'+struct.pack('<I',target)
  assert name in names[target]
  ops.append((va,1,target))
 tables=[]
 for va,encoding,base,count in TABLES:
  assert rows[va]==bytes.fromhex(encoding)
  for k in range(count):
   target=struct.unpack_from('<I',data,base-OLD_DATA+4*k)[0]
   assert target in rows,('dispatch target is not an instruction',hex(target))
  tables.append((base,count))
 actual=tuple(va for va,raw in rows.items() if raw==bytes.fromhex('9a000000000700'))
 assert actual==GATES
 assert struct.unpack_from('<I',data,BRK_WORD-OLD_DATA)[0]==RUNTIME_BRK_MIN
 return {'operand_sites':ops,'text_tables':[],'data_tables':tables,'data_symbol_ptrs':[],'symbol_count':len(names)}

def relocate(path,text,data,gate7,gate15=None):
 return relocate_exact(SimpleNamespace(**globals()),path,text,data,gate7,gate15)

def trap_inventory(text):
 out=[]
 for va in GATES:
  i=va-OLD_TEXT;num=1 if va==0x110 else struct.unpack_from('<I',text,i-4)[0]
  out.append({'pc':va,'selector':7,'syscall':num,'name':NAMES.get(num,'unknown')})
 return out

def profile_info(data,coff,text,path=None):
 return {'id':'pgc-as860-native-svr3-i386','family':'native-static-svr3-i386','fingerprint_sha256':SHA256,
 'layout':{'text_start':OLD_TEXT,'text_size':TEXT_SIZE,'entry':OLD_ENTRY,'data_start':OLD_DATA,'data_size':DATA_SIZE,'bss_start':OLD_BSS,'bss_size':BSS_SIZE},
 'relocation':{'new_text_va':NEW_TEXT,'delta':DELTA},'traps':trap_inventory(text)}
