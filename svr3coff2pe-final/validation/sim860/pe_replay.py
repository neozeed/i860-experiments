"""Execute actual PE instructions in Unicorn; mock only imported Win32 APIs."""
import sys,struct,collections,json
from pathlib import Path
from unicorn import *
from unicorn.x86_const import *
here=Path(__file__).resolve().parent
root=here.parent.parent
b=(root/'sim860-i386-pe.exe').read_bytes();pe=struct.unpack_from('<I',b,60)[0];opt=pe+24
base=struct.unpack_from('<I',b,opt+28)[0];size=struct.unpack_from('<I',b,opt+56)[0];entry=base+struct.unpack_from('<I',b,opt+16)[0]
u=Uc(UC_ARCH_X86,UC_MODE_32);u.mem_map(base,(size+4095)&~4095);u.mem_write(base,b[:4096]);u.mem_map(0x70000000,0x200000);u.mem_map(0x68000000,0x10000)
for i in range(struct.unpack_from('<H',b,pe+6)[0]):
 s=pe+24+struct.unpack_from('<H',b,pe+20)[0]+i*40;vs,va,rs,ro=struct.unpack_from('<IIII',b,s+8);u.mem_write(base+va,b[ro:ro+rs])
def rd(a):return struct.unpack('<I',u.mem_read(a,4))[0]
def wr(a,v):u.mem_write(a,struct.pack('<I',v&0xffffffff))
def string(a):
 z=bytearray()
 while a:
  c=u.mem_read(a,1)[0];a+=1
  if not c:break
  z.append(c)
 return z.decode(errors='replace')
args=sys.argv[1:] or ['exit860'];cmd='sim860-i386-pe.exe '+' '.join(args);u.mem_write(0x68008000,cmd.encode()+b'\0');u.mem_write(0x68009000,b'\0\0')
u.reg_write(UC_X86_REG_ESP,0x701f0000);u.reg_write(UC_X86_REG_FPCW,0x37f)
files={};nextfd=100;stdin=bytearray(b':r _start\n$q\n');output=bytearray();counts=collections.Counter();status=None
fixtures={p.name:p.read_bytes() for p in (here/'fixtures').iterdir()}
fixtures['loop']=(here/'loop.oracle').read_bytes()
argc={'VirtualProtect':4,'GetStdHandle':1,'SetUnhandledExceptionFilter':1,'GetEnvironmentVariableA':3,'GetEnvironmentStringsA':0,'GetCommandLineA':0,'WriteFile':5,'ReadFile':5,'CreateFileA':7,'SetFilePointer':4,'CloseHandle':1,'GetFileAttributesA':1,'ExitProcess':1,'GetFileSize':2}
def api(uc,at,sz,name):
 global nextfd,status
 if name not in argc:raise RuntimeError('unexpected API '+name)
 counts[name]+=1;sp=u.reg_read(UC_X86_REG_ESP);v=[rd(sp+4+4*i) for i in range(argc[name])];rv=0
 if name=='VirtualProtect':wr(v[3],4);rv=1
 elif name=='GetStdHandle':rv={0xfffffff6:10,0xfffffff5:11,0xfffffff4:12}[v[0]]
 elif name=='GetCommandLineA':rv=0x68008000
 elif name=='GetEnvironmentStringsA':rv=0x68009000
 elif name in ('GetEnvironmentVariableA','SetUnhandledExceptionFilter'):rv=0
 elif name=='WriteFile':
  z=bytes(u.mem_read(v[1],v[2]));output.extend(z);wr(v[3],len(z));rv=1
 elif name=='ReadFile':
  if v[0]==10:z=bytes(stdin[:v[2]]);del stdin[:len(z)]
  else:
   f=files[v[0]];z=f[0][f[1]:f[1]+v[2]];f[1]+=len(z)
  if z:u.mem_write(v[1],z)
  wr(v[3],len(z));rv=1
 elif name=='CreateFileA':
  path=string(v[0])
  if path in fixtures:rv=nextfd;nextfd+=1;files[rv]=[fixtures[path],0]
  else:rv=0xffffffff
 elif name=='SetFilePointer':
  f=files[v[0]];off=v[1] if v[1]<2**31 else v[1]-2**32;f[1]=[0,f[1],len(f[0])][v[3]]+off;rv=f[1]
 elif name=='CloseHandle':files.pop(v[0],None);rv=1
 elif name=='GetFileAttributesA':rv=0x80 if string(v[0]) in fixtures else 0xffffffff
 elif name=='GetFileSize':rv=len(files[v[0]][0])
 elif name=='ExitProcess':status=v[0];u.emu_stop();return
 u.reg_write(UC_X86_REG_EAX,rv);u.reg_write(UC_X86_REG_EIP,rd(sp));u.reg_write(UC_X86_REG_ESP,sp+4+4*argc[name])
imp=base+struct.unpack_from('<I',b,opt+104)[0];idx=0
while rd(imp+12):
 orig=base+rd(imp);iat=base+rd(imp+16);j=0
 while rd(orig+4*j):
  name=string(base+rd(orig+4*j)+2);stub=0x68000000+16*idx;idx+=1;wr(iat+4*j,stub);u.hook_add(UC_HOOK_CODE,api,user_data=name,begin=stub,end=stub);j+=1
 imp+=20
try:u.emu_start(entry,0,count=10000000)
except Exception as e:print('ERROR',e,'PC',hex(u.reg_read(UC_X86_REG_EIP)));raise
print(output.decode(errors='replace'))
result={'exit':status,'target_r16':rd(0x411e28),'pc':hex(u.reg_read(UC_X86_REG_EIP)),'api_calls':dict(counts)}
print(json.dumps(result))
if status is None:raise RuntimeError('instruction limit reached')
