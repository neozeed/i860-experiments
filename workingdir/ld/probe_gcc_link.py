from pathlib import Path
import struct, ctypes, hashlib
root=Path(__file__).resolve().parent
art=root/'artifacts'
payload=(art/'ld860.payload.i860.coff').read_bytes()
startobj=Path('/mnt/data/as860r3e/as860-r3d-package/artifacts/start.o').read_bytes()
gcdobj=Path('/mnt/data/as860r3e/as860-r3d-package/artifacts/gcd.o').read_bytes()
umodobj=Path('/mnt/data/as860r3e/as860-r3d-package/artifacts/umodsi3.o').read_bytes()
def fail(s): print('FAIL',s); raise SystemExit(1)
def ok(s): print('PASS',s)
# Independent AS860 R3 i860 execution oracle: same ISA subset, now with write(4) trap service. This deliberately does not import or
# execute r5cpu.c; it replays the supported ISA subset directly from .i860.
import ctypes

def u32(x): return x & 0xffffffff
def s32(x): return ctypes.c_int32(x & 0xffffffff).value
def sx16(x):
    x &= 0xffff
    return x-0x10000 if x & 0x8000 else x
def sx26(x):
    x &= 0x03ffffff
    return x-0x04000000 if x & 0x02000000 else x
def opm(w,m,l): return (w&m)==m and (w&l)==0
def split16(w): return sx16(((w>>5)&0xf800)|(w&0x07ff))

TBASE=0xf04000c0; TSZ=0x153c0; TRAW=0xc0
DBASE=0x1480; DSZ=0x4440; DRAW=0x15480; BSZ=0x100
SBASE=0x00100000; SSZ=0x10000; ENTRY=0xf040dbe0
text=bytearray(payload[TRAW:TRAW+TSZ]); low=bytearray(payload[DRAW:DRAW+DSZ]+b'\0'*(SBASE-DBASE-DSZ)); stack=bytearray(SSZ)

def region(a,n,write=False):
    if TBASE <= a and a+n <= TBASE+len(text):
        if write: raise RuntimeError('write-text')
        return text,a-TBASE
    if DBASE <= a and a+n <= DBASE+len(low): return low,a-DBASE
    if SBASE <= a and a+n <= SBASE+len(stack): return stack,a-SBASE
    raise RuntimeError('memory %08x+%d'%(a,n))
def rd(a,n):
    b,o=region(a,n,False); v=int.from_bytes(b[o:o+n],'little')
    if n==1 and v&0x80: v|=0xffffff00
    elif n==2 and v&0x8000: v|=0xffff0000
    return u32(v)
def wr(a,n,v):
    if n in (2,4,8) and a&(n-1): raise RuntimeError('unaligned')
    b,o=region(a,n,True); b[o:o+n]=(v&((1<<(n*8))-1)).to_bytes(n,'little')

r=[0]*32; f=[0]*32; cr=[0]*16; cc=0; lcc=0; pc=ENTRY; count=0; r[2]=SBASE+SSZ-16

def setr(n,v):
    if n: r[n]=u32(v)
def getfd(n):
    return struct.unpack('<d', struct.pack('<II',f[n]&0xffffffff,f[n+1]&0xffffffff))[0]
def setfd(n,v):
    lo,hi=struct.unpack('<II',struct.pack('<d',v)); f[n]=lo; f[n+1]=hi
def nonctl(at,w):
    global pc,cc
    s1=(w>>11)&31; s2=(w>>21)&31; d=(w>>16)&31
    if opm(w,0x30000000,0xcc000000): setr(d,cr[s2&15]); pc=u32(at+4); return True
    if opm(w,0x08000000,0xf4000000): f[d]=r[s1]; pc=u32(at+4); return True
    if opm(w,0x480001a1,0xb400065e): f[d]=u32(f[s1]*f[s2]); f[d+1 if d<31 else d]=0 if d<31 else f[d]; pc=u32(at+4); return True
    if opm(w,0x48000040,0xb40007bf): setr(d,f[s1]); pc=u32(at+4); return True
    if opm(w,0x48000049,0xb40007b6): f[d]=u32(f[s1]+f[s2]); pc=u32(at+4); return True
    if opm(w,0x480001b1,0xb400044e):
        if (s1|s2|d)&1: return False
        setfd(d,getfd(s1)-getfd(s2)); pc=u32(at+4); return True
    if opm(w,0x480001a2,0xb400065d):
        if (s2|d)&1: return False
        setfd(d,1.0/getfd(s2)); pc=u32(at+4); return True
    if opm(w,0x480001a0,0xb400065f):
        if (s1|s2|d)&1: return False
        setfd(d,getfd(s1)*getfd(s2)); pc=u32(at+4); return True
    if opm(w,0x480001ba,0xb4000445):
        if (s1|d)&1: return False
        iv=int(getfd(s1)); f[d]=u32(iv); f[d+1]=0; pc=u32(at+4); return True
    if opm(w,0x38000000,0xc4000000): cr[s2&15]=r[s1]; pc=u32(at+4); return True
    # floating loads; ++ replaces src2 with the effective address
    floads=[(0x24000002,0xd8000001,1,4,False,True),(0x20000002,0xdc000001,1,4,False,False),
            (0x24000003,0xd8000000,1,4,True,True),(0x20000003,0xdc000000,1,4,True,False),
            (0x24000000,0xd8000007,2,8,False,True),(0x20000000,0xdc000007,2,8,False,False),
            (0x24000001,0xd8000006,2,8,True,True),(0x20000001,0xdc000006,2,8,True,False),
            (0x24000004,0xd8000003,4,16,False,True),(0x20000004,0xdc000003,4,16,False,False),
            (0x24000005,0xd8000002,4,16,True,True),(0x20000005,0xdc000002,4,16,True,False)]
    for m,l,words,al,inc,imm in floads:
        if opm(w,m,l):
            if d&(words-1): return False
            off=(u32(sx16(w))&~(al-1)) if imm else r[s1]; a=u32(r[s2]+off)
            for j in range(words): f[d+j]=rd(u32(a+j*4),4)
            if inc: setr(s2,a)
            pc=u32(at+4); return True
    if opm(w,0x2c000005,0xd0000002):
        if d&3: return False
        off=u32(sx16(w))&~15; a=u32(r[s2]+off)
        for j in range(4): wr(u32(a+j*4),4,f[d+j])
        setr(s2,a); pc=u32(at+4); return True
    if opm(w,0x28000005,0xd4000002):
        if d&3: return False
        a=u32(r[s2]+r[s1])
        for j in range(4): wr(u32(a+j*4),4,f[d+j])
        setr(s2,a); pc=u32(at+4); return True
    if opm(w,0x2c000004,0xd0000003):
        if d&3: return False
        a=u32(r[s2]+(u32(sx16(w))&~15))
        for j in range(4): wr(u32(a+j*4),4,f[d+j])
        pc=u32(at+4); return True
    if opm(w,0x28000004,0xd4000003):
        if d&3: return False
        a=u32(r[s2]+r[s1])
        for j in range(4): wr(u32(a+j*4),4,f[d+j])
        pc=u32(at+4); return True
    fstores=[(0x2c000002,0xd0000001,1,4,False,True),(0x28000002,0xd4000001,1,4,False,False),
             (0x2c000003,0xd0000000,1,4,True,True),(0x28000003,0xd4000000,1,4,True,False),
             (0x2c000001,0xd0000006,2,8,True,True),(0x28000001,0xd4000006,2,8,True,False)]
    for m,l,words,al,inc,imm in fstores:
        if opm(w,m,l):
            if d&(words-1): return False
            off=(u32(sx16(w))&~(al-1)) if imm else r[s1]; a=u32(r[s2]+off)
            for j in range(words): wr(u32(a+j*4),4,f[d+j])
            if inc: setr(s2,a)
            pc=u32(at+4); return True
    if opm(w,0x2c000000,0xd0000007):
        if d&1: return False
        off=u32(sx16(w))&~7; wr(u32(r[s2]+off),8,(f[d]&0xffffffff)|((f[d+1]&0xffffffff)<<32)); pc=u32(at+4); return True
    if opm(w,0x28000000,0xd4000007):
        if d&1: return False
        wr(u32(r[s2]+r[s1]),8,(f[d]&0xffffffff)|((f[d+1]&0xffffffff)<<32)); pc=u32(at+4); return True
    n=0
    if opm(w,0x0c000000,0xf0000000): n=1
    elif opm(w,0x1c000000,0xe0000001): n=2
    elif opm(w,0x1c000001,0xe0000000): n=4
    if n:
        off=split16(w)&~(n-1); wr(u32(r[s2]+off),n,r[s1]); pc=u32(at+4); return True
    mode=None
    if opm(w,0x00000000,0xfc000000): n,off=1,r[s1]
    elif opm(w,0x04000000,0xf8000000): n,off=1,u32(sx16(w))
    elif opm(w,0x10000000,0xec000001): n,off=2,r[s1]
    elif opm(w,0x14000000,0xe8000001): n,off=2,u32(sx16(w))&~1
    elif opm(w,0x10000001,0xec000000): n,off=4,r[s1]
    elif opm(w,0x14000001,0xe8000000): n,off=4,u32(sx16(w))&~3
    else: n=0
    if n:
        if n in (2,4) and u32(r[s2]+off)&(n-1): raise RuntimeError('unaligned load')
        setr(d,rd(u32(r[s2]+off),n)); pc=u32(at+4); return True
    ar=[('addu',0x80000000,0x7c000000,0),('addu',0x84000000,0x78000000,1),('adds',0x90000000,0x6c000000,0),('adds',0x94000000,0x68000000,1),('subu',0x88000000,0x74000000,0),('subu',0x8c000000,0x70000000,1),('subs',0x98000000,0x64000000,0),('subs',0x9c000000,0x60000000,1)]
    for name,m,l,imm in ar:
        if opm(w,m,l):
            a=u32(sx16(w)) if imm else r[s1]; b=r[s2]
            if name=='addu': v=u32(a+b); cc=1 if v<a else 0
            elif name=='adds': v=u32(a+b); cc=1 if s32(b)<s32(u32(-a)) else 0
            elif name=='subu': v=u32(a-b); cc=1 if b<=a else 0
            else: v=u32(a-b); cc=1 if s32(b)>s32(a) else 0
            setr(d,v); pc=u32(at+4); return True
    shifts=[('shl',0xa0000000,0x5c000000,0),('shl',0xa4000000,0x58000000,1),('shr',0xa8000000,0x54000000,0),('shr',0xac000000,0x50000000,1),('shra',0xb8000000,0x44000000,0),('shra',0xbc000000,0x40000000,1)]
    for name,m,l,imm in shifts:
        if opm(w,m,l):
            sh=((w&0xffff) if imm else r[s1])&31; b=r[s2]
            v=u32(b<<sh) if name=='shl' else (b>>sh if name=='shr' else u32(s32(b)>>sh))
            setr(d,v); pc=u32(at+4); return True
    logs=[('and',0xc0000000,0x3c000000,0,0),('and',0xc4000000,0x38000000,1,0),('and',0xcc000000,0x30000000,1,1),('andnot',0xd0000000,0x2c000000,0,0),('andnot',0xd4000000,0x28000000,1,0),('andnot',0xdc000000,0x20000000,1,1),('or',0xe0000000,0x1c000000,0,0),('or',0xe4000000,0x18000000,1,0),('or',0xec000000,0x10000000,1,1),('xor',0xf0000000,0x0c000000,0,0),('xor',0xf4000000,0x08000000,1,0),('xor',0xfc000000,0x00000000,1,1)]
    for name,m,l,imm,hi in logs:
        if opm(w,m,l):
            a=(w&0xffff) if imm else r[s1]
            if hi: a=u32(a<<16)
            b=r[s2]
            if name=='and': v=a&b
            elif name=='andnot': v=(~a)&b
            elif name=='or': v=a|b
            else: v=a^b
            v=u32(v); cc=1 if v==0 else 0; setr(d,v); pc=u32(at+4); return True
    branches=[('bte',0x58000000,0xa4000000,0),('bte',0x5c000000,0xa0000000,1),('btne',0x50000000,0xac000000,0),('btne',0x54000000,0xa8000000,1)]
    for name,m,l,imm in branches:
        if opm(w,m,l):
            a=s1 if imm else r[s1]; take=(a==r[s2]);
            if name=='btne': take=not take
            pc=u32(at+4+(split16(w)*4)) if take else u32(at+4); return True
    if opm(w,0x70000000,0x8c000000): pc=u32(at+4+(sx26(w)*4)) if cc else u32(at+4); return True
    if opm(w,0x78000000,0x84000000): pc=u32(at+4+(sx26(w)*4)) if not cc else u32(at+4); return True
    return False

def fetch(at):
    global count
    w=rd(at,4); count+=1; return w
def delay(at):
    w=fetch(at)
    if not nonctl(at,w): raise RuntimeError('unsupported delay %08x %08x'%(at,w))

def get_cstr(addr,limit=1024):
    out=bytearray()
    for i in range(limit):
        b=rd(addr+i,1)&0xff
        if b==0: return bytes(out).decode('latin1')
        out.append(b)
    raise RuntimeError('unterminated string')

def store_stat(addr,size,mode=0x81b6):
    blob=bytearray(32)
    def p16(o,v): blob[o:o+2]=(v&0xffff).to_bytes(2,'little')
    def p32(o,v): blob[o:o+4]=(v&0xffffffff).to_bytes(4,'little')
    p16(0,0); p16(2,1); p16(4,mode); p16(6,1); p16(8,0); p16(10,0); p16(12,0)
    p32(16,size); p32(20,631152000); p32(24,631152000); p32(28,631152000)
    put_bytes(addr,blob)

class OF:
    def __init__(self,path,pos=0,flags=0): self.path=path; self.pos=pos; self.flags=flags

def normpath(path):
    p=path.replace('\\','/')
    for pre in ('/usr/tmp/','/tmp/'):
        if p.startswith(pre):
            tail=p[len(pre):]
            return (tail if tail else '.'), (not tail)
    if p in ('/usr/tmp','/tmp','/','.'):
        return '.',True
    return p,False

fs={'start.o':bytearray(startobj),'gcd.o':bytearray(gcdobj),'umodsi3.o':bytearray(umodobj)}
fds={}
nextfd=[3]
file_events=[]

def newfd(path,flags):
    fd=nextfd[0]; nextfd[0]+=1; fds[fd]=OF(path,0,flags); return fd

trap_counts={}
def step():
    global pc,cc,lcc
    at=pc; w=fetch(at); s1=(w>>11)&31
    if opm(w,0x68000000,0x94000000) or opm(w,0x6c000000,0x90000000):
        target=u32(at+4+(sx26(w)*4)); is_call=opm(w,0x6c000000,0x90000000)
        delay(at+4)
        if is_call: setr(1,at+8)
        pc=target; return True
    if opm(w,0x40000000,0xbc000000):
        target=r[s1]; delay(at+4); pc=target; return True
    if opm(w,0x4c000002,0xb000001d):
        target=r[s1]; setr(1,at+8); delay(at+4); pc=target; return True
    if opm(w,0x74000000,0x88000000) or opm(w,0x7c000000,0x80000000):
        cond=(cc!=0) if opm(w,0x74000000,0x88000000) else (cc==0)
        target=u32(at+4+(sx26(w)*4))
        if cond: delay(at+4); pc=target
        else: pc=u32(at+8)
        return True
    if opm(w,0xb4000000,0x48000000):
        s2=(w>>21)&31; old=lcc; src1v=r[s1]; orig2=r[s2]
        new_lcc=1 if s32(orig2)>=s32(u32(0-src1v)) else 0
        sm=u32(orig2+src1v); setr(s2,sm)
        target=u32(at+4+(split16(w)*4)); delay(at+4)
        lcc=new_lcc
        pc=target if old else u32(at+8); return True
    if opm(w,0x44000000,0xb8000000):
        nr=r[31]
        trap_counts[nr]=trap_counts.get(nr,0)+1
        if nr==1:
            exit_events.append((count,at,r[16]&0xff)); pc=u32(at+4); return 'exit'
        if nr==3:
            fd,buf,n=r[16],r[17],r[18]; file_events.append((count,at,'read',fd,buf,n))
            if fd==0:
                data=b''
            elif fd in fds:
                of=fds[fd]; data=bytes(fs[of.path][of.pos:of.pos+n]); of.pos+=len(data)
            else:
                setr(16,9); cc=1; pc=u32(at+4); return True
            put_bytes(buf,data); setr(16,len(data)); cc=0; pc=u32(at+4); return True
        if nr==4:
            fd,buf,n=r[16],r[17],r[18]
            try: bb,oo=region(buf,n,False); data=bytes(bb[oo:oo+n])
            except Exception: return False
            if fd<=2:
                if not (std_open_mask[0]&(1<<fd)): setr(16,9); cc=1; pc=u32(at+4); return True
                outputs.append((count,at,fd,buf,n,data))
            elif fd in fds:
                of=fds[fd]; arr=fs[of.path]; endp=of.pos+n
                if endp>len(arr): arr.extend(b'\0'*(endp-len(arr)))
                arr[of.pos:endp]=data; of.pos=endp
                file_events.append((count,at,'write',fd,n,of.path))
            else:
                setr(16,9); cc=1; pc=u32(at+4); return True
            setr(16,n); cc=0; pc=u32(at+4); return True
        if nr==5:
            raw=get_cstr(r[16]); path,isdir=normpath(raw); flags=r[17]; file_events.append((count,at,'open',raw,path,flags,r[18]))
            creat=bool(flags&0x100); excl=bool(flags&0x400); trunc=bool(flags&0x200)
            if path not in fs:
                if not creat: setr(16,2); cc=1; pc=u32(at+4); return True
                fs[path]=bytearray()
            elif creat and excl:
                setr(16,17); cc=1; pc=u32(at+4); return True
            if trunc: fs[path]=bytearray()
            fd=newfd(path,flags)
            if flags&8: fds[fd].pos=len(fs[path])
            setr(16,fd); cc=0; pc=u32(at+4); return True
        if nr==6:
            fd=r[16]; close_events.append((count,at,fd))
            if fd<=2 and (std_open_mask[0]&(1<<fd)):
                std_open_mask[0]&=~(1<<fd); setr(16,0); cc=0; pc=u32(at+4); return True
            if fd in fds:
                file_events.append((count,at,'close',fd,fds[fd].path)); del fds[fd]
                setr(16,0); cc=0; pc=u32(at+4); return True
            setr(16,9); cc=1; pc=u32(at+4); return True
        if nr==8:
            raw=get_cstr(r[16]); path,isdir=normpath(raw); fs[path]=bytearray(); fd=newfd(path,1|0x200); file_events.append((count,at,'creat',raw,path,r[17],fd)); setr(16,fd); cc=0; pc=u32(at+4); return True
        if nr==10:
            raw=get_cstr(r[16]); path,isdir=normpath(raw); file_events.append((count,at,'unlink',raw,path))
            if path in fs: del fs[path]; setr(16,0); cc=0
            else: setr(16,2); cc=1
            pc=u32(at+4); return True
        if nr==13:
            if r[16]: wr(r[16],4,631152000)
            setr(16,631152000); cc=0; pc=u32(at+4); return True
        if nr==15:
            raw=get_cstr(r[16]); path,isdir=normpath(raw); file_events.append((count,at,'chmod',raw,path,r[17]))
            if isdir or path in fs: setr(16,0); cc=0
            else: setr(16,2); cc=1
            pc=u32(at+4); return True
        if nr==17:
            req=r[16]
            if req>=DBASE+DSZ+BSZ and req<SBASE: setr(16,0); cc=0; pc=u32(at+4); return True
            setr(16,12); cc=1; pc=u32(at+4); return True
        if nr==18:
            raw=get_cstr(r[16]); path,isdir=normpath(raw); file_events.append((count,at,'stat',raw,path,r[17]))
            if isdir: store_stat(r[17],0,0x41ff); setr(16,0); cc=0
            elif path not in fs: setr(16,2); cc=1
            else: store_stat(r[17],len(fs[path])); setr(16,0); cc=0
            pc=u32(at+4); return True
        if nr==19:
            fd,off,wh=r[16],s32(r[17]),r[18]; file_events.append((count,at,'lseek',fd,off,wh))
            if fd not in fds: setr(16,22); cc=1; pc=u32(at+4); return True
            of=fds[fd]
            base=0 if wh==0 else (of.pos if wh==1 else len(fs[of.path]) if wh==2 else None)
            if base is None or base+off<0: setr(16,22); cc=1
            else: of.pos=base+off; setr(16,of.pos); cc=0
            pc=u32(at+4); return True
        if nr==28:
            fd=r[16]; file_events.append((count,at,'fstat',fd,r[17]))
            if fd<=2: store_stat(r[17],0,0x21b6); setr(16,0); cc=0
            elif fd in fds: store_stat(r[17],len(fs[fds[fd].path])); setr(16,0); cc=0
            else: setr(16,9); cc=1
            pc=u32(at+4); return True
        if nr==48:
            signal_events.append((count,at,r[16],r[17],r[18],r[19])); setr(16,0); cc=0; pc=u32(at+4); return True
        if nr==57:
            if r[17]==0 and r[18]==0:
                fields=[b'UNIX',b'run860',b'3.2',b'N1.3',b'i860']; blob=b''.join(x+b'\0'*(9-len(x)) for x in fields)
                put_bytes(r[16],blob); setr(16,0); cc=0; pc=u32(at+4); return True
            return False
        return False
    return nonctl(at,w)



# Construct the independently expected no-user-argument run860 startup state.
# Match the ABI contract, while deriving it independently from the build output:
# pointer vectors live at the bottom of the synthetic stack and strings follow.
def put_bytes(addr,b):
    reg,o=region(addr,len(b),True); reg[o:o+len(b)]=b

def put32(addr,v): wr(addr,4,v)

argv_strings=[b'ld860-r1.exe\0',b'start.o\0',b'gcd.o\0',b'umodsi3.o\0',b'-o\0',b'gcd\0']
env_strings=[b'PATH=.\0']
argc=len(argv_strings)
argv_addr=SBASE+0x100
envp_addr=argv_addr+(argc+1)*4
cur=(envp_addr+8+3)&~3
for i,s in enumerate(argv_strings):
    put32(argv_addr+i*4,cur); put_bytes(cur,s); cur+=len(s)
put32(argv_addr+argc*4,0)
for i,s in enumerate(env_strings):
    put32(envp_addr+i*4,cur); put_bytes(cur,s); cur+=len(s)
put32(envp_addr+len(env_strings)*4,0)
r[16]=argc; r[17]=argv_addr; r[18]=envp_addr
outputs=[]
close_events=[]
signal_events=[]
exit_events=[]
std_open_mask=[7]

stop=None
clean_exit=None
history=[]
for _ in range(1000000):
    at=pc; w=rd(at,4)
    history.append((at,w,r[1],r[2],r[3],r[4],r[16],r[17],r[18],r[19],cc,lcc))
    if len(history)>20: history.pop(0)
    try:
        rv=step()
    except Exception as e:
        print('EXCEPTION',hex(at),hex(w),count,repr(e),'regs', [hex(x) for x in r]); [print('HIST',' '.join(hex(v) for v in h)) for h in history]
        stop=(at,w,count,r[31],r[16],r[17],r[18],r[19],cc)
        break
    if rv == 'exit':
        clean_exit=(at,w,count,r[31],exit_events[-1][2],r[17],r[18],r[19],cc)
        break
    if not rv:
        stop=(at,w,count,r[31],r[16],r[17],r[18],r[19],cc)
        break


from collections import Counter

def sha(b): return hashlib.sha256(b).hexdigest()
if stop is not None or clean_exit is None:
    fail('linker did not reach clean exit: stop=%r exit=%r' % (stop,clean_exit))
print('CLEAN_EXIT',clean_exit)
print('TRAPS',sorted(trap_counts.items()))
print('FILE_EVENTS',Counter(e[2] for e in file_events))
print('FILES',[(k,len(v),sha(bytes(v))) for k,v in sorted(fs.items())])
console=b''.join(x[5] for x in outputs)
print('CONSOLE',repr(console))
if 'gcd' not in fs:
    fail('expected linked output gcd not produced')
out=bytes(fs['gcd'])
print('GCD_OUT',len(out),sha(out),out[:4].hex())
if out[:2] != b'\x4d\x01': fail('gcd output is not i860 COFF')
ok('GCC 1.40 objects linked to i860 COFF gcd')
(root/'artifacts-r1q'/'gcd.oracle').write_bytes(out)
