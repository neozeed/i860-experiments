from pathlib import Path
import struct
ROOT=Path(__file__).resolve().parent
T=0xf04000c0
loop=(ROOT/'loop.oracle').read_bytes()
def coff(text):
 b=bytearray(loop[:192])+bytearray(text)+bytearray(loop[224:]);delta=len(text)-32
 struct.pack_into('<I',b,8,224+delta);struct.pack_into('<I',b,24,len(text))
 struct.pack_into('<I',b,56+16,len(text));struct.pack_into('<I',b,56+24,224+delta)
 struct.pack_into('<I',b,96+20,224+delta)
 return bytes(b)
def imm(r,v):return [0xe4000000|(r<<16)|(v&65535),0xec000000|(r<<21)|(r<<16)|((v>>16)&65535)]
def umod(a,b):
 words=imm(16,a)+imm(17,b)
 words += [0x6c000000|((32-(len(words)*4+4))//4),0xa0000000,0xe41f0001,0x47e0f800]
 wrapper=bytearray((ROOT/'u.o').read_bytes()[140:188]);helper=(ROOT/'uimod.o').read_bytes()[140:364]
 call=struct.unpack_from('<I',wrapper,20)[0];struct.pack_into('<I',wrapper,20,(call&0xfc000000)|((48-24)//4))
 return coff(struct.pack('<8I',*words)+wrapper+helper)
exit860=coff(struct.pack('<8I',0xe4100000,0xe41f0001,0x47e0f800,*([0xa0000000]*5)))
if __name__=='__main__':
 p=ROOT/'fixtures';p.mkdir(exist_ok=True);(p/'exit860').write_bytes(exit860)
 for a,b in [(1071,462),(17,5),(0xffffffff,3),(0xffffffff,0x80000000),(0x80000000,7),(0,7),(7,1),(5,17),(0xfffffffe,0xffffffff)]:
  (p/f'umod-{a:x}-{b:x}').write_bytes(umod(a,b))

if __name__=='__main__':
 msg=b'Native i386 SIM860 target write PASS\n'
 words=[0xe4100001]+imm(17,T+48)+[0xe4120000|len(msg),0xe41f0004,0x47e0f800,0xe4100000,0xe41f0001,0x47e0f800]+[0xa0000000]*3
 (p/'hello860').write_bytes(coff(struct.pack('<12I',*words)+msg+b'\0'*((-len(msg))%4)))
