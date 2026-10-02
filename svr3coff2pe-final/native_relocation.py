"""Shared patch engine for fingerprinted SVR3 native targets."""
import struct

def relocate_exact(profile,path,text,data,gate7,gate15=None):
 t=bytearray(text); d=bytearray(data); patches=[]
 if len(t)!=profile.TEXT_SIZE or len(d)!=profile.DATA_SIZE: raise RuntimeError('IC profile section sizes changed')
 man=profile.discover_manifest(path,text,data)
 # syscall gates
 pat=b'\x9a\x00\x00\x00\x00\x07\x00'; pos=0; count=0
 while True:
  i=t.find(pat,pos)
  if i<0: break
  callva=profile.NEW_TEXT+i; rel=(gate7-(callva+5))&0xffffffff
  t[i:i+7]=b'\xe8'+struct.pack('<I',rel)+b'\x90\x90'; patches.append({'kind':'syscall_gate','selector':7,'old_va':profile.OLD_TEXT+i,'new_va':callva,'target':gate7}); count+=1;pos=i+7
 if profile.EXPECTED_GATES is not None and count!=profile.EXPECTED_GATES: raise RuntimeError('native gate count mismatch %d expected %s'%(count,profile.EXPECTED_GATES))
 occupied=set()
 # tables first
 for va,n in man['text_tables']:
  off=va-profile.OLD_TEXT
  for k in range(n):
   p=off+4*k; old=struct.unpack_from('<I',text,p)[0]
   if not profile.OLD_TEXT<=old<profile.OLD_TEXT+profile.TEXT_SIZE: raise RuntimeError('bad IC text table')
   if bytes(t[p:p+4]) != bytes(text[p:p+4]): continue
   struct.pack_into('<I',t,p,old+profile.DELTA); occupied.update(range(p,p+4)); patches.append({'kind':'text_switch_target','va':va+4*k,'old':old,'new':old+profile.DELTA})
 data_patched=set()
 for va,n in man['data_tables']:
  off=va-profile.OLD_DATA
  for k in range(n):
   p=off+4*k; slotva=va+4*k
   old=struct.unpack_from('<I',data,p)[0]
   if not profile.OLD_TEXT<=old<profile.OLD_TEXT+profile.TEXT_SIZE: raise RuntimeError('bad IC data table')
   if slotva in data_patched: continue
   struct.pack_into('<I',d,p,old+profile.DELTA); data_patched.add(slotva); patches.append({'kind':'data_function_target','va':slotva,'old':old,'new':old+profile.DELTA})
 for va,old in man['data_symbol_ptrs']:
  p=va-profile.OLD_DATA
  if va in data_patched: continue
  if struct.unpack_from('<I',data,p)[0]==old:
   struct.pack_into('<I',d,p,old+profile.DELTA); data_patched.add(va); patches.append({'kind':'data_symbol_target','va':va,'old':old,'new':old+profile.DELTA})
 # exact symbol-valued instruction immediates
 for va,k,old in man['operand_sites']:
  p=(va-profile.OLD_TEXT)+k
  if any(x in occupied for x in range(p,p+4)): continue
  if struct.unpack_from('<I',t,p)[0]!=old: continue
  struct.pack_into('<I',t,p,old+profile.DELTA); patches.append({'kind':'absolute_text_operand','va':va,'patch_offset':p,'old':old,'new':old+profile.DELTA})
 return bytes(t),bytes(d),patches,{7:count,15:0},man
