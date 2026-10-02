#!/usr/bin/env python3
"""Exact native-SVR3 profile for the recovered Intel ICC Release 3.3 driver.

This is profile family #2 for SVR3COFF2PE.  The final COFF has no relocation
records, so the relocation manifest is reconstructed from the exact image's
control-flow tables, retained symbols, and kernel-gate veneers.  It is
intentionally fingerprinted instead of guessed onto unrelated executables.
"""
import hashlib, json, re, struct, subprocess
from pathlib import Path

ICC_SHA256='aba93b229211d73f04d6bd3dd0b9db7e1633ae3c5c26c5f2ba457a1b9d1e2b9b'
OLD_TEXT=0x000000d0
OLD_ENTRY=0x000000f0
OLD_DATA=0x00400bc4
OLD_BSS=0x004033ac
TEXT_SIZE=0x0000aaf4
DATA_SIZE=0x000027e8
BSS_SIZE=0x000065b4
NEW_TEXT=0x00500000
DELTA=NEW_TEXT-OLD_TEXT
HEAP_LIMIT=0x004f0000

# VA, entry count. These are compiler-generated switch target arrays proven by
# the surrounding index range checks in the exact ICC image.
TEXT_TABLES=[
 (0x000003c0,25),(0x00000448,20),(0x00000888,6),(0x00003574,34),
 (0x00004f8c,2),(0x00005208,13),(0x00005dd0,14),(0x00005e30,9),
 (0x00005fb0,9),(0x00005ffc,9),
]
DATA_TABLES=[(0x004025c8,21),(0x00402764,89)]
# Instruction VA, old literal VA.  The 10 indirect-jump displacements are
# biased table bases; the four immediates are retained function pointers.
TEXT_OPERANDS=[
 (0x000003b9,0x000002b8),(0x0000043e,0x000002bc),(0x00000881,0x000007c8),
 (0x0000356b,0x0000357c),(0x00004f82,0x00004df4),(0x000051fe,0x000050e4),
 (0x00005dc9,0x00005ca0),(0x00005e26,0x00005ca0),(0x00005fa9,0x00005e80),
 (0x00005ff2,0x00005e6c),
 (0x00000199,0x00000128),(0x000001bc,0x00000128),
 (0x0000ab1d,0x0000ab80),(0x0000ab31,0x0000ab80),
]
SYSCALL_NAMES={1:'exit',2:'fork',3:'read',4:'write',5:'open',6:'close',7:'wait',8:'creat',10:'unlink',17:'brk',18:'stat',19:'lseek',20:'getpid',33:'access',48:'signal',54:'ioctl',59:'execve',80:'mkdir'}

def sha256(b): return hashlib.sha256(b).hexdigest()

def matches(data,coff):
 return (sha256(data)==ICC_SHA256 and coff['magic']==0x14c and coff['nscns']==4 and
         coff['optional_common'] and coff['optional_common']['entry']==OLD_ENTRY and
         coff['optional_common']['text_start']==OLD_TEXT and coff['optional_common']['data_start']==OLD_DATA)

def _patch_literal(buf, section_va, insn_va, old, patches, kind):
 off=insn_va-section_va
 pat=struct.pack('<I',old)
 # Search only a conservative 12-byte instruction window.
 hit=buf.find(pat,max(0,off),min(len(buf),off+12))
 if hit<0: raise RuntimeError('native ICC relocation literal missing at %08x -> %08x'%(insn_va,old))
 new=(old+DELTA)&0xffffffff
 buf[hit:hit+4]=struct.pack('<I',new)
 patches.append({'kind':kind,'va':insn_va,'patch_offset':hit,'old':old,'new':new})

def relocate(text,data,gate7,gate15):
 t=bytearray(text); d=bytearray(data); patches=[]
 if len(t)!=TEXT_SIZE or len(d)!=DATA_SIZE: raise RuntimeError('ICC profile section sizes changed')
 # Kernel gates.  Near CALL + 2 NOPs keeps each seven-byte veneer site fixed-size.
 counts={7:0,15:0}
 for sel,target in ((7,gate7),(15,gate15)):
  pat=b'\x9a\x00\x00\x00\x00'+struct.pack('<H',sel); pos=0
  while True:
   i=t.find(pat,pos)
   if i<0: break
   callva=NEW_TEXT+i
   rel=(target-(callva+5))&0xffffffff
   oldva=OLD_TEXT+i
   t[i:i+7]=b'\xe8'+struct.pack('<I',rel)+b'\x90\x90'
   patches.append({'kind':'syscall_gate','selector':sel,'old_va':oldva,'new_va':callva,'target':target})
   counts[sel]+=1;pos=i+7
 if counts!={7:20,15:1}: raise RuntimeError('ICC gate count mismatch %r'%counts)
 # Absolute operands embedded in actual instructions.
 for va,old in TEXT_OPERANDS:
  _patch_literal(t,OLD_TEXT,va,old,patches,'absolute_text_operand')
 # Embedded switch tables in .text.
 for va,n in TEXT_TABLES:
  off=va-OLD_TEXT
  for k in range(n):
   p=off+k*4; old=struct.unpack_from('<I',t,p)[0]
   if not (OLD_TEXT<=old<OLD_TEXT+TEXT_SIZE): raise RuntimeError('bad ICC text table entry %08x=%08x'%(va+k*4,old))
   new=old+DELTA; struct.pack_into('<I',t,p,new)
   patches.append({'kind':'text_switch_target','va':va+k*4,'old':old,'new':new})
 # Function-pointer tables in the preserved historical data segment.
 for va,n in DATA_TABLES:
  off=va-OLD_DATA
  for k in range(n):
   p=off+k*4; old=struct.unpack_from('<I',d,p)[0]
   if not (OLD_TEXT<=old<OLD_TEXT+TEXT_SIZE): raise RuntimeError('bad ICC data table entry %08x=%08x'%(va+k*4,old))
   new=old+DELTA; struct.pack_into('<I',d,p,new)
   patches.append({'kind':'data_function_target','va':va+k*4,'old':old,'new':new})
 return bytes(t),bytes(d),patches,counts

def trap_inventory(text):
 out=[]
 for i in range(len(text)-6):
  if text[i:i+5]==b'\x9a\0\0\0\0':
   sel=struct.unpack_from('<H',text,i+5)[0]
   num=None
   if sel==7:
    for j in range(max(0,i-16),i):
     if text[j]==0xb8 and j+5<=i: num=struct.unpack_from('<I',text,j+1)[0]
   out.append({'pc':OLD_TEXT+i,'selector':sel,'syscall':num,'name':SYSCALL_NAMES.get(num,'unknown') if num is not None else 'signal_return'})
 return out

def profile_info(data,coff,text):
 return {
  'id':'intel-icc33-native-svr3-i386','family':'native-static-svr3-i386','fingerprint_sha256':ICC_SHA256,
  'layout':{'text_start':OLD_TEXT,'text_size':TEXT_SIZE,'entry':OLD_ENTRY,'data_start':OLD_DATA,'data_size':DATA_SIZE,'bss_start':OLD_BSS,'bss_size':BSS_SIZE},
  'relocation':{'new_text_va':NEW_TEXT,'delta':DELTA,'text_switch_tables':TEXT_TABLES,'data_function_tables':DATA_TABLES,'absolute_operand_sites':TEXT_OPERANDS},
  'traps':trap_inventory(text),
 }

def native_asm_source(base, iat_abs):
    # Reuse the proven SVR3 bootstrap/gate substrate but add R3's generic
    # synchronous fork/exec/wait virtualization for native driver programs.
    saved=(base.OLD_TEXT_VA,base.OLD_DATA_VA,base.OLD_ENTRY,base.HOST_RVA,base.HOSTDATA_RVA,base.SVTEXT_RVA,base.IDATA_RVA,base.I860_RVA)
    try:
        base.OLD_TEXT_VA=OLD_TEXT; base.OLD_DATA_VA=OLD_DATA; base.OLD_ENTRY=OLD_ENTRY
        base.HOST_RVA=0x110000; base.HOSTDATA_RVA=0x114000; base.SVTEXT_RVA=0x100000; base.IDATA_RVA=0x118000; base.I860_RVA=0x119000
        s=base.asm_source(iat_abs,0)
    finally:
        (base.OLD_TEXT_VA,base.OLD_DATA_VA,base.OLD_ENTRY,base.HOST_RVA,base.HOSTDATA_RVA,base.SVTEXT_RVA,base.IDATA_RVA,base.I860_RVA)=saved
    s=s.replace('SIM860 R10','SVR3 ICC33 R3').replace('sim860-r10.exe','icc-pe.exe')

    # R4L: native SVR3 applications must see small Unix file descriptors, never
    # raw Win32 HANDLE values. Route the native syscall veneers through the
    # same fd_table helpers already proven by the i860 toolchain.
    def replace_block(src, start, end, body):
        a=src.find(start)
        if a < 0: raise RuntimeError('native fd block start changed: '+start)
        b=src.find(end,a)
        if b < 0: raise RuntimeError('native fd block end changed: '+end)
        return src[:a]+body+src[b:]

    s=replace_block(s,'sc_write:\n','sc_read:\n',r'''sc_write:
    cmp DWORD PTR [trace_level],3
    jb nfd_write_trace_done
    push DWORD PTR [esi+8]
    push DWORD PTR [esi]
    push OFFSET FLAT:trace_write_prefix
    call trace_fd_count3
    add esp,12
nfd_write_trace_done:
    push DWORD PTR [esi+8]
    push DWORD PTR [esi+4]
    push DWORD PTR [esi]
    call host_write_fd
    add esp,12
    cmp eax,0xffffffff
    je err_ebadf
    jmp sc_ok

''')
    s=replace_block(s,'sc_read:\n','sc_open:\n',r'''sc_read:
    cmp DWORD PTR [trace_level],3
    jb nfd_read_trace_done
    push DWORD PTR [esi+8]
    push DWORD PTR [esi]
    push OFFSET FLAT:trace_read_prefix
    call trace_fd_count3
    add esp,12
nfd_read_trace_done:
    push DWORD PTR [esi+8]
    push DWORD PTR [esi+4]
    push DWORD PTR [esi]
    call host_read_fd
    add esp,12
    cmp eax,0xffffffff
    je err_ebadf
    mov edi,eax
    cmp DWORD PTR [trace_level],3
    jb nfd_read_result_done
    push edi
    push OFFSET FLAT:trace_result_prefix
    call trace_result2
    add esp,8
nfd_read_result_done:
    mov eax,edi
    jmp sc_ok

''')
    s=replace_block(s,'sc_open:\n','sc_close:\n',r'''sc_open:
    cmp DWORD PTR [trace_level],2
    jb nfd_open_trace_done
    push DWORD PTR [esi]
    push OFFSET FLAT:trace_open_prefix
    call trace_path2
    add esp,8
nfd_open_trace_done:
    push DWORD PTR [esi+8]
    push DWORD PTR [esi+4]
    push DWORD PTR [esi]
    call host_open_file
    add esp,12
    cmp eax,0xffffffff
    je err_enoent
    mov edi,eax
    cmp DWORD PTR [trace_level],2
    jb nfd_open_result_done
    push edi
    push OFFSET FLAT:trace_open_result_prefix
    call trace_result2
    add esp,8
nfd_open_result_done:
    mov eax,edi
    jmp sc_ok

''')
    s=replace_block(s,'sc_close:\n','sc_access:\n',r'''sc_close:
    push DWORD PTR [esi]
    call host_close_fd
    add esp,4
    cmp eax,0xffffffff
    je err_ebadf
    xor eax,eax
    jmp sc_ok

''')
    old_cont=0x00400000+0x100000+(0x110-OLD_TEXT)+5
    new_cont=0x00400000+0x100000+(0x11d-OLD_TEXT)+5
    s=s.replace('0x%08x'%old_cont,'0x%08x'%new_cont)
    exit_old='''sc_exit_now:\n    push eax\n    call DWORD PTR ds:[IAT_ExitProcess]\n    jmp sc_unknown\n'''
    exit_new='''sc_exit_now:\n    cmp DWORD PTR [fork_active],0\n    jne child_exit_resume\n    push eax\n    call DWORD PTR ds:[IAT_ExitProcess]\n    jmp sc_unknown\n'''
    if exit_old not in s: raise RuntimeError('ICC exit hook point changed')
    s=s.replace(exit_old,exit_new,1)
    branch='''    cmp ebx,2\n    je sc_fork\n    cmp ebx,7\n    je sc_wait\n    cmp ebx,8\n    je sc_creat_native\n    cmp ebx,10\n    je sc_unlink_native\n    cmp ebx,17\n    je sc_brk_native\n    cmp ebx,18\n    je sc_stat_native\n    cmp ebx,19\n    je sc_lseek_native\n    cmp ebx,20\n    je sc_getpid_native\n    cmp ebx,54\n    je sc_ioctl_native\n    cmp ebx,80\n    je sc_mkdir_native\n'''
    needle='    cmp ebx,59\n    je sc_execve\n    jmp sc_unknown\n'
    if needle not in s: raise RuntimeError('ICC branch injection point changed')
    s=s.replace(needle,'    cmp ebx,59\n    je sc_execve_native\n'+branch+'    jmp sc_unknown\n',1)
    handlers=f'''
sc_fork:
    cmp DWORD PTR [fork_active],0
    jne fork_fail
    mov DWORD PTR [fork_saved_esp],esp
    mov eax,DWORD PTR fs:4
    mov DWORD PTR [fork_stack_base],eax
    sub eax,esp
    cmp eax,0x00100000
    ja fork_fail
    mov DWORD PTR [fork_stack_size],eax
    cmp DWORD PTR [fork_stack_snapshot],0
    jne fork_have_stack_buf
    push PAGE_READWRITE
    push MEM_COMMIT_RESERVE
    push 0x00100000
    push 0
    call DWORD PTR ds:[IAT_VirtualAlloc]
    test eax,eax
    jz fork_fail
    mov DWORD PTR [fork_stack_snapshot],eax
fork_have_stack_buf:
    cmp DWORD PTR [fork_mem_snapshot],0
    jne fork_have_mem_buf
    push PAGE_READWRITE
    push MEM_COMMIT_RESERVE
    push 0x00100000
    push 0
    call DWORD PTR ds:[IAT_VirtualAlloc]
    test eax,eax
    jz fork_fail
    mov DWORD PTR [fork_mem_snapshot],eax
fork_have_mem_buf:
    mov eax,DWORD PTR [native_brk]
    mov DWORD PTR [fork_saved_brk],eax
    sub eax,0x{OLD_DATA:08x}
    cmp eax,0x00100000
    ja fork_fail
    mov DWORD PTR [fork_mem_size],eax
    cld
    mov esi,DWORD PTR [fork_saved_esp]
    mov edi,DWORD PTR [fork_stack_snapshot]
    mov ecx,DWORD PTR [fork_stack_size]
    rep movsb
    mov esi,0x{OLD_DATA:08x}
    mov edi,DWORD PTR [fork_mem_snapshot]
    mov ecx,DWORD PTR [fork_mem_size]
    rep movsb
    mov DWORD PTR [fork_active],1
    xor eax,eax
    jmp sc_ok
fork_fail:
    mov eax,11
    jmp sc_err

sc_wait:
    cmp DWORD PTR [wait_pending],1
    jne wait_nochild
    mov edi,DWORD PTR [esi]
    test edi,edi
    jz wait_no_status
    mov eax,DWORD PTR [child_exit_status]
    and eax,0xff
    shl eax,8
    mov DWORD PTR [edi],eax
wait_no_status:
    mov DWORD PTR [wait_pending],0
    mov eax,DWORD PTR [synthetic_pid]
    jmp sc_ok
wait_nochild:
    mov eax,10
    jmp sc_err

sc_creat_native:
    cmp DWORD PTR [trace_level],2
    jb tr_creat_done
    push DWORD PTR [esi]
    push OFFSET FLAT:trace_creat_prefix
    call trace_path2
    add esp,8
tr_creat_done:
    push DWORD PTR [esi+4]
    push DWORD PTR [esi]
    call host_creat_file
    add esp,8
    cmp eax,0xffffffff
    je err_eio
    jmp sc_ok
sc_unlink_native:
    cmp DWORD PTR [trace_level],2
    jb tr_unlink_done
    push DWORD PTR [esi]
    push OFFSET FLAT:trace_unlink_prefix
    call trace_path2
    add esp,8
tr_unlink_done:
    push DWORD PTR [esi]
    call DWORD PTR ds:[IAT_DeleteFileA]
    mov edi,eax
    cmp DWORD PTR [trace_level],2
    jb tr_unlink_result_done
    push edi
    push OFFSET FLAT:trace_unlink_result_prefix
    call trace_result2
    add esp,8
tr_unlink_result_done:
    mov eax,edi
    test eax,eax
    jz err_enoent
    xor eax,eax
    jmp sc_ok
sc_brk_native:
    /* R4J: snapshot the real SysV malloc arena state at every heap-growth request. */
    cmp DWORD PTR [trace_level],3
    jb tr_brk_state_done
    push DWORD PTR ds:[0x00442b1c]
    push OFFSET FLAT:trace_allocp_prefix
    call trace_result2
    add esp,8
    push DWORD PTR ds:[0x00442b20]
    push OFFSET FLAT:trace_alloct_prefix
    call trace_result2
    add esp,8
    push DWORD PTR ds:[0x00442b24]
    push OFFSET FLAT:trace_allocx_prefix
    call trace_result2
    add esp,8
    push DWORD PTR ds:[0x00442b28]
    push OFFSET FLAT:trace_allocend_prefix
    call trace_result2
    add esp,8
    push DWORD PTR ds:[0x00442b2c]
    push OFFSET FLAT:trace_allocs_prefix
    call trace_result2
    add esp,8
    push DWORD PTR ds:[0x00442b34]
    push OFFSET FLAT:trace_sbrk_prefix
    call trace_result2
    add esp,8
tr_brk_state_done:
    mov eax,DWORD PTR [esi]
    cmp eax,0x00409960
    jb err_enomem
    cmp eax,0x004f0000
    ja err_enomem
    mov DWORD PTR [native_brk],eax
    cmp DWORD PTR [trace_level],3
    jb tr_brk_result_done
    push eax
    push OFFSET FLAT:trace_brk_result_prefix
    call trace_result2
    add esp,8
tr_brk_result_done:
    xor eax,eax
    jmp sc_ok
sc_lseek_native:
    cmp DWORD PTR [trace_level],3
    jb tr_lseek_done
    push DWORD PTR [esi+4]
    push DWORD PTR [esi]
    push OFFSET FLAT:trace_lseek_prefix
    call trace_fd_count3
    add esp,12
tr_lseek_done:
    push DWORD PTR [esi+8]
    push DWORD PTR [esi+4]
    push DWORD PTR [esi]
    call host_lseek_fd
    add esp,12
    mov edi,eax
    cmp DWORD PTR [trace_level],3
    jb tr_lseek_result_done
    push edi
    push OFFSET FLAT:trace_lseek_result_prefix
    call trace_result2
    add esp,8
tr_lseek_result_done:
    mov eax,edi
    cmp eax,0xffffffff
    je err_eio
    jmp sc_ok

sc_getpid_native:
    mov eax,1
    jmp sc_ok
sc_ioctl_native:
    mov eax,DWORD PTR [esi]
    cmp eax,2
    ja err_enotty
    xor eax,eax
    jmp sc_ok
sc_mkdir_native:
    cmp DWORD PTR [trace_level],2
    jb tr_mkdir_done
    push DWORD PTR [esi]
    push OFFSET FLAT:trace_mkdir_prefix
    call trace_path2
    add esp,8
tr_mkdir_done:
    push 0
    push DWORD PTR [esi]
    call DWORD PTR ds:[IAT_CreateDirectoryA]
    test eax,eax
    jnz nmkdir_ok
    push DWORD PTR [esi]
    call DWORD PTR ds:[IAT_GetFileAttributesA]
    cmp eax,INVALID_HANDLE_VALUE
    je err_eio
nmkdir_ok:
    xor eax,eax
    jmp sc_ok
sc_stat_native:
    cmp DWORD PTR [trace_level],2
    jb tr_stat_done
    push DWORD PTR [esi]
    push OFFSET FLAT:trace_stat_prefix
    call trace_path2
    add esp,8
tr_stat_done:
    push DWORD PTR [esi]
    call DWORD PTR ds:[IAT_GetFileAttributesA]
    cmp eax,INVALID_HANDLE_VALUE
    je err_enoent
    mov edi,DWORD PTR [esi+4]
    push ecx
    xor eax,eax
    mov ecx,8
    rep stosd
    pop ecx
    mov edi,DWORD PTR [esi+4]
    mov WORD PTR [edi+4],0x81a4
    xor eax,eax
    jmp sc_ok

sc_execve_native:
    push DWORD PTR [esi+8]
    push DWORD PTR [esi+4]
    push DWORD PTR [esi]
    call spawn_execve_sync
    add esp,12
    cmp eax,0xffffffff
    je exec_spawn_fail
    cmp DWORD PTR [fork_active],0
    jne resume_parent_from_child
    push eax
    call DWORD PTR ds:[IAT_ExitProcess]
exec_spawn_fail:
    cmp DWORD PTR [fork_active],0
    je err_enoent
    mov eax,127
    jmp resume_parent_from_child

resume_parent_from_child:
    and eax,0xff
    mov DWORD PTR [child_exit_status],eax
    mov DWORD PTR [wait_pending],1
    mov DWORD PTR [fork_active],0
    mov eax,DWORD PTR [fork_saved_brk]
    mov DWORD PTR [native_brk],eax
    cld
    mov esi,DWORD PTR [fork_mem_snapshot]
    mov edi,0x{OLD_DATA:08x}
    mov ecx,DWORD PTR [fork_mem_size]
    rep movsb
    mov esi,DWORD PTR [fork_stack_snapshot]
    mov edi,DWORD PTR [fork_saved_esp]
    mov ecx,DWORD PTR [fork_stack_size]
    rep movsb
    mov esp,DWORD PTR [fork_saved_esp]
    mov eax,DWORD PTR [synthetic_pid]
    jmp sc_ok

spawn_execve_sync:
    push ebp
    mov ebp,esp
    push ebx
    push esi
    push edi
    push OFFSET FLAT:exec_request_prefix
    call host_puts_err
    add esp,4
    push DWORD PTR [ebp+8]
    call host_puts_err
    add esp,4
    push OFFSET FLAT:crlf
    call host_puts_err
    add esp,4
    mov esi,DWORD PTR [ebp+8]
    mov ebx,esi
spawn_find_base:
    mov al,BYTE PTR [esi]
    test al,al
    jz spawn_have_base
    cmp al,'/'
    je spawn_mark_base
    cmp al,92
    jne spawn_find_next
spawn_mark_base:
    lea ebx,[esi+1]
spawn_find_next:
    inc esi
    jmp spawn_find_base
spawn_have_base:
    mov esi,ebx
    mov edi,OFFSET FLAT:child_path_buf
spawn_copy_base:
    mov al,BYTE PTR [esi]
    test al,al
    jz spawn_add_pe
    cmp edi,OFFSET FLAT:child_path_buf+240
    jae spawn_fail
    mov BYTE PTR [edi],al
    inc esi
    inc edi
    jmp spawn_copy_base
spawn_add_pe:
    mov DWORD PTR [edi],0x2e65702d
    mov DWORD PTR [edi+4],0x00657865
    push OFFSET FLAT:child_path_buf
    call DWORD PTR ds:[IAT_GetFileAttributesA]
    cmp eax,INVALID_HANDLE_VALUE
    jne spawn_path_ok
    mov esi,ebx
    mov edi,OFFSET FLAT:child_path_buf
spawn_copy_base2:
    mov al,BYTE PTR [esi]
    test al,al
    jz spawn_add_exe
    cmp edi,OFFSET FLAT:child_path_buf+244
    jae spawn_fail
    mov BYTE PTR [edi],al
    inc esi
    inc edi
    jmp spawn_copy_base2
spawn_add_exe:
    mov DWORD PTR [edi],0x6578652e
    mov BYTE PTR [edi+4],0
    push OFFSET FLAT:child_path_buf
    call DWORD PTR ds:[IAT_GetFileAttributesA]
    cmp eax,INVALID_HANDLE_VALUE
    je spawn_fail
spawn_path_ok:
    push OFFSET FLAT:spawn_prefix
    call host_puts_err
    add esp,4
    push OFFSET FLAT:child_path_buf
    call host_puts_err
    add esp,4
    push OFFSET FLAT:crlf
    call host_puts_err
    add esp,4
    mov edi,OFFSET FLAT:child_cmd_buf
    mov BYTE PTR [edi],34
    inc edi
    mov esi,OFFSET FLAT:child_path_buf
spawn_cmd_path:
    mov al,BYTE PTR [esi]
    test al,al
    jz spawn_cmd_path_done
    cmp edi,OFFSET FLAT:child_cmd_buf+8180
    jae spawn_fail
    mov BYTE PTR [edi],al
    inc esi
    inc edi
    jmp spawn_cmd_path
spawn_cmd_path_done:
    mov BYTE PTR [edi],34
    inc edi
    mov ebx,DWORD PTR [ebp+12]
    add ebx,4
spawn_arg_next:
    mov esi,DWORD PTR [ebx]
    test esi,esi
    jz spawn_cmd_done
    cmp edi,OFFSET FLAT:child_cmd_buf+8176
    jae spawn_fail
    mov BYTE PTR [edi],' '
    mov BYTE PTR [edi+1],34
    add edi,2
spawn_arg_copy:
    mov al,BYTE PTR [esi]
    test al,al
    jz spawn_arg_done
    cmp al,34
    je spawn_fail
    cmp edi,OFFSET FLAT:child_cmd_buf+8176
    jae spawn_fail
    mov BYTE PTR [edi],al
    inc esi
    inc edi
    jmp spawn_arg_copy
spawn_arg_done:
    mov BYTE PTR [edi],34
    inc edi
    add ebx,4
    jmp spawn_arg_next
spawn_cmd_done:
    mov BYTE PTR [edi],0
    mov edi,OFFSET FLAT:child_startup_info
    xor eax,eax
    mov ecx,21
    rep stosd
    mov DWORD PTR [child_startup_info],68
    push OFFSET FLAT:child_process_info
    push OFFSET FLAT:child_startup_info
    push 0
    push 0
    push 0
    push 1
    push 0
    push 0
    push OFFSET FLAT:child_cmd_buf
    push 0
    call DWORD PTR ds:[IAT_CreateProcessA]
    test eax,eax
    jz spawn_fail
    push 0xffffffff
    push DWORD PTR [child_process_info]
    call DWORD PTR ds:[IAT_WaitForSingleObject]
    push OFFSET FLAT:child_exit_tmp
    push DWORD PTR [child_process_info]
    call DWORD PTR ds:[IAT_GetExitCodeProcess]
    test eax,eax
    jz spawn_close_fail
    mov ebx,DWORD PTR [child_exit_tmp]
    push DWORD PTR [child_process_info+4]
    call DWORD PTR ds:[IAT_CloseHandle]
    push DWORD PTR [child_process_info]
    call DWORD PTR ds:[IAT_CloseHandle]
    mov eax,ebx
    jmp spawn_done
spawn_close_fail:
    push DWORD PTR [child_process_info+4]
    call DWORD PTR ds:[IAT_CloseHandle]
    push DWORD PTR [child_process_info]
    call DWORD PTR ds:[IAT_CloseHandle]
spawn_fail:
    mov eax,0xffffffff
spawn_done:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

child_exit_resume:
    jmp resume_parent_from_child

err_enomem:
    mov eax,12
    jmp sc_err
err_enotty:
    mov eax,25
    jmp sc_err
'''
    s=s.replace('sc_unknown:\n',handlers+'\nsc_unknown:\n',1)
    s += '''\n.section .data
.balign 4
native_brk: .long 0x00409960
fork_active: .long 0
wait_pending: .long 0
synthetic_pid: .long 2
child_exit_status: .long 0
child_exit_tmp: .long 0
fork_saved_esp: .long 0
fork_stack_base: .long 0
fork_stack_size: .long 0
fork_stack_snapshot: .long 0
fork_saved_brk: .long 0
fork_mem_size: .long 0
fork_mem_snapshot: .long 0
trace_creat_prefix: .asciz "[svr3 trace] creat: "
trace_unlink_prefix: .asciz "[svr3 trace] unlink: "
trace_lseek_prefix: .asciz "[svr3 trace] lseek fd=0x"
trace_mkdir_prefix: .asciz "[svr3 trace] mkdir: "
trace_stat_prefix: .asciz "[svr3 trace] stat: "
trace_unlink_result_prefix: .asciz "[svr3 trace] unlink result=0x"
trace_lseek_result_prefix: .asciz "[svr3 trace] lseek result=0x"
trace_brk_result_prefix: .asciz "[svr3 trace] brk new=0x"
exec_request_prefix: .asciz "SVR3COFF2PE R4E: guest execve request: "
spawn_prefix: .asciz "SVR3COFF2PE R4E: launching child PE: "
child_path_buf: .space 260
child_cmd_buf: .space 8192
.balign 4
child_startup_info: .space 68
child_process_info: .space 16
'''
    return s

def stub_cpu_source():
    return 'int i860_run(void) { return 1; }\n'
