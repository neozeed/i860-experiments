#!/usr/bin/env python3
import argparse, hashlib, json, os, struct, subprocess, textwrap
from pathlib import Path

I386MAGIC=0x014c; I860MAGIC=0x014d
FILE_ALIGN=0x200; SECT_ALIGN=0x1000
IMAGE_BASE=0x00400000
HOST_RVA=0x1000
HOSTDATA_RVA=0x5000
SVTEXT_RVA=0x7000
IDATA_RVA=0x8000
I860_RVA=0x00009000
OLD_TEXT_VA=0x000000d0
OLD_DATA_VA=0x00400958
OLD_ENTRY=0x000000d4
FUNCS=['GetStdHandle','WriteFile','ExitProcess','GetCommandLineA','GetFileAttributesA','CreateFileA','ReadFile','CloseHandle','DeleteFileA','GetFileSize','SetFilePointer','VirtualProtect','VirtualAlloc','GetEnvironmentStringsA','GetEnvironmentVariableA']

def align(v,a): return (v+a-1)&~(a-1)
def sha256(b): return hashlib.sha256(b).hexdigest()

def parse_coff(data,base=0):
    magic,nscns,stamp,symptr,nsyms,opthdr,flags=struct.unpack_from('<HHLLLHH',data,base)
    shoff=base+20+opthdr
    secs=[]
    for i in range(nscns):
        off=shoff+i*40
        raw=struct.unpack_from('<8sLLLLLLHHL',data,off)
        name=raw[0].split(b'\0',1)[0].decode('ascii','replace')
        secs.append({'name':name,'paddr':raw[1],'vaddr':raw[2],'size':raw[3],'scnptr':raw[4],'relptr':raw[5],'lnnoptr':raw[6],'nreloc':raw[7],'nlnno':raw[8],'flags':raw[9]})
    opt=data[base+20:base+20+opthdr]
    common=None
    if opthdr>=28:
        a=struct.unpack_from('<HHLLLLLL',opt,0)
        common={'magic':a[0],'vstamp':a[1],'tsize':a[2],'dsize':a[3],'bsize':a[4],'entry':a[5],'text_start':a[6],'data_start':a[7]}
    return {'base':base,'magic':magic,'nscns':nscns,'timestamp':stamp,'symptr':symptr,'nsyms':nsyms,'opthdr_size':opthdr,'flags':flags,'optional_common':common,'sections':secs}

def coff_extent(coff):
    base=coff['base']; end=base+20+coff['opthdr_size']+coff['nscns']*40
    for s in coff['sections']:
        if s['size'] and s['scnptr']: end=max(end,base+s['scnptr']+s['size'])
        if s['nreloc'] and s['relptr']: end=max(end,base+s['relptr']+s['nreloc']*10)
        if s['nlnno'] and s['lnnoptr']: end=max(end,base+s['lnnoptr']+s['nlnno']*6)
    return end

def secbytes(data,coff,name):
    s=next(x for x in coff['sections'] if x['name']==name)
    if not s['size'] or not s['scnptr']: return b''
    return data[coff['base']+s['scnptr']:coff['base']+s['scnptr']+s['size']]

def make_idata(rva, funcs):
    desc_off=0; null_desc_off=20; ilt_off=40; iat_off=ilt_off+4*(len(funcs)+1); cur=iat_off+4*(len(funcs)+1)
    buf=bytearray(cur); name_rvas=[]
    for fn in funcs:
        if cur&1: buf+=b'\0'; cur+=1
        name_rvas.append(rva+cur)
        item=struct.pack('<H',0)+fn.encode()+b'\0'; buf+=item; cur+=len(item)
    dll_off=cur; buf+=b'KERNEL32.dll\0'
    for i,nrva in enumerate(name_rvas):
        struct.pack_into('<L',buf,ilt_off+i*4,nrva); struct.pack_into('<L',buf,iat_off+i*4,nrva)
    struct.pack_into('<LLLLL',buf,desc_off,rva+ilt_off,0,0,rva+dll_off,rva+iat_off)
    return bytes(buf), {'import_directory_rva':rva,'import_directory_size':40,'iat_rva':rva+iat_off,'iat_size':4*(len(funcs)+1),'iat_entries':{fn:rva+iat_off+i*4 for i,fn in enumerate(funcs)}}

def patch_text(text, host_gate_va, host_gate15_va):
    b=bytearray(text); patches=[]
    delta=(IMAGE_BASE+SVTEXT_RVA)-OLD_TEXT_VA
    # absolute code pointers proven from disassembly
    for pat,oldtarget in [(bytes.fromhex('68 e0 05 00 00'),0x5e0),(bytes.fromhex('ba 40 09 00 00'),0x940)]:
        start=0; count=0
        while True:
            i=b.find(pat,start)
            if i<0: break
            newtarget=oldtarget+delta
            b[i+1:i+5]=struct.pack('<I',newtarget)
            patches.append({'kind':'abs_code_ptr','text_offset':i+1,'old_va':OLD_TEXT_VA+i+1,'old_target':oldtarget,'new_target':newtarget})
            count+=1; start=i+5
        if count==0: raise ValueError('required absolute code pointer pattern missing: '+pat.hex())
    # lcall gates -> near CALL + 2 NOPs
    for sel,target in [(7,host_gate_va),(15,host_gate15_va)]:
        pat=b'\x9a\x00\x00\x00\x00'+struct.pack('<H',sel)
        start=0; count=0
        while True:
            i=b.find(pat,start)
            if i<0: break
            call_va=IMAGE_BASE+SVTEXT_RVA+i
            rel=(target-(call_va+5)) & 0xffffffff
            b[i:i+7]=b'\xE8'+struct.pack('<I',rel)+b'\x90\x90'
            patches.append({'kind':'syscall_gate','selector':sel,'text_offset':i,'old_va':OLD_TEXT_VA+i,'new_va':call_va,'target_va':target})
            count+=1; start=i+7
        if sel==7 and count!=11: raise ValueError('expected 11 selector-7 gates, got %d'%count)
        if sel==15 and count!=1: raise ValueError('expected 1 selector-15 gate, got %d'%count)
    return bytes(b), patches, delta

def asm_source(iat_abs, payload_size):
    defs='\n'.join('.equ IAT_%s, 0x%08x' % (k,v) for k,v in iat_abs.items())
    sv_entry=IMAGE_BASE+SVTEXT_RVA+(OLD_ENTRY-OLD_TEXT_VA)
    direct_exit_cont=IMAGE_BASE+SVTEXT_RVA+(0x110-OLD_TEXT_VA)+5
    return f'''/* SIM860 R10 host personality. 32-bit x86, Intel syntax. */
.intel_syntax noprefix
.code32
{defs}
.equ SV_ENTRY, 0x{sv_entry:08x}
.equ STD_INPUT_HANDLE,  -10
.equ STD_OUTPUT_HANDLE, -11
.equ STD_ERROR_HANDLE,  -12
.equ INVALID_HANDLE_VALUE, -1
.equ I860_PAYLOAD, 0x{IMAGE_BASE+I860_RVA:08x}
.equ I860_PAYLOAD_SIZE, 0x{payload_size:08x}
.equ MEM_COMMIT_RESERVE, 0x3000
.equ PAGE_READWRITE, 0x04
.equ GENERIC_READ,  0x80000000
.equ GENERIC_WRITE, 0x40000000
.equ FILE_SHARE_RW, 7 /* read|write|delete: preserve Unix unlink-while-open semantics */
.equ CREATE_NEW, 1
.equ CREATE_ALWAYS, 2
.equ OPEN_EXISTING, 3
.equ OPEN_ALWAYS, 4
.equ TRUNCATE_EXISTING, 5
.equ FILE_BEGIN, 0
.equ FILE_CURRENT, 1
.equ FILE_END, 2
.equ FILE_ATTRIBUTE_NORMAL, 0x80

.section .text
.global host_entry
.global svr3_gate7
.global svr3_gate15
.global host_puts_out
.global host_puts_err
.global host_puthex32
.global host_write_fd
.global host_read_fd
.global host_open_file
.global host_creat_file
.global host_close_fd
.global host_lseek_fd
.global host_unlink_file
.global host_filesize_fd
.global i860_text_size
.global i860_data_size
.global i860_bss_size
.global i860_entry
.global i860_text_guest
.global i860_data_guest
.global i860_low_size
.global i860_text_host
.global i860_data_host
.global i860_stack_guest
.global i860_stack_size
.global i860_stack_host
.global i860_run860_argv
host_entry:
    cld
    /* R8 retains the R2A mapping: historical SVR3 .data lives in the mapped PE header page at
       0x00400958. Windows maps image headers read-only, so make that page
       writable before entering the historical program. */
    push OFFSET FLAT:old_protect
    push 0x04
    push 0x1000
    push 0x00400000
    call DWORD PTR ds:[IAT_VirtualProtect]
    test eax,eax
    jnz protect_ok
    push 0xed
    call DWORD PTR ds:[IAT_ExitProcess]
protect_ok:
    push STD_OUTPUT_HANDLE
    call DWORD PTR ds:[IAT_GetStdHandle]
    mov DWORD PTR [hstdout], eax
    push STD_ERROR_HANDLE
    call DWORD PTR ds:[IAT_GetStdHandle]
    mov DWORD PTR [hstderr], eax
    push STD_INPUT_HANDLE
    call DWORD PTR ds:[IAT_GetStdHandle]
    mov DWORD PTR [hstdin], eax

    /* R4E: inherit host environment and configure trace level. */
    push 16
    push OFFSET FLAT:trace_buf
    push OFFSET FLAT:trace_env_name
    call DWORD PTR ds:[IAT_GetEnvironmentVariableA]
    test eax,eax
    jz trace_env_done
    movzx eax,BYTE PTR [trace_buf]
    sub eax,'0'
    cmp eax,0
    jl trace_env_done
    cmp eax,3
    jle trace_store
    mov eax,3
trace_store:
    mov DWORD PTR [trace_level],eax
trace_env_done:
    call DWORD PTR ds:[IAT_GetEnvironmentStringsA]
    mov DWORD PTR [host_env_block],eax

    push OFFSET FLAT:banner
    call host_puts_out
    add esp,4

    call DWORD PTR ds:[IAT_GetCommandLineA]
    test eax,eax
    jz host_bad_cmd
    mov esi,eax
    mov edi, OFFSET FLAT:cmd_buf
    mov ebx, OFFSET FLAT:argv_vec
    xor ecx,ecx

parse_next:
    cmp ecx,63
    jae parse_done
skip_ws:
    mov al, BYTE PTR [esi]
    cmp al,' '
    je skip_one
    cmp al,9
    je skip_one
    test al,al
    jz parse_done
    jmp start_arg
skip_one:
    inc esi
    jmp skip_ws

start_arg:
    mov DWORD PTR [ebx+ecx*4],edi
    inc ecx
    xor edx,edx
arg_loop:
    mov al,BYTE PTR [esi]
    inc esi
    test al,al
    jz arg_eol
    cmp al,'"'
    jne not_quote
    xor dl,1
    jmp arg_loop
not_quote:
    test dl,dl
    jnz copy_char
    cmp al,' '
    je arg_end
    cmp al,9
    je arg_end
copy_char:
    cmp edi, OFFSET FLAT:cmd_buf_end-2
    jae host_bad_cmd
    mov BYTE PTR [edi],al
    inc edi
    jmp arg_loop
arg_end:
    mov BYTE PTR [edi],0
    inc edi
    jmp parse_next
arg_eol:
    mov BYTE PTR [edi],0
    inc edi
parse_done:
    test ecx,ecx
    jnz have_args
    mov DWORD PTR [ebx], OFFSET FLAT:fallback_argv0
    mov ecx,1
have_args:
    mov DWORD PTR [ebx+ecx*4],0
    mov DWORD PTR [argc_store],ecx

    /* Build authentic SVR3 startup stack using host environment strings. */
    mov esi,DWORD PTR [host_env_block]
    mov edi, OFFSET FLAT:env_vec
    xor ecx,ecx
    test esi,esi
    jz env_fallback
env_scan_next:
    cmp ecx,255
    jae env_scan_done
    cmp BYTE PTR [esi],0
    je env_scan_done
    mov DWORD PTR [edi+ecx*4],esi
    inc ecx
env_skip:
    cmp BYTE PTR [esi],0
    je env_after
    inc esi
    jmp env_skip
env_after:
    inc esi
    jmp env_scan_next
env_fallback:
    mov DWORD PTR [edi], OFFSET FLAT:path_env
    mov ecx,1
env_scan_done:
    mov DWORD PTR [env_count],ecx
    push 0
    dec ecx
env_push_rev:
    cmp ecx,-1
    je env_pushed
    push DWORD PTR [env_vec+ecx*4]
    dec ecx
    jmp env_push_rev
env_pushed:
    push 0
    mov ecx,DWORD PTR [argc_store]
    dec ecx
push_argv_rev:
    cmp ecx,-1
    je argv_pushed
    push DWORD PTR [argv_vec+ecx*4]
    dec ecx
    jmp push_argv_rev
argv_pushed:
    push DWORD PTR [argc_store]
    jmp SV_ENTRY

host_bad_cmd:
    push OFFSET FLAT:bad_cmd
    call host_puts_err
    add esp,4
    push 0xee
    call DWORD PTR ds:[IAT_ExitProcess]

/* Patched replacement for SVR3 lcall 7:0.
   At entry [esp] is the replacement CALL return; [esp+4] is the libc wrapper's
   own return address, so syscall arg1 starts at [esp+8]. */
svr3_gate7:
    push ebp
    push ebx
    push esi
    push edi
    mov ebx,eax
    lea esi,[esp+24]

    cmp ebx,1
    je sc_exit
    cmp ebx,3
    je sc_read
    cmp ebx,4
    je sc_write
    cmp ebx,5
    je sc_open
    cmp ebx,6
    je sc_close
    cmp ebx,27
    je sc_alarm
    cmp ebx,29
    je sc_pause
    cmp ebx,33
    je sc_access
    cmp ebx,48
    je sc_signal
    cmp ebx,59
    je sc_execve
    jmp sc_unknown

sc_exit:
    /* crt's direct final exit has no libc-wrapper return frame and always passes 0.
       The normal _exit wrapper calls here with arg1 at [esi]. */
    mov eax,DWORD PTR [esp+16]
    /* [esp+16] is replacement-call return before saved regs; compare against
       replacement CALL return 0x{direct_exit_cont:08x} (old gate at 0x110 + 5-byte CALL). */
    cmp eax,0x{direct_exit_cont:08x}
    je sc_exit_zero
    mov eax,DWORD PTR [esi]
    jmp sc_exit_now
sc_exit_zero:
    xor eax,eax
sc_exit_now:
    push eax
    call DWORD PTR ds:[IAT_ExitProcess]
    jmp sc_unknown

sc_write:
    cmp DWORD PTR [trace_level],3
    jb tr_write_done
    push DWORD PTR [esi+8]
    push DWORD PTR [esi]
    push OFFSET FLAT:trace_write_prefix
    call trace_fd_count3
    add esp,12
tr_write_done:
    /* R4H: on the first stderr write at trace level 3, dump the exact IC
       optimizer/allocator state that feeds fatal error #7.  These historical
       addresses are specific to the exact IC native profile but harmless for
       other family members because this block is gated by ic_diag_enabled. */
    cmp DWORD PTR [trace_level],3
    jb tr_icdiag_done
    cmp DWORD PTR [ic_diag_enabled],0
    je tr_icdiag_done
    cmp DWORD PTR [ic_diag_once],0
    jne tr_icdiag_done
    cmp DWORD PTR [esi],2
    jne tr_icdiag_done
    mov DWORD PTR [ic_diag_once],1
    push DWORD PTR ds:[0x00442f54]
    push OFFSET FLAT:trace_bih_ptr_prefix
    call trace_result2
    add esp,8
    push DWORD PTR ds:[0x00442f58]
    push OFFSET FLAT:trace_bih_count_prefix
    call trace_result2
    add esp,8
    push DWORD PTR ds:[0x00442f5c]
    push OFFSET FLAT:trace_bih_cur_prefix
    call trace_result2
    add esp,8
    push DWORD PTR ds:[0x00442b1c]
    push OFFSET FLAT:trace_allocp_prefix
    call trace_result2
    add esp,8
    push DWORD PTR ds:[0x00442b20]
    push OFFSET FLAT:trace_alloct_prefix
    call trace_result2
    add esp,8
    push DWORD PTR ds:[0x00442b28]
    push OFFSET FLAT:trace_allocend_prefix
    call trace_result2
    add esp,8
    push DWORD PTR ds:[0x00442b34]
    push OFFSET FLAT:trace_sbrk_prefix
    call trace_result2
    add esp,8
    push DWORD PTR [native_brk]
    push OFFSET FLAT:trace_nativebrk_prefix
    call trace_result2
    add esp,8
tr_icdiag_done:
    mov eax,DWORD PTR [esi]
    cmp eax,1
    je wr_stdout
    cmp eax,2
    je wr_stderr
    mov edi,eax
    jmp wr_have
wr_stdout:
    mov edi,DWORD PTR [hstdout]
    jmp wr_have
wr_stderr:
    mov edi,DWORD PTR [hstderr]
wr_have:
    push 0
    push OFFSET FLAT:io_count
    push DWORD PTR [esi+8]
    push DWORD PTR [esi+4]
    push edi
    call DWORD PTR ds:[IAT_WriteFile]
    test eax,eax
    jz err_eio
    mov eax,DWORD PTR [io_count]
    jmp sc_ok

sc_read:
    cmp DWORD PTR [trace_level],3
    jb tr_read_done
    push DWORD PTR [esi+8]
    push DWORD PTR [esi]
    push OFFSET FLAT:trace_read_prefix
    call trace_fd_count3
    add esp,12
tr_read_done:
    mov eax,DWORD PTR [esi]
    cmp eax,0
    jne rd_have_raw
    mov edi,DWORD PTR [hstdin]
    jmp rd_have
rd_have_raw:
    mov edi,eax
rd_have:
    push 0
    push OFFSET FLAT:io_count
    push DWORD PTR [esi+8]
    push DWORD PTR [esi+4]
    push edi
    call DWORD PTR ds:[IAT_ReadFile]
    test eax,eax
    jz err_eio
    mov eax,DWORD PTR [io_count]
    cmp DWORD PTR [trace_level],3
    jb tr_read_result_done
    push eax
    push eax
    push OFFSET FLAT:trace_result_prefix
    call trace_result2
    add esp,8
    pop eax
tr_read_result_done:
    jmp sc_ok

sc_open:
    cmp DWORD PTR [trace_level],2
    jb tr_open_done
    push DWORD PTR [esi]
    push OFFSET FLAT:trace_open_prefix
    call trace_path2
    add esp,8
tr_open_done:
    /* SVR3 open(path, flags, mode): access low 2 bits; O_APPEND=0010,
       O_CREAT=0400, O_TRUNC=01000, O_EXCL=02000 (octal).  The Unix
       permission-mode argument is intentionally ignored on Win32. */
    mov ebx,DWORD PTR [esi+4]       /* flags */
    mov eax,ebx
    and eax,3
    cmp eax,0
    je op_read
    cmp eax,1
    je op_write
    mov edi,GENERIC_READ|GENERIC_WRITE
    jmp op_disp
op_read:
    mov edi,GENERIC_READ
    jmp op_disp
op_write:
    mov edi,GENERIC_WRITE
op_disp:
    mov edx,OPEN_EXISTING
    test ebx,0x100                  /* O_CREAT 0400 */
    jz op_nocreat
    test ebx,0x400                  /* O_EXCL 02000 */
    jnz op_create_new
    test ebx,0x200                  /* O_TRUNC 01000 */
    jnz op_create_always
    mov edx,OPEN_ALWAYS
    jmp op_go
op_create_new:
    mov edx,CREATE_NEW
    jmp op_go
op_create_always:
    mov edx,CREATE_ALWAYS
    jmp op_go
op_nocreat:
    test ebx,0x200                  /* O_TRUNC without O_CREAT */
    jz op_go
    mov edx,TRUNCATE_EXISTING
op_go:
    push 0
    push FILE_ATTRIBUTE_NORMAL
    push edx
    push 0
    push FILE_SHARE_RW
    push edi
    push DWORD PTR [esi]
    call DWORD PTR ds:[IAT_CreateFileA]
    cmp eax,INVALID_HANDLE_VALUE
    je err_enoent
    mov edi,eax                     /* preserve HANDLE across optional seek */
    test ebx,8                      /* O_APPEND 0010 */
    jz op_open_return
    push FILE_END
    push 0
    push 0
    push edi
    call DWORD PTR ds:[IAT_SetFilePointer]
op_open_return:
    mov eax,edi
    cmp DWORD PTR [trace_level],2
    jb tr_open_result_done
    push eax
    push eax
    push OFFSET FLAT:trace_open_result_prefix
    call trace_result2
    add esp,8
    pop eax
tr_open_result_done:
    jmp sc_ok

sc_close:
    mov eax,DWORD PTR [esi]
    cmp eax,2
    jbe close_ok
    push eax
    call DWORD PTR ds:[IAT_CloseHandle]
    test eax,eax
    jz err_ebadf
close_ok:
    xor eax,eax
    jmp sc_ok

sc_access:
    cmp DWORD PTR [trace_level],2
    jb tr_access_done
    push DWORD PTR [esi]
    push OFFSET FLAT:trace_access_prefix
    call trace_path2
    add esp,8
tr_access_done:
    /* Intel fat-binary wrapper probes run860 through access() before execve().
       R8 supplies an in-process run860 execution vehicle, so advertise that
       synthetic target as present. */
    push DWORD PTR [esi]
    call is_run860
    add esp,4
    test eax,eax
    jnz access_ok
    push DWORD PTR [esi]
    call DWORD PTR ds:[IAT_GetFileAttributesA]
    cmp eax,INVALID_HANDLE_VALUE
    je err_enoent
access_ok:
    xor eax,eax
    jmp sc_ok

sc_alarm:
    xor eax,eax
    jmp sc_ok

sc_pause:
    /* No asynchronous signal delivery in R2. Fail explicitly as EINTR. */
    mov eax,4
    jmp sc_err

sc_signal:
    /* R2 records disposition only by accepting it; no async delivery. */
    xor eax,eax
    jmp sc_ok

sc_execve:
    push DWORD PTR [esi]
    call is_run860
    add esp,4
    test eax,eax
    jz exec_real_target

    push OFFSET FLAT:run860_banner
    call host_puts_out
    add esp,4
    /* execve(path, argv, envp): argv is argument two at [esi+4].
       Successful execve never returns; the R8 shim similarly terminates the
       vessel after validating/materializing the i860 image. */
    push DWORD PTR [esi+4]
    call run860_shim
    add esp,4
    /* Any return is a loader failure. EAX already holds an SVR3 errno. */
    jmp sc_err

exec_real_target:
    push DWORD PTR [esi]
    call DWORD PTR ds:[IAT_GetFileAttributesA]
    cmp eax,INVALID_HANDLE_VALUE
    je err_enoent
    push OFFSET FLAT:exec_prefix
    call host_puts_err
    add esp,4
    push DWORD PTR [esi]
    call host_puts_err
    add esp,4
    push OFFSET FLAT:crlf
    call host_puts_err
    add esp,4
    push OFFSET FLAT:exec_suffix
    call host_puts_err
    add esp,4
    mov eax,2
    jmp sc_err

sc_unknown:
    push OFFSET FLAT:unknown_msg
    call host_puts_err
    add esp,4
    push 0xef
    call DWORD PTR ds:[IAT_ExitProcess]

err_enoent:
    mov eax,2
    jmp sc_err
err_eio:
    mov eax,5
    jmp sc_err
err_ebadf:
    mov eax,9
    jmp sc_err
sc_ok:
    pop edi
    pop esi
    pop ebx
    pop ebp
    clc
    ret
sc_err:
    pop edi
    pop esi
    pop ebx
    pop ebp
    stc
    ret

svr3_gate15:
    push OFFSET FLAT:gate15_msg
    call host_puts_err
    add esp,4
    push 0xf0
    call DWORD PTR ds:[IAT_ExitProcess]

/* R4E tracing helpers. */
trace_path2:
    push ebp
    mov ebp,esp
    push DWORD PTR [ebp+8]
    call host_puts_err
    add esp,4
    push DWORD PTR [ebp+12]
    call host_puts_err
    add esp,4
    push OFFSET FLAT:crlf
    call host_puts_err
    add esp,4
    pop ebp
    ret
trace_result2:
    push ebp
    mov ebp,esp
    push DWORD PTR [ebp+8]
    call host_puts_err
    add esp,4
    push DWORD PTR [ebp+12]
    call trace_hex_err
    add esp,4
    push OFFSET FLAT:crlf
    call host_puts_err
    add esp,4
    pop ebp
    ret
trace_hex_err:
    push ebp
    mov ebp,esp
    push ebx
    push edi
    mov eax,DWORD PTR [ebp+8]
    mov edi,OFFSET FLAT:trace_hex_buf+8
    mov BYTE PTR [edi],0
    mov ecx,8
thx_loop:
    dec edi
    mov edx,eax
    and edx,0x0f
    mov bl,BYTE PTR [hex_digits+edx]
    mov BYTE PTR [edi],bl
    shr eax,4
    dec ecx
    jnz thx_loop
    push OFFSET FLAT:trace_hex_buf
    call host_puts_err
    add esp,4
    pop edi
    pop ebx
    pop ebp
    ret
trace_fd_count3:
    push ebp
    mov ebp,esp
    push DWORD PTR [ebp+8]
    call host_puts_err
    add esp,4
    push DWORD PTR [ebp+12]
    call trace_hex_err
    add esp,4
    push OFFSET FLAT:trace_count_mid
    call host_puts_err
    add esp,4
    push DWORD PTR [ebp+16]
    call trace_hex_err
    add esp,4
    push OFFSET FLAT:crlf
    call host_puts_err
    add esp,4
    pop ebp
    ret

/* Return EAX=1 if path basename is exactly "run860", else 0. */
is_run860:
    push ebp
    mov ebp,esp
    push esi
    push edi
    mov esi,DWORD PTR [ebp+8]
    mov edi,esi
iru_scan:
    mov al,BYTE PTR [esi]
    test al,al
    jz iru_cmp
    cmp al,'/'
    je iru_sep
    cmp al,92
    jne iru_next
iru_sep:
    lea edi,[esi+1]
iru_next:
    inc esi
    jmp iru_scan
iru_cmp:
    cmp BYTE PTR [edi+0],'r'
    jne iru_no
    cmp BYTE PTR [edi+1],'u'
    jne iru_no
    cmp BYTE PTR [edi+2],'n'
    jne iru_no
    cmp BYTE PTR [edi+3],'8'
    jne iru_no
    cmp BYTE PTR [edi+4],'6'
    jne iru_no
    cmp BYTE PTR [edi+5],'0'
    jne iru_no
    cmp BYTE PTR [edi+6],0
    jne iru_no
    mov eax,1
    jmp iru_done
iru_no:
    xor eax,eax
iru_done:
    pop edi
    pop esi
    pop ebp
    ret

/* R8 execution vehicle. Argument is the argv vector supplied by the untouched
   SVR3 wrapper to execve("run860", argv, envp). It parses the embedded i860
   COFF, materializes text and data+bss into host backing buffers, translates
   the guest entry point to its host backing address, and stops before i860
   instruction execution. */
run860_shim:
    push ebp
    mov ebp,esp
    push ebx
    push esi
    push edi
    mov ebx,DWORD PTR [ebp+8]       /* argv */
    test ebx,ebx
    jz r860_bad_argv
    mov DWORD PTR [i860_run860_argv],ebx
    mov eax,DWORD PTR [ebx+4]       /* argv[1] target fat binary */
    test eax,eax
    jz r860_bad_argv
    push OFFSET FLAT:target_prefix
    call host_puts_out
    add esp,4
    push DWORD PTR [ebx+4]
    call host_puts_out
    add esp,4
    push OFFSET FLAT:crlf
    call host_puts_out
    add esp,4

    mov esi,I860_PAYLOAD
    cmp WORD PTR [esi+0],0x014d
    jne r860_bad_coff
    cmp WORD PTR [esi+2],3
    jne r860_bad_coff
    cmp WORD PTR [esi+16],36
    jne r860_bad_coff
    cmp WORD PTR [esi+20],0x010b
    jne r860_bad_coff

    /* Common optional-header fields. */
    mov eax,DWORD PTR [esi+24]
    mov DWORD PTR [i860_text_size],eax
    mov eax,DWORD PTR [esi+28]
    mov DWORD PTR [i860_data_size],eax
    mov eax,DWORD PTR [esi+32]
    mov DWORD PTR [i860_bss_size],eax
    mov eax,DWORD PTR [esi+36]
    mov DWORD PTR [i860_entry],eax
    mov eax,DWORD PTR [esi+40]
    mov DWORD PTR [i860_text_guest],eax
    mov eax,DWORD PTR [esi+44]
    mov DWORD PTR [i860_data_guest],eax

    /* Section table begins after 20-byte file + 36-byte optional header. */
    lea edi,[esi+56]
    cmp DWORD PTR [edi+0],0x7865742e  /* ".tex" */
    jne r860_bad_coff
    cmp DWORD PTR [edi+4],0x00000074  /* "t\\0\\0\\0" */
    jne r860_bad_coff
    cmp DWORD PTR [edi+40],0x7461642e /* ".dat" */
    jne r860_bad_coff
    cmp DWORD PTR [edi+44],0x00000061 /* "a\\0\\0\\0" */
    jne r860_bad_coff
    cmp DWORD PTR [edi+80],0x7373622e /* ".bss" */
    jne r860_bad_coff

    mov eax,DWORD PTR [edi+16]       /* text raw size */
    cmp eax,DWORD PTR [i860_text_size]
    jne r860_bad_coff
    mov edx,DWORD PTR [edi+20]       /* text raw file offset */
    mov DWORD PTR [i860_text_raw],edx
    add eax,edx
    cmp eax,I860_PAYLOAD_SIZE
    ja r860_bad_coff

    mov eax,DWORD PTR [edi+56]       /* data raw size: second sh +16 */
    cmp eax,DWORD PTR [i860_data_size]
    jne r860_bad_coff
    mov edx,DWORD PTR [edi+60]       /* data raw ptr: second sh +20 */
    mov DWORD PTR [i860_data_raw],edx
    add eax,edx
    cmp eax,I860_PAYLOAD_SIZE
    ja r860_bad_coff

    /* Entry must fall inside guest text. */
    mov eax,DWORD PTR [i860_entry]
    sub eax,DWORD PTR [i860_text_guest]
    jc r860_bad_entry
    cmp eax,DWORD PTR [i860_text_size]
    jae r860_bad_entry
    mov DWORD PTR [i860_entry_offset],eax

    /* Allocate backing store for text. */
    push PAGE_READWRITE
    push MEM_COMMIT_RESERVE
    push DWORD PTR [i860_text_size]
    push 0
    call DWORD PTR ds:[IAT_VirtualAlloc]
    test eax,eax
    jz r860_nomem
    mov DWORD PTR [i860_text_host],eax
    mov edi,eax
    mov esi,I860_PAYLOAD
    add esi,DWORD PTR [i860_text_raw]
    mov ecx,DWORD PTR [i860_text_size]
    cld
    rep movsb

    /* R10: preserve .data/.bss and provide a generous low heap backing, but do
       not tie it to the process stack. Intel's i860 process model places the
       user stack high in the address space; SIM860 deliberately touches
       0x7FFFFFFC, so the low heap and high stack must be distinct regions. */
    mov eax,0x01000000
    sub eax,DWORD PTR [i860_data_guest]
    jc r860_bad_coff
    mov DWORD PTR [i860_low_size],eax
    push PAGE_READWRITE
    push MEM_COMMIT_RESERVE
    push eax
    push 0
    call DWORD PTR ds:[IAT_VirtualAlloc]
    test eax,eax
    jz r860_nomem
    mov DWORD PTR [i860_data_host],eax
    mov edi,eax
    mov esi,I860_PAYLOAD
    add esi,DWORD PTR [i860_data_raw]
    mov ecx,DWORD PTR [i860_data_size]
    cld
    rep movsb
    xor eax,eax
    mov ecx,DWORD PTR [i860_bss_size]
    rep stosb
    /* Remaining low-memory heap backing is already zero from VirtualAlloc. */

    mov eax,DWORD PTR [i860_text_host]
    add eax,DWORD PTR [i860_entry_offset]
    mov DWORD PTR [i860_entry_host],eax

    push OFFSET FLAT:coff_ok
    call host_puts_out
    add esp,4
    push OFFSET FLAT:text_prefix
    call host_puts_out
    add esp,4
    push DWORD PTR [i860_text_guest]
    call host_puthex32
    add esp,4
    push OFFSET FLAT:size_prefix
    call host_puts_out
    add esp,4
    push DWORD PTR [i860_text_size]
    call host_puthex32
    add esp,4
    push OFFSET FLAT:crlf
    call host_puts_out
    add esp,4

    push OFFSET FLAT:data_prefix
    call host_puts_out
    add esp,4
    push DWORD PTR [i860_data_guest]
    call host_puthex32
    add esp,4
    push OFFSET FLAT:size_prefix
    call host_puts_out
    add esp,4
    push DWORD PTR [i860_data_size]
    call host_puthex32
    add esp,4
    push OFFSET FLAT:bss_prefix
    call host_puts_out
    add esp,4
    push DWORD PTR [i860_bss_size]
    call host_puthex32
    add esp,4
    push OFFSET FLAT:crlf
    call host_puts_out
    add esp,4

    push OFFSET FLAT:entry_prefix
    call host_puts_out
    add esp,4
    push DWORD PTR [i860_entry]
    call host_puthex32
    add esp,4
    push OFFSET FLAT:entry_off_prefix
    call host_puts_out
    add esp,4
    push DWORD PTR [i860_entry_offset]
    call host_puthex32
    add esp,4
    push OFFSET FLAT:crlf
    call host_puts_out
    add esp,4

    /* R10: historically shaped high user stack, 0x7FFF0000..0x7FFFFFFF. */
    mov DWORD PTR [i860_stack_guest],0x7fff0000
    mov DWORD PTR [i860_stack_size],0x00010000
    push PAGE_READWRITE
    push MEM_COMMIT_RESERVE
    push DWORD PTR [i860_stack_size]
    push 0
    call DWORD PTR ds:[IAT_VirtualAlloc]
    test eax,eax
    jz r860_nomem
    mov DWORD PTR [i860_stack_host],eax

    push OFFSET FLAT:cpu_start_banner
    call host_puts_out
    add esp,4
    call i860_run
    /* Clean guest exit is returned as 0x100 + low 8-bit exit status.
       Any smaller nonzero value is an interpreter/personality failure. */
    cmp eax,0x100
    jb r860_cpu_fail
    sub eax,0x100
    and eax,0xff
    push eax
    call DWORD PTR ds:[IAT_ExitProcess]

r860_cpu_fail:
    push 0xf4
    call DWORD PTR ds:[IAT_ExitProcess]

r860_bad_argv:
    push OFFSET FLAT:bad_argv
    call host_puts_err
    add esp,4
    mov eax,8
    jmp r860_fail
r860_bad_coff:
    push OFFSET FLAT:bad_coff
    call host_puts_err
    add esp,4
    mov eax,8
    jmp r860_fail
r860_bad_entry:
    push OFFSET FLAT:bad_entry
    call host_puts_err
    add esp,4
    mov eax,8
    jmp r860_fail
r860_nomem:
    push OFFSET FLAT:no_memory
    call host_puts_err
    add esp,4
    mov eax,12
r860_fail:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

/* cdecl: print one DWORD as 8 uppercase hexadecimal digits to stdout. */
host_puthex32:
    push ebp
    mov ebp,esp
    push ebx
    push esi
    push edi
    mov eax,DWORD PTR [ebp+8]
    mov edi,OFFSET FLAT:hex_buf+8
    mov BYTE PTR [edi],0
    mov ecx,8
hph_loop:
    dec edi
    mov edx,eax
    and edx,0x0f
    mov bl,BYTE PTR [hex_digits+edx]
    mov BYTE PTR [edi],bl
    shr eax,4
    dec ecx
    jnz hph_loop
    push OFFSET FLAT:hex_buf
    call host_puts_out
    add esp,4
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

/* cdecl: raw-byte guest read. fd 0 maps to stdin; ordinary guest fds
   are small System V-style integers backed by private Win32 HANDLE slots. */
host_read_fd:
    push ebp
    mov ebp,esp
    push ebx
    mov eax,DWORD PTR [ebp+8]
    cmp eax,0
    je hrf_stdin
    cmp eax,2
    jbe hrf_fail
    cmp eax,64
    jae hrf_fail
    mov ebx,DWORD PTR [fd_table+eax*4]
    test ebx,ebx
    jz hrf_fail
    jmp hrf_go
hrf_stdin:
    mov ebx,DWORD PTR [hstdin]
hrf_go:
    push 0
    push OFFSET FLAT:io_count
    push DWORD PTR [ebp+16]
    push DWORD PTR [ebp+12]
    push ebx
    call DWORD PTR ds:[IAT_ReadFile]
    test eax,eax
    jz hrf_fail
    mov eax,DWORD PTR [io_count]
    jmp hrf_done
hrf_fail:
    mov eax,0xffffffff
hrf_done:
    pop ebx
    pop ebp
    ret

/* cdecl: raw-byte guest write. fd 1/2 map to console; ordinary guest fds
   are translated through fd_table. */
host_write_fd:
    push ebp
    mov ebp,esp
    push ebx
    mov eax,DWORD PTR [ebp+8]
    cmp eax,1
    je hwf_stdout
    cmp eax,2
    je hwf_stderr
    cmp eax,2
    jbe hwf_fail
    cmp eax,64
    jae hwf_fail
    mov ebx,DWORD PTR [fd_table+eax*4]
    test ebx,ebx
    jz hwf_fail
    jmp hwf_go
hwf_stdout:
    mov ebx,DWORD PTR [hstdout]
    jmp hwf_go
hwf_stderr:
    mov ebx,DWORD PTR [hstderr]
hwf_go:
    push 0
    push OFFSET FLAT:io_count
    push DWORD PTR [ebp+16]
    push DWORD PTR [ebp+12]
    push ebx
    call DWORD PTR ds:[IAT_WriteFile]
    test eax,eax
    jz hwf_fail
    mov eax,DWORD PTR [io_count]
    jmp hwf_done
hwf_fail:
    mov eax,0xffffffff
hwf_done:
    pop ebx
    pop ebp
    ret

/* Internal: allocate the lowest free guest fd 3..63 for Win32 HANDLE in EAX.
   Returns guest fd or 0xffffffff; closes the HANDLE if the table is full. */
host_adopt_handle:
    push ebx
    push ecx
    mov ebx,eax
    mov ecx,3
hah_loop:
    cmp ecx,64
    jae hah_full
    cmp DWORD PTR [fd_table+ecx*4],0
    je hah_found
    inc ecx
    jmp hah_loop
hah_found:
    mov DWORD PTR [fd_table+ecx*4],ebx
    mov eax,ecx
    pop ecx
    pop ebx
    ret
hah_full:
    push ebx
    call DWORD PTR ds:[IAT_CloseHandle]
    mov eax,0xffffffff
    pop ecx
    pop ebx
    ret

/* cdecl: host_open_file(path, svr3_flags, mode_ignored). System V flags used
   by this tool: access low 2 bits; APPEND 0010; CREAT 0400; TRUNC 01000;
   EXCL 02000. Returns a small guest fd or 0xffffffff. */
host_open_file:
    push ebp
    mov ebp,esp
    push ebx
    push esi
    push edi
    mov esi,DWORD PTR [ebp+12]      /* flags */
    mov eax,esi
    and eax,3
    cmp eax,0
    je hof_rd
    cmp eax,1
    je hof_wr
    mov edi,GENERIC_READ|GENERIC_WRITE
    jmp hof_disp
hof_rd:
    mov edi,GENERIC_READ
    jmp hof_disp
hof_wr:
    mov edi,GENERIC_WRITE
hof_disp:
    mov ebx,OPEN_EXISTING
    test esi,0x100                  /* O_CREAT 0400 */
    jz hof_nocreat
    test esi,0x400                  /* O_EXCL 02000 */
    jnz hof_new
    test esi,0x200                  /* O_TRUNC 01000 */
    jnz hof_always
    mov ebx,OPEN_ALWAYS
    jmp hof_call
hof_new:
    mov ebx,CREATE_NEW
    jmp hof_call
hof_always:
    mov ebx,CREATE_ALWAYS
    jmp hof_call
hof_nocreat:
    test esi,0x200
    jz hof_call
    mov ebx,TRUNCATE_EXISTING
hof_call:
    push 0
    push FILE_ATTRIBUTE_NORMAL
    push ebx
    push 0
    push FILE_SHARE_RW
    push edi
    push DWORD PTR [ebp+8]
    call DWORD PTR ds:[IAT_CreateFileA]
    cmp eax,INVALID_HANDLE_VALUE
    je hof_done
    mov edi,eax                    /* real HANDLE */
    test esi,8                     /* O_APPEND */
    jz hof_adopt
    push FILE_END
    push 0
    push 0
    push edi
    call DWORD PTR ds:[IAT_SetFilePointer]
hof_adopt:
    mov eax,edi
    call host_adopt_handle
hof_done:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

/* cdecl: host_creat_file(path, mode_ignored). Returns a small guest fd. */
host_creat_file:
    push ebp
    mov ebp,esp
    push 0
    push FILE_ATTRIBUTE_NORMAL
    push CREATE_ALWAYS
    push 0
    push FILE_SHARE_RW
    push GENERIC_WRITE
    push DWORD PTR [ebp+8]
    call DWORD PTR ds:[IAT_CreateFileA]
    cmp eax,INVALID_HANDLE_VALUE
    je hcr_done
    call host_adopt_handle
hcr_done:
    pop ebp
    ret

/* cdecl: host_close_fd(fd). Standard handles remain owned by the personality;
   ordinary guest fds close and release their private Win32 HANDLE slot. */
host_close_fd:
    push ebp
    mov ebp,esp
    push ebx
    mov ebx,DWORD PTR [ebp+8]
    cmp ebx,2
    jbe hcf_ok
    cmp ebx,64
    jae hcf_fail
    mov eax,DWORD PTR [fd_table+ebx*4]
    test eax,eax
    jz hcf_fail
    push eax
    call DWORD PTR ds:[IAT_CloseHandle]
    test eax,eax
    jz hcf_fail
    mov DWORD PTR [fd_table+ebx*4],0
hcf_ok:
    xor eax,eax
    pop ebx
    pop ebp
    ret
hcf_fail:
    mov eax,0xffffffff
    pop ebx
    pop ebp
    ret

/* cdecl: host_lseek_fd(fd, signed_offset, whence). */
host_lseek_fd:
    push ebp
    mov ebp,esp
    push ebx
    mov ebx,DWORD PTR [ebp+8]
    cmp ebx,2
    jbe hls_fail
    cmp ebx,64
    jae hls_fail
    mov eax,DWORD PTR [fd_table+ebx*4]
    test eax,eax
    jz hls_fail
    mov edx,DWORD PTR [ebp+16]
    cmp edx,2
    ja hls_fail
    push edx
    push 0
    push DWORD PTR [ebp+12]
    push eax
    call DWORD PTR ds:[IAT_SetFilePointer]
    pop ebx
    pop ebp
    ret
hls_fail:
    mov eax,0xffffffff
    pop ebx
    pop ebp
    ret

/* cdecl: host_unlink_file(path). Return 0 or 0xffffffff. */
host_unlink_file:
    push ebp
    mov ebp,esp
    push DWORD PTR [ebp+8]
    call DWORD PTR ds:[IAT_DeleteFileA]
    test eax,eax
    jz huf_fail
    xor eax,eax
    pop ebp
    ret
huf_fail:
    mov eax,0xffffffff
    pop ebp
    ret

/* cdecl: host_filesize_fd(fd). 32-bit file sizes are sufficient for the N1.3
   toolchain artifacts used by this compatibility experiment. */
host_filesize_fd:
    push ebp
    mov ebp,esp
    mov ecx,DWORD PTR [ebp+8]
    cmp ecx,2
    jbe hfs_zero
    cmp ecx,64
    jae hfs_fail
    mov eax,DWORD PTR [fd_table+ecx*4]
    test eax,eax
    jz hfs_fail
    push 0
    push eax
    call DWORD PTR ds:[IAT_GetFileSize]
    pop ebp
    ret
hfs_zero:
    xor eax,eax
    pop ebp
    ret
hfs_fail:
    mov eax,0xffffffff
    pop ebp
    ret

/* cdecl helper: one char* argument. */
host_puts_out:
    push ebp
    mov ebp,esp
    push esi
    mov esi,DWORD PTR [ebp+8]
    call strlen_esi
    push 0
    push OFFSET FLAT:io_count
    push eax
    push DWORD PTR [ebp+8]
    push DWORD PTR [hstdout]
    call DWORD PTR ds:[IAT_WriteFile]
    pop esi
    pop ebp
    ret
host_puts_err:
    push ebp
    mov ebp,esp
    push esi
    mov esi,DWORD PTR [ebp+8]
    call strlen_esi
    push 0
    push OFFSET FLAT:io_count
    push eax
    push DWORD PTR [ebp+8]
    push DWORD PTR [hstderr]
    call DWORD PTR ds:[IAT_WriteFile]
    pop esi
    pop ebp
    ret
strlen_esi:
    push edi
    mov edi,esi
    xor eax,eax
    mov ecx,-1
    repne scasb
    not ecx
    dec ecx
    mov eax,ecx
    pop edi
    ret

.section .data
.balign 4
hstdin: .long 0
hstdout: .long 0
hstderr: .long 0
/* Guest descriptor table. Slots 0..2 are reserved for stdio and handled
   specially; slots 3..63 hold opaque Win32 HANDLE values. */
fd_table: .space 64*4
io_count: .long 0
argc_store: .long 0
old_protect: .long 0
banner: .asciz "SIM860 R10: entering original UNIX System V/386 wrapper\\r\\n"
bad_cmd: .asciz "SIM860 R10: command line too long\\r\\n"
unknown_msg: .asciz "SIM860 R10: unhandled SVR3 syscall; aborting\\r\\n"
gate15_msg: .asciz "SIM860 R10: selector 0x0F signal trampoline reached unexpectedly\\r\\n"
exec_prefix: .asciz "SIM860 R10: historical execve reached non-run860 target: "
exec_suffix: .asciz "SIM860 R10: generic second-image chaining is not implemented.\\r\\n"
crlf: .asciz "\\r\\n"
run860_banner: .asciz "SIM860 R10: untouched wrapper requested run860; entering in-process execution vehicle\\r\\n"
target_prefix: .asciz "SIM860 R10: run860 target argv[1] = "
coff_ok: .asciz "SIM860 R10: embedded i860 COFF validated (magic 014D, 3 sections)\\r\\n"
text_prefix: .asciz "SIM860 R10: text guest=0x"
data_prefix: .asciz "SIM860 R10: data guest=0x"
size_prefix: .asciz " size=0x"
bss_prefix: .asciz " bss=0x"
entry_prefix: .asciz "SIM860 R10: entry guest=0x"
entry_off_prefix: .asciz " text+0x"
cpu_start_banner: .asciz "SIM860 R10: RUN860 LOAD PASS; starting bounded i860 CPU core\\r\\n"
bad_argv: .asciz "SIM860 R10: run860 argv contract invalid\\r\\n"
bad_coff: .asciz "SIM860 R10: embedded i860 COFF validation failed\\r\\n"
bad_entry: .asciz "SIM860 R10: i860 entry point is outside .text\\r\\n"
no_memory: .asciz "SIM860 R10: unable to allocate i860 guest backing memory\\r\\n"
hex_digits: .ascii "0123456789ABCDEF"
hex_buf: .space 9
.balign 4
i860_text_size: .long 0
i860_data_size: .long 0
i860_bss_size: .long 0
i860_entry: .long 0
i860_text_guest: .long 0
i860_data_guest: .long 0
i860_text_raw: .long 0
i860_data_raw: .long 0
i860_entry_offset: .long 0
i860_low_size: .long 0
i860_text_host: .long 0
i860_data_host: .long 0
i860_entry_host: .long 0
i860_stack_guest: .long 0
i860_stack_size: .long 0
i860_stack_host: .long 0
i860_run860_argv: .long 0
path_env: .asciz "PATH=."
trace_level: .long 0
host_env_block: .long 0
env_count: .long 0
trace_env_name: .asciz "SVR3COFF2PE_TRACE"
trace_buf: .space 16
trace_hex_buf: .space 9
trace_open_prefix: .asciz "[svr3 trace] open: "
trace_access_prefix: .asciz "[svr3 trace] access: "
trace_read_prefix: .asciz "[svr3 trace] read fd=0x"
trace_write_prefix: .asciz "[svr3 trace] write fd=0x"
trace_result_prefix: .asciz "[svr3 trace] read result=0x"
trace_open_result_prefix: .asciz "[svr3 trace] open result=0x"
trace_count_mid: .asciz " arg=0x"
trace_bih_ptr_prefix: .asciz "[svr3 trace] IC bih_ptr=0x"
trace_bih_count_prefix: .asciz "[svr3 trace] IC bih_count=0x"
trace_bih_cur_prefix: .asciz "[svr3 trace] IC bih_cur=0x"
trace_allocp_prefix: .asciz "[svr3 trace] IC allocp=0x"
trace_alloct_prefix: .asciz "[svr3 trace] IC alloct=0x"
trace_allocx_prefix: .asciz "[svr3 trace] IC allocx=0x"
trace_allocend_prefix: .asciz "[svr3 trace] IC allocend=0x"
trace_allocs_prefix: .asciz "[svr3 trace] IC allocs=0x"
trace_sbrk_prefix: .asciz "[svr3 trace] IC sbrk_cur=0x"
trace_nativebrk_prefix: .asciz "[svr3 trace] host native_brk=0x"
.balign 4
ic_diag_enabled: .long 1
ic_diag_once: .long 0
env_vec: .space 1024
fallback_argv0: .asciz "sim860-r10.exe"
.balign 4
argv_vec: .space 64*4
cmd_buf: .space 4096
cmd_buf_end:
'''

def cpu_source():
    return r'''/* SIM860 R10 bounded i860 interpreter.
   Runs the original Intel AS860 N1.3 i860 payload with the complete statically-linked
   SVR3 syscall surface needed by the assembler, binary-safe Win32 file services, and
   instruction semantics cross-checked against the Previous/Dimension i860 core.
   Guest exit returns a tagged status to the Win32 execution vehicle. */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed int s32;

extern u32 i860_text_size, i860_data_size, i860_bss_size;
extern u32 i860_entry, i860_text_guest, i860_data_guest, i860_low_size;
extern u32 i860_text_host, i860_data_host;
extern u32 i860_stack_guest, i860_stack_size, i860_stack_host;
extern u32 i860_run860_argv;
extern void host_puts_out(const char *s);
extern void host_puts_err(const char *s);
extern void host_puthex32(u32 v);
extern u32 host_write_fd(u32 fd, const void *p, u32 n);
extern u32 host_read_fd(u32 fd, void *p, u32 n);
extern u32 host_open_file(const char *path, u32 flags, u32 mode);
extern u32 host_creat_file(const char *path, u32 mode);
extern u32 host_close_fd(u32 fd);
extern u32 host_lseek_fd(u32 fd, u32 off, u32 whence);
extern u32 host_unlink_file(const char *path);
extern u32 host_filesize_fd(u32 fd);

static u32 r[32];
static u32 f[32];
static u32 cr[16];
static u32 cc;
static u32 lcc;
static u32 startup_argc;
static u32 pc;
static u32 icount;
static u32 fault_addr;
static u32 fault_kind;
static u32 write_traps;
static u32 write_bytes;
static u32 close_traps;
static u32 signal_traps;
static u32 utssys_traps;
static u32 brk_traps;
static u32 read_traps;
static u32 open_traps;
static u32 creat_traps;
static u32 unlink_traps;
static u32 time_traps;
static u32 stat_traps;
static u32 lseek_traps;
static u32 fstat_traps;
static u32 access_traps;
static u32 getpid_traps;
static u32 getuid_traps;
static u32 getgid_traps;
static u32 exit_traps;
static u32 guest_exit_status;
static u32 std_open_mask;
static u32 brk_floor;
static u32 brk_current;
static u32 inner_entry_seen;
static u32 inner_loop_cc_seen;
static u32 inner_loop_d0_seen;
static u32 inner_entry_count;
static u32 inner_loop_cc_count;
static u32 inner_loop_d0_count;

#define INNER_REG_BASE 0x0001A5D0u
#define INNER_PC_ADDR  0x0001A760u
#define TARGET_ENTRY_PC 0xF04000C0u
#define TARGET_LOOP_PC  0xF04000CCu
#define TARGET_DELAY_PC 0xF04000D0u

#define TRACE_LIMIT 24u
#define STEP_LIMIT 1000000u
#define EXPECT_PC 0xF041B644u
#define EXPECT_WORD 0x47E0F800u
#define EXPECT_COUNT 9485u
#define EXPECT_WRITE_TRAPS 112u
#define EXPECT_CLOSE_TRAPS 3u
#define EXPECT_SIGNAL_TRAPS 1u
#define STARTUP_BASE 0x7fff0100u
#define STARTUP_LIMIT 0x7fff4000u

static int opmatch(u32 w, u32 match, u32 lose)
{
    return ((w & match) == match) && ((w & lose) == 0u);
}

static s32 sx16(u32 x)
{
    x &= 0xffffu;
    if (x & 0x8000u) x |= 0xffff0000u;
    return (s32)x;
}

static s32 sx26(u32 x)
{
    x &= 0x03ffffffu;
    if (x & 0x02000000u) x |= 0xfc000000u;
    return (s32)x;
}

static s32 split16(u32 w)
{
    u32 x;
    x = ((w >> 5) & 0xf800u) | (w & 0x07ffu);
    return sx16(x);
}

static void setr(u32 n, u32 v)
{
    if (n != 0u) r[n & 31u] = v;
}

static u8 *guest_ptr(u32 a, u32 n, int write_access)
{
    u32 off;
    if (n == 0u) return (u8 *)0;
    if (a >= i860_text_guest) {
        off = a - i860_text_guest;
        if (off <= i860_text_size && n <= i860_text_size - off) {
            if (write_access) {
                fault_addr = a; fault_kind = 2u; return (u8 *)0;
            }
            return (u8 *)(i860_text_host + off);
        }
    }
    if (a >= i860_data_guest) {
        off = a - i860_data_guest;
        if (off <= i860_low_size && n <= i860_low_size - off)
            return (u8 *)(i860_data_host + off);
    }
    if (a >= i860_stack_guest) {
        off = a - i860_stack_guest;
        if (off <= i860_stack_size && n <= i860_stack_size - off)
            return (u8 *)(i860_stack_host + off);
    }
    fault_addr = a; fault_kind = write_access ? 4u : 3u;
    return (u8 *)0;
}

static int read_mem(u32 a, u32 n, u32 *out)
{
    u8 *p;
    if ((n == 2u && (a & 1u)) || (n == 4u && (a & 3u))) {
        fault_addr = a; fault_kind = 5u; return 0;
    }
    p = guest_ptr(a,n,0);
    if (!p) return 0;
    if (n == 1u) {
        *out = (u32)p[0];
        if (*out & 0x80u) *out |= 0xffffff00u;
    } else if (n == 2u) {
        *out = (u32)p[0] | ((u32)p[1] << 8);
        if (*out & 0x8000u) *out |= 0xffff0000u;
    } else *out = (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
    return 1;
}

static int write_mem(u32 a, u32 n, u32 v)
{
    u8 *p;
    if ((n == 2u && (a & 1u)) || (n == 4u && (a & 3u))) {
        fault_addr = a; fault_kind = 5u; return 0;
    }
    p = guest_ptr(a,n,1);
    if (!p) return 0;
    p[0] = (u8)v;
    if (n >= 2u) p[1] = (u8)(v >> 8);
    if (n >= 4u) { p[2] = (u8)(v >> 16); p[3] = (u8)(v >> 24); }
    return 1;
}

/* i860 floating registers are 32 bits each. A double uses an even register
   and the following register. This target is little-endian, so the first
   register supplies the low-address 32-bit word. */
static int write_fpair64(u32 a, u32 freg)
{
    u8 *p;
    u32 lo, hi;
    if ((a & 7u) != 0u) {
        fault_addr = a; fault_kind = 5u; return 0;
    }
    if ((freg & 1u) != 0u || freg >= 31u) return 0;
    p = guest_ptr(a,8u,1);
    if (!p) return 0;
    lo=f[freg]; hi=f[freg+1u];
    p[0]=(u8)lo; p[1]=(u8)(lo>>8); p[2]=(u8)(lo>>16); p[3]=(u8)(lo>>24);
    p[4]=(u8)hi; p[5]=(u8)(hi>>8); p[6]=(u8)(hi>>16); p[7]=(u8)(hi>>24);
    return 1;
}

static int write_fwords(u32 a, u32 freg, u32 words)
{
    u32 i,align;
    align=words*4u;
    if (words==0u || words>4u || (a & (align-1u))!=0u ||
        (freg & (words-1u))!=0u || freg+words>32u) {
        fault_addr=a; fault_kind=5u; return 0;
    }
    for (i=0u;i<words;i++) if (!write_mem(a+i*4u,4u,f[freg+i])) return 0;
    return 1;
}

static int read_fwords(u32 a, u32 freg, u32 words)
{
    u32 i,align,v;
    align=words*4u;
    if (words==0u || words>4u || (a & (align-1u))!=0u ||
        (freg & (words-1u))!=0u || freg+words>32u) {
        fault_addr=a; fault_kind=5u; return 0;
    }
    for (i=0u;i<words;i++) {
        if (!read_mem(a+i*4u,4u,&v)) return 0;
        f[freg+i]=v;
    }
    return 1;
}

typedef union I860_DBL_BITS { double d; u32 w[2]; } I860_DBL_BITS;
static double get_f64(u32 freg)
{
    I860_DBL_BITS x; x.w[0]=f[freg]; x.w[1]=f[freg+1u]; return x.d;
}
static void set_f64(u32 freg,double v)
{
    I860_DBL_BITS x; x.d=v; f[freg]=x.w[0]; f[freg+1u]=x.w[1];
}

static int guest_store_utsname(u32 a)
{
    u8 *p;
    static const char *fields[5] = {"UNIX", "run860", "3.2", "N1.3", "i860"};
    u32 i,j;
    p=guest_ptr(a,45u,1);
    if (!p) return 0;
    for (i=0u;i<45u;i++) p[i]=0u;
    for (i=0u;i<5u;i++) {
        for (j=0u;j<8u && fields[i][j];j++) p[i*9u+j]=(u8)fields[i][j];
    }
    return 1;
}

static const char *guest_cstr(u32 a)
{
    u8 *p;
    u32 i;
    p=guest_ptr(a,1u,0);
    if (!p) return (const char *)0;
    for (i=0u;i<1024u;i++) {
        p=guest_ptr(a+i,1u,0);
        if (!p) return (const char *)0;
        if (*p==0u) return (const char *)guest_ptr(a,i+1u,0);
    }
    return (const char *)0;
}

static char host_path_buf[1024];
static int path_prefix(const char *s,const char *p)
{
    u32 i; for (i=0u;p[i];i++) if (s[i]!=p[i]) return 0; return 1;
}
static const char *guest_host_path(u32 a,int *is_dir)
{
    const char *s,*q; u32 i,j;
    s=guest_cstr(a); if (!s) return (const char *)0;
    *is_dir=0; q=s;
    if (path_prefix(s,"/usr/tmp/")) { q=s+9; if (!*q) *is_dir=1; }
    else if (path_prefix(s,"/tmp/")) { q=s+5; if (!*q) *is_dir=1; }
    else if (path_prefix(s,"\\tmp\\")) { q=s+5; if (!*q) *is_dir=1; }
    else if ((s[0]=='.' && s[1]==0) || (s[0]=='/' && s[1]==0)) { q=s+1; *is_dir=1; }
    else if ((path_prefix(s,"/usr/tmp") && s[8]==0) || (path_prefix(s,"/tmp") && s[4]==0) ||
             (path_prefix(s,"\\tmp") && s[4]==0)) { q=s+(s[1]=='u'?8:4); *is_dir=1; }
    if (*is_dir) { host_path_buf[0]='.'; host_path_buf[1]=0; return host_path_buf; }
    for (i=0u,j=0u;q[i] && j<1023u;i++) {
        char c; c=q[i]; if (c=='/') c='\\'; host_path_buf[j++]=c;
    }
    host_path_buf[j]=0;
    if (j==0u) { host_path_buf[0]='.'; host_path_buf[1]=0; *is_dir=1; }
    return host_path_buf;
}

static void put16le(u8 *p,u32 v)
{
    p[0]=(u8)v; p[1]=(u8)(v>>8);
}

static void put32le(u8 *p,u32 v)
{
    p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24);
}

/* Old System V struct stat used by this N1.3 binary:
   short dev; ushort ino,mode; short nlink; ushort uid,gid; short rdev;
   2-byte ABI alignment pad; long size,atime,mtime,ctime. Total 32 bytes. */
static int guest_store_stat(u32 a,u32 size,u32 mode)
{
    u8 *p; u32 i;
    p=guest_ptr(a,32u,1);
    if (!p) return 0;
    for (i=0u;i<32u;i++) p[i]=0u;
    put16le(p+0,0u);           /* st_dev */
    put16le(p+2,1u);           /* st_ino */
    put16le(p+4,mode);         /* st_mode */
    put16le(p+6,1u);           /* st_nlink */
    put16le(p+8,0u);           /* st_uid */
    put16le(p+10,0u);          /* st_gid */
    put16le(p+12,0u);          /* st_rdev */
    put32le(p+16,size);        /* st_size */
    put32le(p+20,631152000u);  /* 1990-01-01 UTC, deterministic */
    put32le(p+24,631152000u);
    put32le(p+28,631152000u);
    return 1;
}

static void trace_insn(u32 at, u32 w)
{
    if (icount > TRACE_LIMIT) return;
    host_puts_out("SIM860 R10: TRACE #0x"); host_puthex32(icount);
    host_puts_out(" pc=0x"); host_puthex32(at);
    host_puts_out(" insn=0x"); host_puthex32(w);
    host_puts_out("\r\n");
    if (icount == TRACE_LIMIT)
        host_puts_out("SIM860 R10: trace suppressed after first 24 instructions\r\n");
}

/* Build the i860-side process startup contract that run860 would have supplied.
   The outer historical wrapper passes run860 an argv vector of:
       run860, fat-binary-path, original-user-args...
   The i860 program therefore receives argv beginning at element 1.  r16/r17/r18
   carry argc/argv/envp; a compact pointer/string area is placed safely near the
   bottom of the synthetic guest stack, away from the live stack top. */
static u32 host_strlen_bounded(const char *s, u32 lim)
{
    u32 n;
    if (!s) return 0xffffffffu;
    for (n=0u;n<lim;n++) if (s[n]==0) return n;
    return 0xffffffffu;
}

static int setup_startup(void)
{
    u32 *hav;
    u32 argc, i, cur, argv_addr, envp_addr, n;
    const char *hs;
    u8 *p;
    static const char path_s[] = "PATH=.";
    hav=(u32 *)i860_run860_argv;
    if (!hav) return 0;
    argc=0u;
    while (argc<62u && hav[argc+1u]!=0u) argc++;
    if (argc==0u) return 0;

    cur=STARTUP_BASE;
    /* Reserve argv pointers + NULL and envp pointer + NULL first. */
    argv_addr=cur;
    cur += (argc+1u)*4u;
    envp_addr=cur;
    cur += 8u;
    cur=(cur+3u)&~3u;
    if (cur>=STARTUP_LIMIT) return 0;

    for (i=0u;i<argc;i++) {
        hs=(const char *)hav[i+1u];
        n=host_strlen_bounded(hs,1023u);
        if (n==0xffffffffu || cur+n+1u>STARTUP_LIMIT) return 0;
        p=guest_ptr(cur,n+1u,1);
        if (!p) return 0;
        {
            u32 j;
            for (j=0u;j<=n;j++) p[j]=(u8)hs[j];
        }
        if (!write_mem(argv_addr+i*4u,4u,cur)) return 0;
        cur += n+1u;
    }
    if (!write_mem(argv_addr+argc*4u,4u,0u)) return 0;

    n=(u32)(sizeof(path_s));
    p=guest_ptr(cur,n,1);
    if (!p) return 0;
    for (i=0u;i<n;i++) p[i]=(u8)path_s[i];
    if (!write_mem(envp_addr,4u,cur)) return 0;
    if (!write_mem(envp_addr+4u,4u,0u)) return 0;

    r[16]=argc;
    r[17]=argv_addr;
    r[18]=envp_addr;
    return 1;
}

/* Execute only a non-control instruction. Return 1 if supported, 0 otherwise,
   and -1 for a memory fault. */
static int exec_noncontrol(u32 at, u32 w)
{
    u32 s1, s2, d, a, b, v, n, off;
    s1 = (w >> 11) & 31u;
    s2 = (w >> 21) & 31u;
    d = (w >> 16) & 31u;

    if (opmatch(w,0x30000000u,0xcc000000u)) { setr(d,cr[s2 & 15u]); pc = at + 4u; return 1; }
    if (opmatch(w,0x38000000u,0xc4000000u)) { cr[s2 & 15u] = r[s1]; pc = at + 4u; return 1; }

    /* ixfr: transfer integer register bits to a floating register. */
    if (opmatch(w,0x08000000u,0xf4000000u)) { f[d]=r[s1]; pc=at+4u; return 1; }

    /* fmlow.dd is used by the N1.3 runtime for 32-bit integer multiply:
       ixfr operands into FP regs, fmlow.dd, then fxfr the low product back. */
    if (opmatch(w,0x480001a1u,0xb400065eu)) {
        f[d]=f[s1]*f[s2]; if (d<31u) f[d+1u]=0u; pc=at+4u; return 1;
    }
    /* fxfr: transfer low 32-bit floating-register bits to an integer reg. */
    if (opmatch(w,0x48000040u,0xb40007bfu)) { setr(d,f[s1]); pc=at+4u; return 1; }
    /* fiadd.ss: 32-bit integer add in the floating register file.  This
       also implements the fmov.ss pseudo-op when fsrc2 is f0. */
    if (opmatch(w,0x48000049u,0xb40007b6u)) { f[d]=f[s1]+f[s2]; pc=at+4u; return 1; }
    /* Scalar double subtraction used by the assembler's numeric runtime. */
    if (opmatch(w,0x480001b1u,0xb400044eu)) {
        if ((s1&1u)||(s2&1u)||(d&1u)||s1>=31u||s2>=31u||d>=31u) return 0;
        set_f64(d,get_f64(s1)-get_f64(s2)); pc=at+4u; return 1;
    }
    if (opmatch(w,0x480001a2u,0xb400065du)) {
        if ((s2&1u)||(d&1u)||s2>=31u||d>=31u) return 0;
        set_f64(d,1.0/get_f64(s2)); pc=at+4u; return 1;
    }
    if (opmatch(w,0x480001a0u,0xb400065fu)) {
        if ((s1&1u)||(s2&1u)||(d&1u)||s1>=31u||s2>=31u||d>=31u) return 0;
        set_f64(d,get_f64(s1)*get_f64(s2)); pc=at+4u; return 1;
    }
    if (opmatch(w,0x480001bau,0xb4000445u)) {
        s32 iv;
        if ((s1&1u)||(d&1u)||s1>=31u||d>=31u) return 0;
        iv=(s32)get_f64(s1); f[d]=(u32)iv; f[d+1u]=0u; pc=at+4u; return 1;
    }

    /* Floating loads: the immediate is aligned to operand width.  With
       autoincrement, src2 receives the effective address after the load. */
    if (opmatch(w,0x24000002u,0xd8000001u)) { off=(u32)sx16(w)&~3u; if (!read_fwords(r[s2]+off,d,1u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x20000002u,0xdc000001u)) { if (!read_fwords(r[s2]+r[s1],d,1u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x24000003u,0xd8000000u)) { off=(u32)sx16(w)&~3u; a=r[s2]+off; if (!read_fwords(a,d,1u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x20000003u,0xdc000000u)) { a=r[s2]+r[s1]; if (!read_fwords(a,d,1u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x24000000u,0xd8000007u)) { off=(u32)sx16(w)&~7u; if (!read_fwords(r[s2]+off,d,2u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x20000000u,0xdc000007u)) { if (!read_fwords(r[s2]+r[s1],d,2u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x24000001u,0xd8000006u)) { off=(u32)sx16(w)&~7u; a=r[s2]+off; if (!read_fwords(a,d,2u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x20000001u,0xdc000006u)) { a=r[s2]+r[s1]; if (!read_fwords(a,d,2u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x24000004u,0xd8000003u)) { off=(u32)sx16(w)&~15u; if (!read_fwords(r[s2]+off,d,4u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x20000004u,0xdc000003u)) { if (!read_fwords(r[s2]+r[s1],d,4u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x24000005u,0xd8000002u)) { off=(u32)sx16(w)&~15u; a=r[s2]+off; if (!read_fwords(a,d,4u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x20000005u,0xdc000002u)) { a=r[s2]+r[s1]; if (!read_fwords(a,d,4u)) return -1; setr(s2,a); pc=at+4u; return 1; }

    /* AS860 uses quad FP stores to spill register-save areas.  In i860
       autoincrement addressing src2 is replaced by the effective address. */
    if (opmatch(w,0x2c000005u,0xd0000002u)) {
        off=(u32)sx16(w) & ~15u; a=r[s2]+off;
        if (!write_fwords(a,d,4u)) return -1;
        setr(s2,a); pc=at+4u; return 1;
    }
    if (opmatch(w,0x28000005u,0xd4000002u)) {
        a=r[s2]+r[s1];
        if (!write_fwords(a,d,4u)) return -1;
        setr(s2,a); pc=at+4u; return 1;
    }
    if (opmatch(w,0x2c000004u,0xd0000003u)) {
        off=(u32)sx16(w) & ~15u;
        if (!write_fwords(r[s2]+off,d,4u)) return -1;
        pc=at+4u; return 1;
    }
    if (opmatch(w,0x28000004u,0xd4000003u)) {
        if (!write_fwords(r[s2]+r[s1],d,4u)) return -1;
        pc=at+4u; return 1;
    }

    /* Single/double floating stores, including autoincrement forms. */
    if (opmatch(w,0x2c000002u,0xd0000001u)) { off=(u32)sx16(w)&~3u; if (!write_fwords(r[s2]+off,d,1u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x28000002u,0xd4000001u)) { if (!write_fwords(r[s2]+r[s1],d,1u)) return -1; pc=at+4u; return 1; }
    if (opmatch(w,0x2c000003u,0xd0000000u)) { off=(u32)sx16(w)&~3u; a=r[s2]+off; if (!write_fwords(a,d,1u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x28000003u,0xd4000000u)) { a=r[s2]+r[s1]; if (!write_fwords(a,d,1u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x2c000001u,0xd0000006u)) { off=(u32)sx16(w)&~7u; a=r[s2]+off; if (!write_fwords(a,d,2u)) return -1; setr(s2,a); pc=at+4u; return 1; }
    if (opmatch(w,0x28000001u,0xd4000006u)) { a=r[s2]+r[s1]; if (!write_fwords(a,d,2u)) return -1; setr(s2,a); pc=at+4u; return 1; }

    /* R8 preserved floating-point operation: normal fst.d. GNU's opcode table
       defines immediate fst.d as 0x2c000000/0xd0000007 with an 8-byte-aligned
       signed immediate, and register-indexed fst.d as 0x28000000/0xd4000007. */
    if (opmatch(w,0x2c000000u,0xd0000007u)) {
        off=(u32)sx16(w) & ~7u;
        if (!write_fpair64(r[s2]+off,d)) return -1;
        pc=at+4u; return 1;
    }
    if (opmatch(w,0x28000000u,0xd4000007u)) {
        if (!write_fpair64(r[s2]+r[s1],d)) return -1;
        pc=at+4u; return 1;
    }

    if (opmatch(w,0x0c000000u,0xf0000000u)) n=1u;
    else if (opmatch(w,0x1c000000u,0xe0000001u)) n=2u;
    else if (opmatch(w,0x1c000001u,0xe0000000u)) n=4u;
    else n=0u;
    if (n) {
        off = (u32)split16(w) & ~(n-1u);
        if (!write_mem(r[s2] + off,n,r[s1])) return -1;
        pc = at + 4u; return 1;
    }

    if (opmatch(w,0x00000000u,0xfc000000u)) { n=1u; off=r[s1]; }
    else if (opmatch(w,0x04000000u,0xf8000000u)) { n=1u; off=(u32)sx16(w); }
    else if (opmatch(w,0x10000000u,0xec000001u)) { n=2u; off=r[s1]; }
    else if (opmatch(w,0x14000000u,0xe8000001u)) { n=2u; off=(u32)sx16(w) & ~1u; }
    else if (opmatch(w,0x10000001u,0xec000000u)) { n=4u; off=r[s1]; }
    else if (opmatch(w,0x14000001u,0xe8000000u)) { n=4u; off=(u32)sx16(w) & ~3u; }
    else n=0u;
    if (n) {
        if (!read_mem(r[s2] + off,n,&v)) return -1;
        setr(d,v); pc=at+4u; return 1;
    }

#define ARITH(MATCH,LOSE,IMM,OP) \
    if (opmatch(w,(MATCH),(LOSE))) { \
        a = (IMM) ? (u32)sx16(w) : r[s1]; b = r[s2]; \
        if ((OP)==0u) { v=a+b; cc=(v<a); } \
        else if ((OP)==1u) { v=a+b; cc=((s32)b < (s32)(0u-a)); } \
        else if ((OP)==2u) { v=a-b; cc=(b<=a); } \
        else { v=a-b; cc=((s32)b > (s32)a); } \
        setr(d,v); pc=at+4u; return 1; \
    }
    ARITH(0x80000000u,0x7c000000u,0,0u)
    ARITH(0x84000000u,0x78000000u,1,0u)
    ARITH(0x90000000u,0x6c000000u,0,1u)
    ARITH(0x94000000u,0x68000000u,1,1u)
    ARITH(0x88000000u,0x74000000u,0,2u)
    ARITH(0x8c000000u,0x70000000u,1,2u)
    ARITH(0x98000000u,0x64000000u,0,3u)
    ARITH(0x9c000000u,0x60000000u,1,3u)
#undef ARITH

#define SHIFT(MATCH,LOSE,IMM,OP) \
    if (opmatch(w,(MATCH),(LOSE))) { \
        a=((IMM) ? (w & 0xffffu) : r[s1]) & 31u; b=r[s2]; \
        if ((OP)==0u) v=b<<a; else if ((OP)==1u) v=b>>a; else v=(u32)(((s32)b)>>a); \
        setr(d,v); pc=at+4u; return 1; \
    }
    SHIFT(0xa0000000u,0x5c000000u,0,0u)
    SHIFT(0xa4000000u,0x58000000u,1,0u)
    SHIFT(0xa8000000u,0x54000000u,0,1u)
    SHIFT(0xac000000u,0x50000000u,1,1u)
    SHIFT(0xb8000000u,0x44000000u,0,2u)
    SHIFT(0xbc000000u,0x40000000u,1,2u)
#undef SHIFT

#define LOGIC(MATCH,LOSE,IMM,HIGH,OP) \
    if (opmatch(w,(MATCH),(LOSE))) { \
        a=(IMM) ? (w & 0xffffu) : r[s1]; if (HIGH) a <<= 16; b=r[s2]; \
        if ((OP)==0u) v=a&b; else if ((OP)==1u) v=(~a)&b; else if ((OP)==2u) v=a|b; else v=a^b; \
        cc=(v==0u); setr(d,v); pc=at+4u; return 1; \
    }
    LOGIC(0xc0000000u,0x3c000000u,0,0,0u)
    LOGIC(0xc4000000u,0x38000000u,1,0,0u)
    LOGIC(0xcc000000u,0x30000000u,1,1,0u)
    LOGIC(0xd0000000u,0x2c000000u,0,0,1u)
    LOGIC(0xd4000000u,0x28000000u,1,0,1u)
    LOGIC(0xdc000000u,0x20000000u,1,1,1u)
    LOGIC(0xe0000000u,0x1c000000u,0,0,2u)
    LOGIC(0xe4000000u,0x18000000u,1,0,2u)
    LOGIC(0xec000000u,0x10000000u,1,1,2u)
    LOGIC(0xf0000000u,0x0c000000u,0,0,3u)
    LOGIC(0xf4000000u,0x08000000u,1,0,3u)
    LOGIC(0xfc000000u,0x00000000u,1,1,3u)
#undef LOGIC

    if (opmatch(w,0x58000000u,0xa4000000u) || opmatch(w,0x5c000000u,0xa0000000u) ||
        opmatch(w,0x50000000u,0xac000000u) || opmatch(w,0x54000000u,0xa8000000u)) {
        int neq, imm, take;
        neq = opmatch(w,0x50000000u,0xac000000u) || opmatch(w,0x54000000u,0xa8000000u);
        imm = opmatch(w,0x5c000000u,0xa0000000u) || opmatch(w,0x54000000u,0xa8000000u);
        a = imm ? s1 : r[s1]; b=r[s2]; take=(a==b); if (neq) take=!take;
        pc = take ? at + 4u + (u32)(split16(w)*4) : at + 4u; return 1;
    }

    if (opmatch(w,0x70000000u,0x8c000000u)) { pc=cc ? at+4u+(u32)(sx26(w)*4) : at+4u; return 1; }
    if (opmatch(w,0x78000000u,0x84000000u)) { pc=!cc ? at+4u+(u32)(sx26(w)*4) : at+4u; return 1; }

    return 0;
}

static int fetch_trace(u32 at, u32 *w)
{
    if (!read_mem(at,4u,w)) return 0;
    ++icount; trace_insn(at,*w); return 1;
}

static int exec_delay(u32 at)
{
    u32 w; int rc;
    if (!fetch_trace(at,&w)) return -1;
    rc=exec_noncontrol(at,w);
    if (rc <= 0) { pc=at; return rc ? rc : 0; }
    return 1;
}

/* Return 2 clean guest exit, 1 supported/progressed, 0 unsupported, -1 memory fault. */
static int step_one(void)
{
    u32 at,w,s1,target; int rc,cond;
    at=pc;
    if (!fetch_trace(at,&w)) return -1;
    s1=(w>>11)&31u;

    if (opmatch(w,0x68000000u,0x94000000u) || opmatch(w,0x6c000000u,0x90000000u)) {
        int is_call;
        target=at+4u+(u32)(sx26(w)*4);
        is_call=opmatch(w,0x6c000000u,0x90000000u);
        rc=exec_delay(at+4u); if (rc<=0) return rc;
        /* Relative call writes r1 after the delay slot; the delay-slot
           instruction therefore sees the old r1. */
        if (is_call) setr(1u,at+8u);
        pc=target; return 1;
    }
    if (opmatch(w,0x40000000u,0xbc000000u)) {
        target=r[s1]; rc=exec_delay(at+4u); if (rc<=0) return rc; pc=target; return 1;
    }
    if (opmatch(w,0x4c000002u,0xb000001du)) {
        target=r[s1]; setr(1u,at+8u); rc=exec_delay(at+4u); if (rc<=0) return rc; pc=target; return 1;
    }
    if (opmatch(w,0x74000000u,0x88000000u) || opmatch(w,0x7c000000u,0x80000000u)) {
        cond=opmatch(w,0x74000000u,0x88000000u) ? (cc!=0u) : (cc==0u);
        target=at+4u+(u32)(sx26(w)*4);
        /* bc.t/bnc.t execute the delay-slot instruction only when the
           branch is taken.  A not-taken branch skips directly to at+8. */
        if (cond) { rc=exec_delay(at+4u); if (rc<=0) return rc; pc=target; }
        else pc=at+8u;
        return 1;
    }
    /* bla: branch on old LCC, add, then install the comparison-derived
       new LCC after the delay slot. */
    if (opmatch(w,0xb4000000u,0x48000000u)) {
        u32 old_lcc,sum,s2,src1v,orig2,new_lcc;
        s2=(w>>21)&31u; src1v=r[(w>>11)&31u]; orig2=r[s2]; old_lcc=lcc;
        /* i860 definition: new LCC = signed(old src2) >= -signed(src1).
           Compute the negation in unsigned space to avoid host signed-overflow UB. */
        new_lcc=((s32)orig2 >= (s32)(0u-src1v)) ? 1u : 0u;
        sum=orig2+src1v;
        setr(s2,sum);
        target=at+4u+(u32)(split16(w)*4);
        rc=exec_delay(at+4u); if (rc<=0) return rc;
        lcc=new_lcc;
        pc=old_lcc ? target : at+8u; return 1;
    }
    /* i860 System V host traps. R8 preserves live-proven write(4) and close(6)
       and adds only exit(1). Standard descriptors remain logical guest state:
       guest close does not destroy Win32 console HANDLEs needed for diagnostics. */
    if (opmatch(w,0x44000000u,0xb8000000u)) {
        if (r[31]==1u) {
            ++exit_traps;
            guest_exit_status=r[16] & 0xffu;
            pc=at+4u;
            return 2;
        }
        if (r[31]==3u) {
            u8 *p; u32 rv,fd;
            fd=r[16]; p=guest_ptr(r[17],r[18],1);
            ++read_traps;
            if (!p && r[18]!=0u) return -1;
            rv=host_read_fd(fd,p,r[18]);
            if (rv==0xffffffffu) { r[16]=5u; cc=1u; }
            else { r[16]=rv; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==4u) {
            u8 *p; u32 rv,fd;
            fd=r[16];
            if (fd<=2u && (std_open_mask & (1u<<fd))==0u) { r[16]=9u; cc=1u; pc=at+4u; return 1; }
            p=guest_ptr(r[17],r[18],0);
            if (!p && r[18]!=0u) return -1;
            rv=host_write_fd(fd,p,r[18]);
            ++write_traps;
            if (rv==0xffffffffu) { r[16]=5u; cc=1u; }
            else { r[16]=rv; write_bytes+=rv; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==5u) {
            const char *path; u32 rv; int is_dir;
            ++open_traps; path=guest_host_path(r[16],&is_dir);
            if (!path) return -1;
            rv=host_open_file(path,r[17],r[18]);
            if (rv==0xffffffffu) { r[16]=2u; cc=1u; }
            else { r[16]=rv; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==6u) {
            u32 fd; fd=r[16]; ++close_traps;
            if (fd<=2u && (std_open_mask & (1u<<fd))!=0u) {
                std_open_mask &= ~(1u<<fd); r[16]=0u; cc=0u; pc=at+4u; return 1;
            }
            if (fd>2u && host_close_fd(fd)==0u) { r[16]=0u; cc=0u; pc=at+4u; return 1; }
            r[16]=9u; cc=1u; pc=at+4u; return 1;
        }
        if (r[31]==8u) {
            const char *path; u32 rv; int is_dir;
            ++creat_traps; path=guest_host_path(r[16],&is_dir);
            if (!path) return -1;
            rv=host_creat_file(path,r[17]);
            if (rv==0xffffffffu) { r[16]=5u; cc=1u; }
            else { r[16]=rv; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==10u) {
            const char *path; u32 rv; int is_dir;
            ++unlink_traps; path=guest_host_path(r[16],&is_dir);
            if (!path) return -1;
            rv=host_unlink_file(path);
            if (rv==0xffffffffu) { r[16]=2u; cc=1u; }
            else { r[16]=0u; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==13u) {
            u32 now;
            ++time_traps; now=631152000u;
            if (r[16]!=0u && !write_mem(r[16],4u,now)) return -1;
            r[16]=now; cc=0u; pc=at+4u; return 1;
        }
        if (r[31]==17u) {
            u32 req;
            req=r[16]; ++brk_traps;
            if (req>=brk_floor && req<i860_data_guest+i860_low_size) {
                brk_current=req; r[16]=0u; cc=0u; pc=at+4u; return 1;
            }
            r[16]=12u; cc=1u; pc=at+4u; return 1;
        }
        if (r[31]==18u) {
            const char *path; u32 fd,sz; int is_dir;
            ++stat_traps; path=guest_host_path(r[16],&is_dir);
            if (!path) return -1;
            if (is_dir) {
                if (!guest_store_stat(r[17],0u,0x41ffu)) { r[16]=14u; cc=1u; }
                else { r[16]=0u; cc=0u; }
                pc=at+4u; return 1;
            }
            fd=host_open_file(path,0u,0u);
            if (fd==0xffffffffu) { r[16]=2u; cc=1u; pc=at+4u; return 1; }
            sz=host_filesize_fd(fd); (void)host_close_fd(fd);
            if (sz==0xffffffffu || !guest_store_stat(r[17],sz,0x81b6u)) { r[16]=5u; cc=1u; }
            else { r[16]=0u; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==19u) {
            u32 rv;
            ++lseek_traps; rv=host_lseek_fd(r[16],r[17],r[18]);
            if (rv==0xffffffffu) { r[16]=22u; cc=1u; }
            else { r[16]=rv; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==28u) {
            u32 sz,mode;
            ++fstat_traps;
            if (r[16]<=2u) { sz=0u; mode=0x21b6u; }
            else { sz=host_filesize_fd(r[16]); mode=0x81b6u; }
            if (sz==0xffffffffu || !guest_store_stat(r[17],sz,mode)) { r[16]=9u; cc=1u; }
            else { r[16]=0u; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==20u) {
            ++getpid_traps; r[16]=1u; cc=0u; pc=at+4u; return 1;
        }
        if (r[31]==24u) {
            ++getuid_traps; r[16]=0u; cc=0u; pc=at+4u; return 1;
        }
        if (r[31]==33u) {
            const char *path; u32 fd; int is_dir;
            ++access_traps; path=guest_host_path(r[16],&is_dir);
            if (!path) return -1;
            if (is_dir) { r[16]=0u; cc=0u; pc=at+4u; return 1; }
            fd=host_open_file(path,0u,0u);
            if (fd==0xffffffffu) { r[16]=2u; cc=1u; }
            else { (void)host_close_fd(fd); r[16]=0u; cc=0u; }
            pc=at+4u; return 1;
        }
        if (r[31]==47u) {
            ++getgid_traps; r[16]=0u; cc=0u; pc=at+4u; return 1;
        }
        if (r[31]==48u) {
            /* Match the already-proven outer SVR3 personality policy: accept
               signal disposition registration, but provide no async delivery. */
            ++signal_traps; r[16]=0u; cc=0u; pc=at+4u; return 1;
        }
        if (r[31]==57u) {
            /* SCO/SVR3 utssys(buf,0,0): the uname form.  Return a deterministic
               classic five-by-nine-byte struct utsname, not modern host data. */
            ++utssys_traps;
            if (r[17]==0u && r[18]==0u && guest_store_utsname(r[16])) {
                r[16]=0u; cc=0u; pc=at+4u; return 1;
            }
            r[16]=14u; cc=1u; pc=at+4u; return 1;
        }
        return 0;
    }
    return exec_noncontrol(at,w);
}

static void observe_inner_target(void)
{
    u32 ipc;
    if (!read_mem(INNER_PC_ADDR,4u,&ipc)) return;
    if (ipc==TARGET_ENTRY_PC && !inner_entry_seen) { inner_entry_seen=1u; inner_entry_count=icount; }
    if (ipc==TARGET_LOOP_PC && !inner_loop_cc_seen) { inner_loop_cc_seen=1u; inner_loop_cc_count=icount; }
    if (ipc==TARGET_DELAY_PC && !inner_loop_d0_seen) { inner_loop_d0_seen=1u; inner_loop_d0_count=icount; }
}

int i860_run(void)
{
    u32 i,w; int rc;
    for (i=0u;i<32u;i++) { r[i]=0u; f[i]=0u; }
    for (i=0u;i<16u;i++) cr[i]=0u;
    cc=0u; lcc=0u; startup_argc=0u; icount=0u; fault_addr=0u; fault_kind=0u;
    write_traps=0u; write_bytes=0u; close_traps=0u; signal_traps=0u; utssys_traps=0u; brk_traps=0u;
    read_traps=0u; open_traps=0u; creat_traps=0u; unlink_traps=0u; time_traps=0u; stat_traps=0u; lseek_traps=0u; fstat_traps=0u;
    access_traps=0u; getpid_traps=0u; getuid_traps=0u; getgid_traps=0u; exit_traps=0u; guest_exit_status=0u; std_open_mask=7u;
    inner_entry_seen=0u; inner_loop_cc_seen=0u; inner_loop_d0_seen=0u;
    inner_entry_count=0u; inner_loop_cc_count=0u; inner_loop_d0_count=0u;
    brk_floor=i860_data_guest+i860_data_size+i860_bss_size; brk_current=brk_floor;
    r[2]=i860_stack_guest+i860_stack_size-16u;
    if (!setup_startup()) {
        host_puts_err("SIM860 R10: unable to construct i860 argc/argv/envp startup state\r\n");
        return 1;
    }
    startup_argc=r[16];
    pc=i860_entry;

    host_puts_out("SIM860 R10: i860 entry=0x"); host_puthex32(pc);
    host_puts_out(" synthetic-sp=0x"); host_puthex32(r[2]);
    host_puts_out(" argc=0x"); host_puthex32(r[16]);
    host_puts_out(" argv=0x"); host_puthex32(r[17]);
    host_puts_out(" envp=0x"); host_puthex32(r[18]); host_puts_out("\r\n");

    for (i=0u;i<STEP_LIMIT;i++) {
        rc=step_one();
        observe_inner_target();
        if (rc<0) {
            host_puts_err("SIM860 R10: i860 MEMORY FAULT kind=0x"); host_puthex32(fault_kind);
            host_puts_err(" address=0x"); host_puthex32(fault_addr); host_puts_err(" pc=0x"); host_puthex32(pc); host_puts_err("\r\n");
            return 1;
        }
        if (rc==2) {
            host_puts_out("SIM860 R10: i860 System V exit(1) serviced at pc=0x"); host_puthex32(pc-4u);
            host_puts_out(" count=0x"); host_puthex32(icount);
            host_puts_out(" status=0x"); host_puthex32(guest_exit_status); host_puts_out("\r\n");
            host_puts_out("SIM860 R10: serviced write(4) traps=0x"); host_puthex32(write_traps);
            host_puts_out(" bytes=0x"); host_puthex32(write_bytes);
            host_puts_out(" close(6) traps=0x"); host_puthex32(close_traps);
            host_puts_out(" signal(48) traps=0x"); host_puthex32(signal_traps);
            host_puts_out(" utssys(57) traps=0x"); host_puthex32(utssys_traps);
            host_puts_out(" brk(17) traps=0x"); host_puthex32(brk_traps);
            host_puts_out(" read(3)=0x"); host_puthex32(read_traps);
            host_puts_out(" open(5)=0x"); host_puthex32(open_traps);
            host_puts_out(" creat(8)=0x"); host_puthex32(creat_traps);
            host_puts_out(" unlink(10)=0x"); host_puthex32(unlink_traps);
            host_puts_out(" time(13)=0x"); host_puthex32(time_traps);
            host_puts_out(" stat(18)=0x"); host_puthex32(stat_traps);
            host_puts_out(" lseek(19)=0x"); host_puthex32(lseek_traps);
            host_puts_out(" fstat(28)=0x"); host_puthex32(fstat_traps);
            host_puts_out(" access(33)=0x"); host_puthex32(access_traps);
            host_puts_out(" getpid(20)=0x"); host_puthex32(getpid_traps);
            host_puts_out(" getuid(24)=0x"); host_puthex32(getuid_traps);
            host_puts_out(" getgid(47)=0x"); host_puthex32(getgid_traps);
            host_puts_out(" exit(1) traps=0x"); host_puthex32(exit_traps); host_puts_out("\r\n");
            if (startup_argc==1u) {
                if ((pc-4u)==EXPECT_PC && icount==EXPECT_COUNT && guest_exit_status==3u &&
                    write_traps==EXPECT_WRITE_TRAPS && write_bytes==EXPECT_WRITE_TRAPS &&
                    close_traps==EXPECT_CLOSE_TRAPS && signal_traps==EXPECT_SIGNAL_TRAPS &&
                    utssys_traps==0u && brk_traps==0u &&
                    exit_traps==1u && std_open_mask==0u) {
                    host_puts_out("SIM860 R10: N1.3 USAGE/EXIT PASS; guest process completed with status 3\r\n");
                    return 0x100u + guest_exit_status;
                }
                host_puts_err("SIM860 R10: guest exit observed but no-argument oracle differed; SIM860 R10 FAIL\r\n");
                return 1;
            }
            host_puts_out("SIM860 R10: guest process completed cleanly with status 0x");
            host_puthex32(guest_exit_status); host_puts_out("\r\n");
            return 0x100u + guest_exit_status;
        }
        if (rc==0) {
            if (!read_mem(pc,4u,&w)) w=0u;
            host_puts_out("SIM860 R10: first unsupported i860 instruction/service pc=0x"); host_puthex32(pc);
            host_puts_out(" insn=0x"); host_puthex32(w); host_puts_out(" count=0x"); host_puthex32(icount); host_puts_out("\r\n");
            if (opmatch(w,0x44000000u,0xb8000000u)) {
                host_puts_out("SIM860 R10: UNKNOWN TRAP state r31=0x"); host_puthex32(r[31]);
                host_puts_out(" r16=0x"); host_puthex32(r[16]);
                host_puts_out(" r17=0x"); host_puthex32(r[17]);
                host_puts_out(" r18=0x"); host_puthex32(r[18]);
                host_puts_out(" r19=0x"); host_puthex32(r[19]); host_puts_out("\r\n");
                host_puts_out("SIM860 R10: additional trap args r20=0x"); host_puthex32(r[20]);
                host_puts_out(" r21=0x"); host_puthex32(r[21]);
                host_puts_out(" r22=0x"); host_puthex32(r[22]);
                host_puts_out(" r23=0x"); host_puthex32(r[23]); host_puts_out("\r\n");
            }
            host_puts_err("SIM860 R10: unexpected unsupported opcode/service before clean guest exit; SIM860 R10 FAIL\r\n");
            return 1;
        }
    }
    if (startup_argc>1u && open_traps>=2u && read_traps>=6u && lseek_traps>=3u &&
        brk_traps>=5u && signal_traps>=3u) {
        u32 inner_pc,ir16,ir17,ir18;
        if (!read_mem(INNER_PC_ADDR,4u,&inner_pc) ||
            !read_mem(INNER_REG_BASE+16u*4u,4u,&ir16) ||
            !read_mem(INNER_REG_BASE+17u*4u,4u,&ir17) ||
            !read_mem(INNER_REG_BASE+18u*4u,4u,&ir18)) {
            host_puts_err("SIM860 R10: unable to inspect inner target state\r\n");
            return 1;
        }
        host_puts_out("SIM860 R10: bounded execution limit reached after loading target; no unsupported opcode/service observed\r\n");
        host_puts_out("SIM860 R10: bounded i860 interpreter count=0x"); host_puthex32(icount);
        host_puts_out(" outer-pc=0x"); host_puthex32(pc); host_puts_out("\r\n");
        host_puts_out("SIM860 R10: loader/runtime evidence open=0x"); host_puthex32(open_traps);
        host_puts_out(" read=0x"); host_puthex32(read_traps);
        host_puts_out(" lseek=0x"); host_puthex32(lseek_traps);
        host_puts_out(" brk=0x"); host_puthex32(brk_traps);
        host_puts_out(" signal=0x"); host_puthex32(signal_traps); host_puts_out("\r\n");
        host_puts_out("SIM860 R10: target entry F04000C0 observed at outer-count=0x"); host_puthex32(inner_entry_count); host_puts_out("\r\n");
        host_puts_out("SIM860 R10: target loop PCs observed F04000CC count=0x"); host_puthex32(inner_loop_cc_count);
        host_puts_out(" F04000D0 count=0x"); host_puthex32(inner_loop_d0_count); host_puts_out("\r\n");
        host_puts_out("SIM860 R10: inner target state pc=0x"); host_puthex32(inner_pc);
        host_puts_out(" r16=0x"); host_puthex32(ir16);
        host_puts_out(" r17=0x"); host_puthex32(ir17);
        host_puts_out(" r18=0x"); host_puthex32(ir18); host_puts_out("\r\n");
        if (inner_entry_seen && inner_loop_cc_seen && inner_loop_d0_seen &&
            ir16==10u && ir17==20u && ir18==30u &&
            (inner_pc==TARGET_LOOP_PC || inner_pc==TARGET_DELAY_PC)) {
            host_puts_out("SIM860 R10: INNER TARGET STATE PASS: entry reached, r18=30, loop executing\r\n");
            return 0x100u;
        }
        host_puts_err("SIM860 R10: inner target state oracle mismatch\r\n");
        return 1;
    }
    host_puts_err("SIM860 R10: i860 step limit reached without sufficient target-load evidence\r\n");
    return 1;
}
'''

def assemble_host(builddir, asm, cpu, host_va, data_va):
    asm_path=builddir/'sim860-r10-host.S'; cpu_path=builddir/'sim860-r10-cpu.c'
    aobj=builddir/'sim860-r10-host.o'; cobj=builddir/'sim860-r10-cpu.o'; elf=builddir/'sim860-r10-host.elf'
    raw_text=builddir/'sim860-r10-host.text.bin'; raw_data=builddir/'sim860-r10-host.data.bin'
    asm_path.write_text(asm); cpu_path.write_text(cpu)
    subprocess.run(['as','--32','-o',str(aobj),str(asm_path)],check=True)
    subprocess.run(['gcc','-m32','-std=c89','-Wall','-Wextra','-Werror','-Os','-march=i386','-mno-sse','-mno-mmx','-ffreestanding','-fno-pic','-fno-pie','-fno-stack-protector','-fno-asynchronous-unwind-tables','-fno-unwind-tables','-fno-ident','-nostdlib','-c',str(cpu_path),'-o',str(cobj)],check=True)
    und=subprocess.run(['nm','-u',str(cobj)],capture_output=True,text=True,check=True).stdout
    allowed={'host_puts_out','host_puts_err','host_puthex32','i860_text_size','i860_data_size','i860_bss_size','i860_entry','i860_text_guest','i860_data_guest','i860_low_size','i860_text_host','i860_data_host','i860_stack_guest','i860_stack_size','i860_stack_host','i860_run860_argv','host_write_fd','host_read_fd','host_open_file','host_creat_file','host_close_fd','host_lseek_fd','host_unlink_file','host_filesize_fd'}
    got=set()
    for line in und.splitlines():
        parts=line.split()
        if parts: got.add(parts[-1])
    bad=got-allowed
    if bad: raise RuntimeError('unexpected C runtime dependencies: '+repr(sorted(bad)))
    lds=builddir/'sim860-r10-host.ld'
    lds.write_text('SECTIONS { . = 0x%08x; .text : { *(.text*) *(.rodata*) } . = 0x%08x; .data : { *(.data*) *(.bss*) *(COMMON) } /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.got*) } }\n'%(host_va,data_va))
    subprocess.run(['ld','--build-id=none','-m','elf_i386','-T',str(lds),'-o',str(elf),str(aobj),str(cobj)],check=True)
    rr=subprocess.run(['readelf','-r',str(elf)],capture_output=True,text=True,check=True).stdout
    if 'There are no relocations' not in rr:
        raise RuntimeError('host ELF still has relocations:\n'+rr)
    subprocess.run(['objcopy','-O','binary','--only-section=.text',str(elf),str(raw_text)],check=True)
    subprocess.run(['objcopy','-O','binary','--only-section=.data',str(elf),str(raw_data)],check=True)
    return raw_text.read_bytes(), raw_data.read_bytes(), asm_path, cpu_path, elf

def build_pe(sections, imp, header_overlay=None):
    # sections: list name,data,rva,chars
    nsec=len(sections); peoff=0x80
    min_headers=peoff+4+20+0xe0+nsec*40
    size_headers=max(0x1000, align(min_headers,FILE_ALIGN))
    ro=size_headers; rows=[]
    for name,data,rva,chars in sections:
        rawsize=align(len(data),FILE_ALIGN) if data else 0
        rows.append((name,data,rva,chars,ro if rawsize else 0,rawsize)); ro+=rawsize
    size_image=align(max(rva+max(1,len(data)) for name,data,rva,chars in sections),SECT_ALIGN)
    dos=bytearray(0x80); dos[:2]=b'MZ'; struct.pack_into('<H',dos,2,0x90); struct.pack_into('<H',dos,4,3); struct.pack_into('<H',dos,8,4); struct.pack_into('<H',dos,0x18,0x40); struct.pack_into('<L',dos,0x3c,peoff)
    msg=b'This program requires Windows.\r\n$'; dos[0x40:0x40+len(msg)]=msg
    out=bytearray(dos); out+=b'PE\0\0'
    out+=struct.pack('<HHLLLHH',0x14c,nsec,0,0,0,0xe0,0x010f)
    size_code=sum(rs for n,d,r,c,o,rs in rows if c&0x20)
    size_init=sum(rs for n,d,r,c,o,rs in rows if c&0x40)
    opt=bytearray(0xe0)
    # AddressOfEntryPoint remains the host bootstrap.  BaseOfCode/BaseOfData
    # must describe the first actual code/data sections; native Windows is
    # stricter than Wine about these optional-header invariants.
    code_rvas=[rva for name,data,rva,chars in sections if chars&0x20]
    data_rvas=[rva for name,data,rva,chars in sections if chars&0x40]
    base_code=min(code_rvas) if code_rvas else 0
    base_data=min(data_rvas) if data_rvas else 0
    struct.pack_into('<HBBLLLLLL',opt,0,0x10b,0,3,size_code,size_init,0,HOST_RVA,base_code,base_data)
    struct.pack_into('<LL',opt,28,IMAGE_BASE,SECT_ALIGN); struct.pack_into('<L',opt,36,FILE_ALIGN)
    struct.pack_into('<HHHHHH',opt,40,4,0,0,0,4,0)
    struct.pack_into('<LL',opt,56,size_image,size_headers); struct.pack_into('<HH',opt,68,3,0)
    struct.pack_into('<LLLLLL',opt,72,0x100000,0x1000,0x100000,0x1000,0,16)
    struct.pack_into('<LL',opt,96+8,imp['import_directory_rva'],imp['import_directory_size'])
    struct.pack_into('<LL',opt,96+12*8,imp['iat_rva'],imp['iat_size'])
    out+=opt
    for name,data,rva,chars,raw,rawsize in rows:
        out+=struct.pack('<8sLLLLLLHHL',name.encode()[:8].ljust(8,b'\0'),len(data),rva,rawsize,raw,0,0,0,0,chars)
    if len(out)>size_headers: raise RuntimeError('headers overflow reserved header page')
    out+=b'\0'*(size_headers-len(out))
    if header_overlay:
        off,blob=header_overlay
        if off < min_headers or off+len(blob)>size_headers:
            raise RuntimeError('header overlay does not fit safely')
        out[off:off+len(blob)]=blob
    for name,data,rva,chars,raw,rawsize in rows:
        if rawsize:
            assert len(out)==raw
            out+=data+b'\0'*(rawsize-len(data))
    return bytes(out), rows, size_image

def parse_pe_sections(pe):
    peoff=struct.unpack_from('<L',pe,0x3c)[0]; machine,nsec,_,_,_,optsz,_=struct.unpack_from('<HHLLLHH',pe,peoff+4); sh=peoff+24+optsz
    out=[]
    for i in range(nsec):
        r=struct.unpack_from('<8sLLLLLLHHL',pe,sh+i*40)
        out.append({'name':r[0].split(b'\0',1)[0].decode(),'vsize':r[1],'rva':r[2],'raw_size':r[3],'raw_offset':r[4],'chars':r[9]})
    return out

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('input'); ap.add_argument('--outdir',default='artifacts'); ap.add_argument('--builddir',default='build'); args=ap.parse_args()
    src=Path(args.input); outdir=Path(args.outdir); builddir=Path(args.builddir); outdir.mkdir(parents=True,exist_ok=True); builddir.mkdir(parents=True,exist_ok=True)
    data=src.read_bytes(); outer=parse_coff(data,0)
    if outer['magic']!=I386MAGIC: raise SystemExit('outer is not i386 COFF')
    split=coff_extent(outer); inner=parse_coff(data,split)
    if inner['magic']!=I860MAGIC: raise SystemExit('appended payload is not i860 COFF at expected split')
    wrapper=data[:split]; payload=data[split:]; text=secbytes(data,outer,'.text'); dat=secbytes(data,outer,'.data')
    if outer['optional_common']['entry']!=OLD_ENTRY or outer['optional_common']['text_start']!=OLD_TEXT_VA or outer['optional_common']['data_start']!=OLD_DATA_VA: raise SystemExit('oracle layout changed')

    idata,imp=make_idata(IDATA_RVA,FUNCS)
    iat_abs={fn:IMAGE_BASE+rva for fn,rva in imp['iat_entries'].items()}
    asm=asm_source(iat_abs,len(payload))
    cpu=cpu_source()
    host,hdata,asm_path,cpu_path,host_elf=assemble_host(builddir,asm,cpu,IMAGE_BASE+HOST_RVA,IMAGE_BASE+HOSTDATA_RVA)
    if len(host)>(HOSTDATA_RVA-HOST_RVA): raise SystemExit('host code overlaps host data: %d'%len(host))
    if len(hdata)>(SVTEXT_RVA-HOSTDATA_RVA): raise SystemExit('host data overlaps SVR3 text: %d'%len(hdata))

    # Extract linked symbol values for gates from ELF.
    nm=subprocess.run(['nm','-n',str(host_elf)],capture_output=True,text=True,check=True).stdout.splitlines()
    syms={}
    for line in nm:
        parts=line.split()
        if len(parts)>=3:
            try: syms[parts[2]]=int(parts[0],16)
            except ValueError: pass
    for req in ['host_entry','svr3_gate7','svr3_gate15']:
        if req not in syms: raise RuntimeError('missing host symbol '+req)
    if syms['host_entry']!=IMAGE_BASE+HOST_RVA: raise RuntimeError('host entry not section start')
    patched,patches,delta=patch_text(text,syms['svr3_gate7'],syms['svr3_gate15'])

    header_data_off=OLD_DATA_VA-IMAGE_BASE
    assert header_data_off==0x958
    assert header_data_off+len(dat)<=0x1000

    meta_base={
      'milestone':'SIM860-PE-R10',
      'policy':'SIM860 R10 implements the complete statically linked i860 SVR3 syscall surface used by Intel AS860 N1.3, binary-safe Win32 file I/O with small guest descriptor numbers, historical temp-path compatibility, and the additional i860 CPU semantics actually reached by a real source assembly. The loop.s oracle must produce a real i860 COFF object and exit status 0.',
      'input':{'name':src.name,'size':len(data),'sha256':sha256(data)},
      'split':{'wrapper_size':len(wrapper),'wrapper_sha256':sha256(wrapper),'payload_offset':split,'payload_size':len(payload),'payload_sha256':sha256(payload)},
      'layout':{'image_base':IMAGE_BASE,'host_va':IMAGE_BASE+HOST_RVA,'host_data_va':IMAGE_BASE+HOSTDATA_RVA,'relocated_text_va':IMAGE_BASE+SVTEXT_RVA,'old_text_va':OLD_TEXT_VA,'text_delta':delta,'old_data_va':OLD_DATA_VA,'old_data_storage':'PE header page at file/RVA offset 0x958','relocated_entry_va':IMAGE_BASE+SVTEXT_RVA+(OLD_ENTRY-OLD_TEXT_VA),'gate7_va':syms['svr3_gate7'],'gate15_va':syms['svr3_gate15']},
      'imports':FUNCS,
      'run860_shim':{'payload_va':IMAGE_BASE+I860_RVA,'payload_size':len(payload),'behavior':'synthetic access(run860) success; execve(run860) parses/materializes embedded i860 COFF, allocates low guest memory and stack, copies wrapper-supplied arguments, and starts bounded i860 execution'},
      'i860_cpu_sim860_r10':{
        'stack_guest':0x7fff0000,'stack_size':0x00010000,'trace_limit':24,'step_limit':1000000,'floating_registers':32,
        'startup':'r16=argc, r17=argv, r18=envp; guest argv copied from run860 argv[1..]; guest envp contains PATH=.',
        'control_flow_fixes':['relative call writes r1 after its delay slot','bc.t/bnc.t execute delay slot only when taken','bla branches on old LCC and installs comparison-derived new LCC after delay slot'],
        'additional_cpu_ops':['ixfr','fxfr','fmlow.dd','bla','fld.l/d/q','fst.l/d/q','fiadd.ss/fmov.ss','fsub.dd','frcp.dd','fmul.dd','ftrunc.dd'],
        'file_personality':'small guest fds 3..63 backed by private Win32 HANDLE table; raw CreateFileA/ReadFile/WriteFile/SetFilePointer; no CRT text translation',
        'temp_paths':'/usr/tmp and /tmp directory probes map to the current private working namespace; temporary basenames stay local',
        'stat_layout':'SVR3 compact 32-byte guest struct stat with deterministic 1990 timestamps',
        'linked_loop_oracle':{'target_name':'loop','target_sha256':'85b2531a8501e67731703cc2856515080338795d221b00c2985e83298e277528','target_size':426,'bounded_instruction_service_count':1114349,'bounded_outer_pc':0xF040BD98,'dynamic_syscalls':{'3_read':6,'4_write':84,'5_open':2,'17_brk':5,'19_lseek':3,'48_signal':3},'behavior':'after loading the linked infinite-loop i860 executable, the simulator runs to the bounded interpreter limit with no unsupported opcode or service','inner_state_oracle':{'pc_address':0x0001A760,'gpr_base':0x0001A5D0,'entry':0xF04000C0,'loop_pc':0xF04000CC,'delay_pc':0xF04000D0,'expected_r16':10,'expected_r17':20,'expected_r18':30}}
      },
      'i860_syscalls_implemented':{'1':'exit','3':'read','4':'write','5':'open','6':'close','8':'creat','10':'unlink','13':'time','17':'break/brk','18':'stat','19':'lseek','20':'getpid','24':'getuid','28':'fstat','33':'access','47':'getgid','48':'signal (stub-success; no async delivery)','57':'utssys/uname'},
      'outer_svr3_personality':'preserves the established wrapper-side access/execve/run860 handoff and narrow historical syscall veneer',
      'patches':patches,
    }
    meta_json=json.dumps(meta_base,sort_keys=True,indent=2).encode()+b'\n'
    meta_rva=align(I860_RVA+len(payload),SECT_ALIGN)
    orig_rva=align(meta_rva+len(meta_json),SECT_ALIGN)
    sections=[
      ('.host',host,HOST_RVA,0x60000020),
      ('.hdata',hdata,HOSTDATA_RVA,0xC0000040),
      ('.svtext',patched,SVTEXT_RVA,0x60000020),
      ('.idata',idata,IDATA_RVA,0x40000040),
      ('.i860',payload,I860_RVA,0x40000040),
      ('.meta',meta_json,meta_rva,0x40000040),
      ('.orig386',wrapper,orig_rva,0x40000040),
    ]
    pe,rows,size_image=build_pe(sections,imp,(header_data_off,dat))

    # Static verification.
    rowmap={r['name']:r for r in parse_pe_sections(pe)}
    def pe_slice(name):
        r=rowmap[name]; return pe[r['raw_offset']:r['raw_offset']+r['vsize']]
    checks=[]
    checks.append({'name':'original-wrapper-preserved','pass':pe_slice('.orig386')==wrapper})
    checks.append({'name':'i860-payload-preserved','pass':pe_slice('.i860')==payload})
    checks.append({'name':'original-data-at-exact-va-in-header','pass':pe[header_data_off:header_data_off+len(dat)]==dat and IMAGE_BASE+header_data_off==OLD_DATA_VA})
    checks.append({'name':'host-code-not-writable','pass':(rowmap['.host']['chars'] & 0x80000000)==0})
    checks.append({'name':'host-data-not-executable','pass':(rowmap['.hdata']['chars'] & 0x20000000)==0})
    pt=pe_slice('.svtext')
    checks.append({'name':'patched-text-same-size','pass':len(pt)==len(text)})
    checks.append({'name':'no-lcall-7-remains','pass':b'\x9a\0\0\0\0\x07\0' not in pt})
    checks.append({'name':'no-lcall-15-remains','pass':b'\x9a\0\0\0\0\x0f\0' not in pt})
    if not all(c['pass'] for c in checks): raise RuntimeError('verification failed: '+repr(checks))

    report=dict(meta_base); report['output']={'name':'sim860-r10.exe','size':len(pe),'sha256':sha256(pe),'size_of_image':size_image,'sections':rowmap,'checks':checks}
    (outdir/'sim860-r10.exe').write_bytes(pe)
    (outdir/'sim860-r10-report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    (outdir/'sim860-r10-host.S').write_text(asm)
    (outdir/'sim860-r10-cpu.c').write_text(cpu)
    (outdir/'sim860.wrapper386.coff').write_bytes(wrapper)
    (outdir/'sim860.payload.i860.coff').write_bytes(payload)
    sums=[]
    for fn in ['sim860-r10.exe','sim860-r10-report.json','sim860-r10-host.S','sim860-r10-cpu.c','sim860.wrapper386.coff','sim860.payload.i860.coff']:
        p=outdir/fn; sums.append('%s  %s'%(sha256(p.read_bytes()),fn))
    (outdir/'SHA256SUMS.txt').write_text('\n'.join(sums)+'\n')
    print(json.dumps(report['output'],indent=2))

if __name__=='__main__': main()
