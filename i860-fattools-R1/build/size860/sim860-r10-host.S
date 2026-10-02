/* I860FAT R1 host personality. 32-bit x86, Intel syntax. */
.intel_syntax noprefix
.code32
.equ IAT_GetStdHandle, 0x00409068
.equ IAT_WriteFile, 0x0040906c
.equ IAT_ExitProcess, 0x00409070
.equ IAT_GetCommandLineA, 0x00409074
.equ IAT_GetFileAttributesA, 0x00409078
.equ IAT_CreateFileA, 0x0040907c
.equ IAT_ReadFile, 0x00409080
.equ IAT_CloseHandle, 0x00409084
.equ IAT_DeleteFileA, 0x00409088
.equ IAT_GetFileSize, 0x0040908c
.equ IAT_SetFilePointer, 0x00409090
.equ IAT_VirtualProtect, 0x00409094
.equ IAT_VirtualAlloc, 0x00409098
.equ IAT_GetEnvironmentStringsA, 0x0040909c
.equ IAT_GetEnvironmentVariableA, 0x004090a0
.equ SV_ENTRY, 0x00408004
.equ STD_INPUT_HANDLE,  -10
.equ STD_OUTPUT_HANDLE, -11
.equ STD_ERROR_HANDLE,  -12
.equ INVALID_HANDLE_VALUE, -1
.equ I860_PAYLOAD, 0x0040a000
.equ I860_PAYLOAD_SIZE, 0x000091d2
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

    /* Host scaffolding is quiet unless I860_VERBOSE is set to a nonzero value. */
    push 16
    push OFFSET FLAT:verbose_env_buf
    push OFFSET FLAT:verbose_env_name
    call DWORD PTR ds:[IAT_GetEnvironmentVariableA]
    test eax,eax
    jz i860_verbose_checked
    cmp BYTE PTR [verbose_env_buf],'0'
    je i860_verbose_checked
    mov DWORD PTR [verbose_flag],1
i860_verbose_checked:

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
       replacement CALL return 0x00408045 (old gate at 0x110 + 5-byte CALL). */
    cmp eax,0x00408045
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
    cmp DWORD PTR [edi+4],0x00000074  /* "t\0\0\0" */
    jne r860_bad_coff
    cmp DWORD PTR [edi+40],0x7461642e /* ".dat" */
    jne r860_bad_coff
    cmp DWORD PTR [edi+44],0x00000061 /* "a\0\0\0" */
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
.global host_force_verbose
host_force_verbose:
    mov DWORD PTR [verbose_flag],1
    ret

host_puts_out:
    cmp DWORD PTR [verbose_flag],0
    je host_puts_out_quiet
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
host_puts_out_quiet:
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
verbose_flag: .long 0
native_brk: .long 0
verbose_env_name: .asciz "I860_VERBOSE"
verbose_env_buf: .space 16
.balign 4
/* Guest descriptor table. Slots 0..2 are reserved for stdio and handled
   specially; slots 3..63 hold opaque Win32 HANDLE values. */
fd_table: .space 64*4
io_count: .long 0
argc_store: .long 0
old_protect: .long 0
banner: .asciz "I860FAT R1: entering original UNIX System V/386 wrapper\r\n"
bad_cmd: .asciz "I860FAT R1: command line too long\r\n"
unknown_msg: .asciz "I860FAT R1: unhandled SVR3 syscall; aborting\r\n"
gate15_msg: .asciz "I860FAT R1: selector 0x0F signal trampoline reached unexpectedly\r\n"
exec_prefix: .asciz "I860FAT R1: historical execve reached non-run860 target: "
exec_suffix: .asciz "I860FAT R1: generic second-image chaining is not implemented.\r\n"
crlf: .asciz "\r\n"
run860_banner: .asciz "I860FAT R1: untouched wrapper requested run860; entering in-process execution vehicle\r\n"
target_prefix: .asciz "I860FAT R1: run860 target argv[1] = "
coff_ok: .asciz "I860FAT R1: embedded i860 COFF validated (magic 014D, 3 sections)\r\n"
text_prefix: .asciz "I860FAT R1: text guest=0x"
data_prefix: .asciz "I860FAT R1: data guest=0x"
size_prefix: .asciz " size=0x"
bss_prefix: .asciz " bss=0x"
entry_prefix: .asciz "I860FAT R1: entry guest=0x"
entry_off_prefix: .asciz " text+0x"
cpu_start_banner: .asciz "I860FAT R1: RUN860 LOAD PASS; starting bounded i860 CPU core\r\n"
bad_argv: .asciz "I860FAT R1: run860 argv contract invalid\r\n"
bad_coff: .asciz "I860FAT R1: embedded i860 COFF validation failed\r\n"
bad_entry: .asciz "I860FAT R1: i860 entry point is outside .text\r\n"
no_memory: .asciz "I860FAT R1: unable to allocate i860 guest backing memory\r\n"
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
fallback_argv0: .asciz "size860.exe"
.balign 4
argv_vec: .space 64*4
cmd_buf: .space 4096
cmd_buf_end:
