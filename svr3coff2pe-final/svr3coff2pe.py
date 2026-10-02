#!/usr/bin/env python3
"""SVR3COFF2PE R4E -- profile-based System V/386 COFF -> PE32 kit.

Family #1: live-proven Intel run860 fat wrapper + appended i860 COFF.
Family #2: native static SVR3/i386 executable, currently exact Intel ICC 3.3
           profile with reconstructed stripped relocation manifest.
"""
import argparse, hashlib, importlib.util, json, struct, subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
 s=importlib.util.spec_from_file_location(name,str(path));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
base=load('proven_intel860_base',HERE/'runtime'/'proven_intel860_base.py')
fat=load('fat_family',HERE/'fat_family.py')
nat=load('native_icc_profile',HERE/'native_icc_profile.py')
icprof=load('native_ic_profile',HERE/'native_ic_profile.py')
asprof=load('native_as_profile',HERE/'native_as_profile.py')
simprof=load('native_sim_profile',HERE/'native_sim_profile.py')
import sim_fp_runtime

def exact_profile(data,coff):
 return next((p for p in (icprof,asprof,simprof) if p.matches(data,coff)),None)

def sha256(b): return hashlib.sha256(b).hexdigest()

def generic_i386_traps(data,c):
 text=base.secbytes(data,c,'.text') if c.get('magic')==base.I386MAGIC else b''
 textva=0
 for sec in c.get('sections',[]):
  if sec['name']=='.text': textva=sec['vaddr']; break
 names={1:'exit',2:'fork',3:'read',4:'write',5:'open',6:'close',7:'wait',8:'creat',9:'link',10:'unlink',11:'exec',12:'chdir',13:'time',14:'mknod',15:'chmod',16:'chown',17:'brk',18:'stat',19:'lseek',20:'getpid',21:'mount',22:'umount',23:'setuid',24:'getuid',25:'stime',27:'alarm',29:'pause',30:'utime',33:'access',37:'kill',39:'pgrpsys',41:'dup',42:'pipe',43:'times',46:'setgid',47:'getgid',48:'signal',51:'acct',54:'ioctl',57:'utssys',59:'execve',60:'umask',61:'chroot',62:'fcntl',63:'ulimit',79:'rmdir',80:'mkdir',81:'getdents'}
 out=[]
 for i in range(max(0,len(text)-6)):
  if text[i:i+5]!=b'\x9a\0\0\0\0': continue
  sel=struct.unpack_from('<H',text,i+5)[0]; num=None
  if sel==7:
   for j in range(i-1,max(-1,i-32),-1):
    if text[j]==0xb8 and j+5<=i:
     num=struct.unpack_from('<I',text,j+1)[0]; break
  out.append({'pc':textva+i,'selector':sel,'syscall':num,'name':names.get(num,'unknown') if num is not None else ('signal_return' if sel==15 else 'unknown')})
 return out

def native_inspect(path):
 data=Path(path).read_bytes(); c=base.parse_coff(data,0); text=base.secbytes(data,c,'.text') if c['magic']==base.I386MAGIC else b''
 matched=nat.matches(data,c); native=exact_profile(data,c); imatched=native is not None
 prof=(nat.profile_info(data,c,text) if matched else (native.profile_info(data,c,text,path) if imatched else None))
 return {
  'input':{'path':str(path),'size':len(data),'sha256':sha256(data)},
  'outer':{'magic':c['magic'],'nscns':c['nscns'],'opthdr_size':c['opthdr_size'],'flags':c['flags'],'optional_common':c['optional_common'],'sections':fat.section_summary(c),'extent':base.coff_extent(c)},
  'profile':prof,
  'traps':(nat.trap_inventory(text) if matched else (native.trap_inventory(text) if imatched else generic_i386_traps(data,c))),
  'family':'native-static-svr3-i386' if (matched or imatched) else ('native-static-svr3-i386-unprofiled' if c['magic']==base.I386MAGIC else 'unrecognized-coff'),
 }

def inspect(path):
 data=Path(path).read_bytes(); c=base.parse_coff(data,0)
 split=base.coff_extent(c)
 wrapper=data[:split]
 if c['magic']==base.I386MAGIC and not (len(wrapper)==fat.PROVEN_WRAPPER_SIZE and sha256(wrapper)==fat.PROVEN_WRAPPER_SHA256): return native_inspect(path)
 return fat.inspect(path)

def native_build_pe(sections, imp, host_rva, hostdata_rva, header_overlay=None):
 saved=(base.HOST_RVA,base.HOSTDATA_RVA)
 try:
  base.HOST_RVA=host_rva;base.HOSTDATA_RVA=hostdata_rva
  return base.build_pe(sections,imp,header_overlay)
 finally:
  base.HOST_RVA,base.HOSTDATA_RVA=saved

def native_convert(input_path,output_path,workdir,label,force_heuristic=False):
 src=Path(input_path); out=Path(output_path); wd=Path(workdir);wd.mkdir(parents=True,exist_ok=True)
 data=src.read_bytes(); c=base.parse_coff(data,0)
 is_icc=nat.matches(data,c); native=exact_profile(data,c)
 if not is_icc and native is None:
  raise SystemExit('Unsupported native COFF fingerprint. Heuristic conversion is disabled; an audited target profile is required. Supported: IC, ICC, Portland Group as860, Intel SIM860 1.1.')
 profmod=nat if is_icc else native
 text=base.secbytes(data,c,'.text'); dat=base.secbytes(data,c,'.data')
 funcs=list(base.FUNCS)+['CreateDirectoryA','CreateProcessA','WaitForSingleObject','GetExitCodeProcess','SetUnhandledExceptionFilter']
 # Allocate native runtime sections after the relocated text.  ICC's original
 # fixed RVAs are insufficient for larger native profiles such as IC.
 svtext_rva=profmod.NEW_TEXT-base.IMAGE_BASE
 host_rva=base.align(svtext_rva+len(text),base.SECT_ALIGN)
 hostdata_rva=host_rva+0x4000
 idata_rva=hostdata_rva+0x5000
 idata,imp=base.make_idata(idata_rva,funcs); iat={fn:base.IMAGE_BASE+r for fn,r in imp['iat_entries'].items()}
 if is_icc:
  asm=nat.native_asm_source(base,iat)
 else:
  saved_nat=(nat.OLD_TEXT,nat.OLD_ENTRY,nat.OLD_DATA,nat.OLD_BSS,nat.TEXT_SIZE,nat.DATA_SIZE,nat.BSS_SIZE,nat.NEW_TEXT,nat.DELTA,nat.HEAP_LIMIT)
  nat.OLD_TEXT,nat.OLD_ENTRY,nat.OLD_DATA,nat.OLD_BSS,nat.TEXT_SIZE,nat.DATA_SIZE,nat.BSS_SIZE,nat.NEW_TEXT,nat.DELTA,nat.HEAP_LIMIT=(profmod.OLD_TEXT,profmod.OLD_ENTRY,profmod.OLD_DATA,profmod.OLD_BSS,profmod.TEXT_SIZE,profmod.DATA_SIZE,profmod.BSS_SIZE,profmod.NEW_TEXT,profmod.DELTA,profmod.HEAP_LIMIT)
  try:
   asm=nat.native_asm_source(base,iat).replace('SVR3 ICC33 R3',profmod.RUNTIME_BANNER)
  finally:
   nat.OLD_TEXT,nat.OLD_ENTRY,nat.OLD_DATA,nat.OLD_BSS,nat.TEXT_SIZE,nat.DATA_SIZE,nat.BSS_SIZE,nat.NEW_TEXT,nat.DELTA,nat.HEAP_LIMIT=saved_nat
  # R4M: install a native-Windows unhandled exception reporter.  This is
  # diagnostic-only: it prints the real fault address/registers and returns
  # EXCEPTION_CONTINUE_SEARCH so Windows still terminates normally.
  crash_install='''
    push OFFSET FLAT:crash_handler
    call DWORD PTR ds:[IAT_SetUnhandledExceptionFilter]
'''
  startup_needle='''    mov DWORD PTR [hstdin], eax

    /* R4E: inherit host environment and configure trace level. */
'''
  if startup_needle not in asm: raise RuntimeError('R4M crash-handler startup injection point changed')
  asm=asm.replace(startup_needle,'''    mov DWORD PTR [hstdin], eax
'''+crash_install+'''
    /* R4E: inherit host environment and configure trace level. */
''',1)
  crash_code=r'''
/* R4N native Windows crash telemetry. EXCEPTION_POINTERS* is [ebp+8]. */
crash_handler:
    push ebp
    mov ebp,esp
    push ebx
    push esi
    push edi
    mov ebx,DWORD PTR [ebp+8]
    test ebx,ebx
    jz crash_done
    mov esi,DWORD PTR [ebx]
    mov edi,DWORD PTR [ebx+4]
    push OFFSET FLAT:crash_hdr
    call host_puts_err
    add esp,4
    test esi,esi
    jz crash_ctx
    push DWORD PTR [esi]
    push OFFSET FLAT:crash_code_prefix
    call crash_field
    add esp,8
    push DWORD PTR [esi+12]
    push OFFSET FLAT:crash_excaddr_prefix
    call crash_field
    add esp,8
    cmp DWORD PTR [esi+16],2
    jb crash_ctx
    push DWORD PTR [esi+20]
    push OFFSET FLAT:crash_access_prefix
    call crash_field
    add esp,8
    push DWORD PTR [esi+24]
    push OFFSET FLAT:crash_fault_prefix
    call crash_field
    add esp,8
crash_ctx:
    test edi,edi
    jz crash_done
    push DWORD PTR [edi+0xB8]
    push OFFSET FLAT:crash_eip_prefix
    call crash_field
    add esp,8
    push DWORD PTR [edi+0xC4]
    push OFFSET FLAT:crash_esp_prefix
    call crash_field
    add esp,8
    mov edx,DWORD PTR [edi+0xC4]
    push DWORD PTR [edx+0]
    push OFFSET FLAT:crash_stk0_prefix
    call crash_field
    add esp,8
    mov edx,DWORD PTR [edi+0xC4]
    push DWORD PTR [edx+4]
    push OFFSET FLAT:crash_stk1_prefix
    call crash_field
    add esp,8
    mov edx,DWORD PTR [edi+0xC4]
    push DWORD PTR [edx+8]
    push OFFSET FLAT:crash_stk2_prefix
    call crash_field
    add esp,8
    mov edx,DWORD PTR [edi+0xC4]
    push DWORD PTR [edx+12]
    push OFFSET FLAT:crash_stk3_prefix
    call crash_field
    add esp,8
    mov edx,DWORD PTR [edi+0xC4]
    push DWORD PTR [edx+16]
    push OFFSET FLAT:crash_stk4_prefix
    call crash_field
    add esp,8
    mov edx,DWORD PTR [edi+0xC4]
    push DWORD PTR [edx+20]
    push OFFSET FLAT:crash_stk5_prefix
    call crash_field
    add esp,8
    mov edx,DWORD PTR [edi+0xC4]
    push DWORD PTR [edx+24]
    push OFFSET FLAT:crash_stk6_prefix
    call crash_field
    add esp,8
    mov edx,DWORD PTR [edi+0xC4]
    push DWORD PTR [edx+28]
    push OFFSET FLAT:crash_stk7_prefix
    call crash_field
    add esp,8
    push DWORD PTR [edi+0xB0]
    push OFFSET FLAT:crash_eax_prefix
    call crash_field
    add esp,8
    push DWORD PTR [edi+0xB4]
    push OFFSET FLAT:crash_ebp_prefix
    call crash_field
    add esp,8
    push DWORD PTR [edi+0xA4]
    push OFFSET FLAT:crash_ebx_prefix
    call crash_field
    add esp,8
    push DWORD PTR [edi+0xAC]
    push OFFSET FLAT:crash_ecx_prefix
    call crash_field
    add esp,8
    push DWORD PTR [edi+0xA8]
    push OFFSET FLAT:crash_edx_prefix
    call crash_field
    add esp,8
    push DWORD PTR [edi+0xA0]
    push OFFSET FLAT:crash_esi_prefix
    call crash_field
    add esp,8
    push DWORD PTR [edi+0x9C]
    push OFFSET FLAT:crash_edi_prefix
    call crash_field
    add esp,8
crash_done:
    xor eax,eax                 /* EXCEPTION_CONTINUE_SEARCH */
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret 4

/* cdecl crash_field(prefix,value), stderr only. */
crash_field:
    push ebp
    mov ebp,esp
    push ebx
    push esi
    push edi
    push DWORD PTR [ebp+8]
    call host_puts_err
    add esp,4
    mov eax,DWORD PTR [ebp+12]
    mov edi,OFFSET FLAT:crash_hex_buf+8
    mov BYTE PTR [edi],0
    mov ecx,8
crash_hex_loop:
    dec edi
    mov edx,eax
    and edx,0x0f
    mov bl,BYTE PTR [hex_digits+edx]
    mov BYTE PTR [edi],bl
    shr eax,4
    dec ecx
    jnz crash_hex_loop
    push OFFSET FLAT:crash_hex_buf
    call host_puts_err
    add esp,4
    push OFFSET FLAT:crash_crlf
    call host_puts_err
    add esp,4
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.section .data
crash_hdr: .asciz "[svr3 crash] native Windows exception captured\r\n"
crash_code_prefix: .asciz "[svr3 crash] code=0x"
crash_excaddr_prefix: .asciz "[svr3 crash] exception_address=0x"
crash_access_prefix: .asciz "[svr3 crash] access_type=0x"
crash_fault_prefix: .asciz "[svr3 crash] fault_address=0x"
crash_eip_prefix: .asciz "[svr3 crash] EIP=0x"
crash_esp_prefix: .asciz "[svr3 crash] ESP=0x"
crash_eax_prefix: .asciz "[svr3 crash] EAX=0x"
crash_ebp_prefix: .asciz "[svr3 crash] EBP=0x"
crash_stk0_prefix: .asciz "[svr3 crash] [ESP+00]=0x"
crash_stk1_prefix: .asciz "[svr3 crash] [ESP+04]=0x"
crash_stk2_prefix: .asciz "[svr3 crash] [ESP+08]=0x"
crash_stk3_prefix: .asciz "[svr3 crash] [ESP+0C]=0x"
crash_stk4_prefix: .asciz "[svr3 crash] [ESP+10]=0x"
crash_stk5_prefix: .asciz "[svr3 crash] [ESP+14]=0x"
crash_stk6_prefix: .asciz "[svr3 crash] [ESP+18]=0x"
crash_stk7_prefix: .asciz "[svr3 crash] [ESP+1C]=0x"
crash_ebx_prefix: .asciz "[svr3 crash] EBX=0x"
crash_ecx_prefix: .asciz "[svr3 crash] ECX=0x"
crash_edx_prefix: .asciz "[svr3 crash] EDX=0x"
crash_esi_prefix: .asciz "[svr3 crash] ESI=0x"
crash_edi_prefix: .asciz "[svr3 crash] EDI=0x"
crash_crlf: .asciz "\r\n"
crash_hex_buf: .space 9
.section .text
'''
  # IC adds time(13) and times(43). Deterministic compatibility values are sufficient for compiler staging.
  needle='    cmp ebx,59\n    je sc_execve_native\n'
  asm=asm.replace(needle,'    cmp ebx,13\n    je sc_time_ic\n    cmp ebx,43\n    je sc_times_ic\n'+needle,1)
  # R4I IC profile compatibility: the historical libc brk() wrapper keeps its
  # current-break bookkeeping word at 0x00442B34.  Mirror each accepted kernel
  # break there as an idempotent safeguard; this is exact-profile-only.
  brk_needle='    mov DWORD PTR [native_brk],eax\n    cmp DWORD PTR [trace_level],3\n'
  brk_repl='    mov DWORD PTR [native_brk],eax\n    mov DWORD PTR ds:[0x%08x],eax\n    cmp DWORD PTR [trace_level],3\n' % profmod.BRK_WORD
  if brk_needle not in asm: raise RuntimeError('IC brk mirror injection point changed')
  asm=asm.replace(brk_needle,brk_repl,1)
  # Same runtime, profile-provided guest addresses. Translate in one pass so
  # destination addresses cannot accidentally match subsequent substitutions.
  guest_words=dict(zip(icprof.ALLOC_WORDS,profmod.ALLOC_WORDS))
  import re
  asm=re.sub(r'0x00442b(?:1c|20|24|28|2c|34)',lambda m:'0x%08x'%guest_words[int(m[0],16)],asm)
  asm=asm.replace('0x00409960','0x%08x'%profmod.RUNTIME_BRK_MIN)

  asm += '''\nsc_time_ic:\n    xor eax,eax\n    mov edi,DWORD PTR [esi]\n    test edi,edi\n    jz sc_ok\n    mov DWORD PTR [edi],eax\n    jmp sc_ok\nsc_times_ic:\n    mov edi,DWORD PTR [esi]\n    test edi,edi\n    jz sc_times_ic_ret\n    mov DWORD PTR [edi],0\n    mov DWORD PTR [edi+4],0\n    mov DWORD PTR [edi+8],0\n    mov DWORD PTR [edi+12],0\nsc_times_ic_ret:\n    xor eax,eax\n    jmp sc_ok\n'''
  data_needle='''\nsc_time_ic:\n'''
  if data_needle not in asm: raise RuntimeError('R4M IC tail injection point changed')
  asm=asm.replace(data_needle,'\n'+crash_code+'\nsc_time_ic:\n',1)
 if native is simprof:
  asm += sim_fp_runtime.asm_source()
  # ICC's CRT direct-exit site differs; SIM860 uses the base CRT site 0x110.
  asm=asm.replace('0x%08x'%(simprof.NEW_TEXT+0x11d-simprof.OLD_TEXT+5),
                  '0x%08x'%(simprof.NEW_TEXT+0x110-simprof.OLD_TEXT+5))
 host,hdata,asm_path,cpu_path,elf=base.assemble_host(wd,asm,nat.stub_cpu_source(),base.IMAGE_BASE+host_rva,base.IMAGE_BASE+hostdata_rva)
 if len(host)>0x4000: raise RuntimeError('native host section exceeded reserved 16 KiB slot')
 if len(hdata)>0x5000: raise RuntimeError('native host data exceeded reserved 20 KiB slot')
 syms={}
 for line in subprocess.run(['nm','-n',str(elf)],capture_output=True,text=True,check=True).stdout.splitlines():
  p=line.split()
  if len(p)>=3:
   try: syms[p[2]]=int(p[0],16)
   except ValueError: pass
 for k in ('host_entry','svr3_gate7','svr3_gate15'):
  if k not in syms: raise RuntimeError('missing native host symbol '+k)
 
 if is_icc:
  patched_text,patched_data,patches,counts=nat.relocate(text,dat,syms['svr3_gate7'],syms['svr3_gate15'])
  manifest_extra=None
 else:
  patched_text,patched_data,patches,counts,manifest_extra=profmod.relocate(src,text,dat,syms['svr3_gate7'],syms.get('svr3_gate15'))
 if native is simprof:
  patched_text,fp_patches=sim_fp_runtime.patch(patched_text,syms,profmod.OLD_TEXT,profmod.NEW_TEXT)
  patches+=fp_patches
 # Historical data starts inside the mapped PE header page. Keep the first
 # fragment there, then continue exact bytes in the RW historical-memory section.
 header_off=profmod.OLD_DATA-base.IMAGE_BASE
 first=0x1000-header_off
 header_blob=patched_data[:first]
 # Preserve initialized data/BSS and the low brk arena.  For a PE image the
 # next section must follow at the next SectionAlignment boundary.  Pad this
 # historical-memory section through NEW_TEXT so native Windows does not see
 # an unmapped RVA hole between .svmem and .svtext.
 svmem_end=profmod.NEW_TEXT
 if svmem_end < profmod.HEAP_LIMIT:
  raise RuntimeError('relocated text overlaps required historical heap arena')
 svmem=bytearray(svmem_end-(base.IMAGE_BASE+0x1000))
 svmem[:len(patched_data)-first]=patched_data[first:]
 profile=(nat.profile_info(data,c,text) if is_icc else profmod.profile_info(data,c,text,src))
 if manifest_extra is not None: profile['discovered_manifest']=manifest_extra
 meta={
  'format':'SVR3COFF2PE-R4S','family':'native-static-svr3-i386','profile':profile,
  'input':{'name':src.name,'size':len(data),'sha256':sha256(data)},
  'layout':{'image_base':base.IMAGE_BASE,'historical_data_va':profmod.OLD_DATA,'historical_bss_va':profmod.OLD_BSS,'heap_limit':profmod.HEAP_LIMIT,'relocated_text_va':profmod.NEW_TEXT,'text_delta':profmod.DELTA,'relocated_entry_va':profmod.NEW_TEXT+(profmod.OLD_ENTRY-profmod.OLD_TEXT),'host_va':base.IMAGE_BASE+host_rva,'host_data_va':base.IMAGE_BASE+hostdata_rva},
  'gate_counts':counts,'patches':patches,
  'runtime':{'implemented_outer_syscalls':'exit/read/write/open/close/creat/unlink/brk/stat/lseek/getpid/access/ioctl/signal/mkdir/fork/wait/execve','process_calls':'generic synchronous fork/exec/wait virtualization; Unix basename X resolves to X-pe.exe then X.exe','selector15':'diagnostic abort; asynchronous signal delivery not implemented'},
  'status':'BUILD_STATIC_VERIFIED_RUNTIME_UNTESTED_R4_NATIVE_PROFILE',
  'limitations':['recognized exact native profile required; R4O IC uses audited operand locations','fork is synchronous snapshot/restore rather than concurrent Unix process cloning','native family Windows runtime not yet tested','stat is a compact deterministic compatibility subset','IC R4O has passed static verification; native Windows compilation remains unverified'],
 }
 if native is simprof:
  meta['status']='STATIC_AND_PE_X86_REPLAY_TESTED_WINDOWS_RUNTIME_PENDING'
  meta['limitations']=['Windows live test pending; replay mocks imported Win32 APIs only',
   'Historical SIM860 Release 1.1; not the newer N1.3',
   'R4S synchronously bridges precision exceptions in Intel FP helpers; other FP signals and Ctrl-C remain unsupported',
   'Bounded historical heap ends at 0x004f0000; complex targets may exhaust it',
   'Unimplemented Unix services report the syscall and stop; stat is a compatibility subset']
 meta_blob=(json.dumps(meta,sort_keys=True,indent=2)+'\n').encode()
 meta_rva=base.align(idata_rva+len(idata),base.SECT_ALIGN)
 orig_rva=base.align(meta_rva+len(meta_blob),base.SECT_ALIGN)
 host_section=host+b'\0'*(0x4000-len(host))
 sections=[
  ('.svmem',bytes(svmem),0x1000,0xC0000040),
  ('.svtext',patched_text,svtext_rva,0x60000020),
  ('.host',host_section,host_rva,0x60000020),
  ('.hdata',hdata.ljust(0x5000,b'\0'),hostdata_rva,0xC0000040),
  ('.idata',idata,idata_rva,0x40000040),
  ('.meta',meta_blob,meta_rva,0x40000040),
  ('.orig386',data,orig_rva,0x40000040),
 ]
 pe,rows,size_image=native_build_pe(sections,imp,host_rva,hostdata_rva,(header_off,header_blob))
 rowmap={r['name']:r for r in base.parse_pe_sections(pe)}
 def sec(n):
  r=rowmap[n];return pe[r['raw_offset']:r['raw_offset']+r['vsize']]
 # Native PE sections must never overlap in virtual address space or file data.
 def _ranges_overlap(a0,a1,b0,b1): return a0 < b1 and b0 < a1
 rows_list=list(rowmap.values())
 overlap_pairs=[]
 for ai in range(len(rows_list)):
  a=rows_list[ai]; av0=a['rva']; av1=av0+base.align(max(a['vsize'],1),base.SECT_ALIGN)
  ar0=a['raw_offset']; ar1=ar0+a['raw_size']
  for bi in range(ai+1,len(rows_list)):
   b=rows_list[bi]; bv0=b['rva']; bv1=bv0+base.align(max(b['vsize'],1),base.SECT_ALIGN)
   br0=b['raw_offset']; br1=br0+b['raw_size']
   if _ranges_overlap(av0,av1,bv0,bv1): overlap_pairs.append('VA:%s/%s'%(a['name'],b['name']))
   if a['raw_size'] and b['raw_size'] and _ranges_overlap(ar0,ar1,br0,br1): overlap_pairs.append('RAW:%s/%s'%(a['name'],b['name']))
 adjacent_pairs=[]
 for ai in range(len(rows_list)-1):
  a=rows_list[ai]; b=rows_list[ai+1]
  expect=base.align(a['rva']+max(a['vsize'],1),base.SECT_ALIGN)
  if b['rva']!=expect:
   adjacent_pairs.append('%s->%s expected=0x%X got=0x%X'%(a['name'],b['name'],expect,b['rva']))
 # Verify OptionalHeader BaseOfCode/BaseOfData against the first actual sections.
 peoff=struct.unpack_from('<I',pe,0x3c)[0]; optoff=peoff+24
 pe_base_code=struct.unpack_from('<I',pe,optoff+20)[0]
 pe_base_data=struct.unpack_from('<I',pe,optoff+24)[0]
 checks={
  'no_section_overlaps':not overlap_pairs,
  'sections_rva_adjacent':not adjacent_pairs,
  'base_of_code_first_code':pe_base_code==rowmap['.svtext']['rva'],
  'base_of_data_first_data':pe_base_data==rowmap['.svmem']['rva'],
  'original_coff_preserved':sec('.orig386')==data,
  'relocated_text_exact':sec('.svtext')==patched_text,
  'no_selector7_lcall':b'\x9a\0\0\0\0\x07\0' not in patched_text,
  'no_selector15_lcall':b'\x9a\0\0\0\0\x0f\0' not in patched_text,
  'header_data_prefix_exact':pe[header_off:header_off+first]==patched_data[:first],
  'svmem_data_suffix_exact':sec('.svmem')[:len(patched_data)-first]==patched_data[first:],
  'text_rx':(rowmap['.svtext']['chars']&0x20000000)!=0 and (rowmap['.svtext']['chars']&0x80000000)==0,
  'historical_memory_rw_nx':(rowmap['.svmem']['chars']&0x80000000)!=0 and (rowmap['.svmem']['chars']&0x20000000)==0,
 }
 if not all(checks.values()): raise RuntimeError('native static verification failed '+repr(checks))
 out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(pe)
 report=dict(meta);report['output']={'path':str(out),'size':len(pe),'sha256':sha256(pe),'size_of_image':size_image,'sections':rowmap,'checks':checks}
 out.with_suffix(out.suffix+'.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 return report

def main():
 ap=argparse.ArgumentParser(description='SVR3COFF2PE R4S profile-based converter/analyzer')
 sp=ap.add_subparsers(dest='cmd',required=True)
 p=sp.add_parser('inspect');p.add_argument('input');p.add_argument('--json',action='store_true')
 p=sp.add_parser('traps');p.add_argument('input');p.add_argument('--json',action='store_true')
 p=sp.add_parser('convert');p.add_argument('input');p.add_argument('--force-native-heuristic',action='store_true',help='deprecated compatibility flag; unknown native fingerprints are always rejected');p.add_argument('-o','--output',required=True);p.add_argument('--workdir',default='.svr3coff2pe-build');p.add_argument('--label',default='SVR3PE R3');p.add_argument('--step-limit',type=int,default=2000000)
 a=ap.parse_args(); info=inspect(a.input)
 if a.cmd=='inspect':
  if a.json: print(json.dumps(info,sort_keys=True,indent=2))
  elif info.get('family') in ('native-static-svr3-i386','native-static-svr3-i386-unprofiled'):
   print('input:',info['input']['path']);print('sha256:',info['input']['sha256']);print('family:',info['family'])
   if info.get('profile'): print('profile:',info['profile']['id'])
   oc=info['outer'].get('optional_common') or {}; print('entry=0x%08X text=0x%08X data=0x%08X'%(oc.get('entry',0),oc.get('text_start',0),oc.get('data_start',0)));print('kernel gate sites:',len(info.get('traps',[])))
  else: fat.print_inspect(info,False)
  return
 if a.cmd=='traps':
  traps=(info.get('profile') or {}).get('traps') or info.get('traps') or (info.get('appended') or {}).get('traps',[])
  if a.json: print(json.dumps(traps,sort_keys=True,indent=2))
  else:
   for t in traps: print('0x%08X selector=%s syscall=%s %s'%(t['pc'],t.get('selector','-'),str(t.get('syscall','?')),t.get('name','unknown')))
  return
 if a.cmd=='convert':
  if info.get('family') in ('native-static-svr3-i386','native-static-svr3-i386-unprofiled'): rep=native_convert(a.input,a.output,a.workdir,a.label,a.force_native_heuristic)
  else: rep=fat.convert(a.input,a.output,a.workdir,a.label,a.step_limit)
  print('wrote',a.output);print('sha256',rep['output']['sha256']);print('report',str(Path(a.output).with_suffix(Path(a.output).suffix+'.json')))
if __name__=='__main__': main()
