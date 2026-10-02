#!/usr/bin/env python3
"""SVR3COFF2PE R1

Converter/analyzer for the Intel N1.x 'fat tool' format proven by SIM860,
AS860, LD860 and SIZE860: a statically-linked SVR3/i386 COFF run860 wrapper
followed by an Intel i860 COFF payload.

Conversion is intentionally conservative.  It requires the proven wrapper
layout and patches only the known SVR3 syscall gates/absolute code pointers.
Other i386 COFF files can still be inspected, but are not claimed executable.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
BASE_PATH = HERE / 'runtime' / 'proven_intel860_base.py'
spec = importlib.util.spec_from_file_location('proven_intel860_base', str(BASE_PATH))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

PROVEN_WRAPPER_SHA256 = '9c0007b43b93b13f1f06f75832c61a44c5276e59860113ebdc6b04896b784023'
PROVEN_WRAPPER_SIZE = 0x10A6
SYSCALL_NAMES = {
    1:'exit', 2:'fork', 3:'read', 4:'write', 5:'open', 6:'close', 7:'wait',
    8:'creat', 9:'link', 10:'unlink', 11:'exec', 12:'chdir', 13:'time',
    14:'mknod', 15:'chmod', 16:'chown', 17:'brk', 18:'stat', 19:'lseek',
    20:'getpid', 21:'mount', 22:'umount', 23:'setuid', 24:'getuid', 25:'stime',
    28:'fstat', 30:'utime', 33:'access', 35:'statfs', 36:'sync', 37:'kill',
    38:'fstatfs', 39:'pgrpsys', 41:'dup', 42:'pipe', 43:'times', 46:'setgid',
    47:'getgid', 48:'signal', 51:'acct', 54:'ioctl', 57:'utssys', 60:'umask',
    61:'chroot', 62:'fcntl', 63:'ulimit', 79:'rmdir', 80:'mkdir', 81:'getdents'
}

def sha256(b):
    return hashlib.sha256(b).hexdigest()

def parse_fat(path):
    data = Path(path).read_bytes()
    outer = base.parse_coff(data, 0)
    split = base.coff_extent(outer)
    inner = None
    if split + 20 <= len(data):
        try:
            inner = base.parse_coff(data, split)
        except Exception:
            inner = None
    wrapper = data[:split]
    payload = data[split:]
    return data, outer, split, inner, wrapper, payload

def section_summary(coff):
    return [dict(name=s['name'], vaddr=s['vaddr'], size=s['size'], scnptr=s['scnptr'],
                 nreloc=s['nreloc'], flags=s['flags']) for s in coff['sections']]

def trap_inventory(data, inner):
    if not inner or inner['magic'] != base.I860MAGIC:
        return []
    textsec = next((s for s in inner['sections'] if s['name'] == '.text'), None)
    if not textsec or not textsec['size'] or not textsec['scnptr']:
        return []
    off0 = inner['base'] + textsec['scnptr']
    out = []
    for o in range(0, textsec['size'] - 3, 4):
        w = struct.unpack_from('<I', data, off0 + o)[0]
        if w != 0x47E0F800:
            continue
        prev = struct.unpack_from('<I', data, off0 + o - 4)[0] if o >= 4 else None
        num = None
        # All four proven N1.3 tools use: or <imm>,r0,r31  (E41Fxxxx)
        if prev is not None and (prev & 0xFFFF0000) == 0xE41F0000:
            num = prev & 0xFFFF
        out.append({
            'pc': (textsec['vaddr'] + o) & 0xffffffff,
            'word': w,
            'predecessor': prev,
            'syscall': num,
            'name': SYSCALL_NAMES.get(num, 'unknown') if num is not None else 'unresolved'
        })
    return out

def inspect(path):
    data, outer, split, inner, wrapper, payload = parse_fat(path)
    info = {
        'input': {'path': str(path), 'size': len(data), 'sha256': sha256(data)},
        'outer': {
            'magic': outer['magic'], 'nscns': outer['nscns'], 'opthdr_size': outer['opthdr_size'],
            'flags': outer['flags'], 'optional_common': outer['optional_common'],
            'sections': section_summary(outer), 'extent': split,
            'wrapper_sha256': sha256(wrapper),
            'proven_intel_run860_wrapper': len(wrapper) == PROVEN_WRAPPER_SIZE and sha256(wrapper) == PROVEN_WRAPPER_SHA256
        },
        'appended': None,
    }
    if inner:
        info['appended'] = {
            'offset': split, 'size': len(payload), 'sha256': sha256(payload),
            'magic': inner['magic'], 'nscns': inner['nscns'], 'opthdr_size': inner['opthdr_size'],
            'flags': inner['flags'], 'optional_common': inner['optional_common'],
            'sections': section_summary(inner), 'traps': trap_inventory(data, inner)
        }
    return info

def generic_cpu_source(label, step_limit):
    s = base.cpu_source()
    # Keep the mature R10 instruction decoder/personality, but remove the
    # SIM860-inner-target proof hook and tool-specific exit/step-limit oracle.
    s = s.replace('SIM860 R10', label)
    s = re.sub(r'#define STEP_LIMIT\s+1000000u', '#define STEP_LIMIT %du' % step_limit, s)
    # Remove R10-only inner-target proof state so strict -Werror remains clean.
    s = re.sub(r'^static u32 inner_(?:entry|loop_cc|loop_d0)_(?:seen|count);\n', '', s, flags=re.M)

    # Add chmod(15): validate that the path exists, then accept Unix mode bits
    # as a compatibility no-op on Win32. This is the live-proven LD860 policy.
    needle = '''        if (r[31]==17u) {\n            u32 req;'''
    chmod = '''        if (r[31]==15u) {\n            const char *path; u32 fd; int is_dir;\n            path=guest_host_path(r[16],&is_dir);\n            if (!path) return -1;\n            if (!is_dir) {\n                fd=host_open_file(path,0u,0u);\n                if (fd==0xffffffffu) { r[16]=2u; cc=1u; pc=at+4u; return 1; }\n                (void)host_close_fd(fd);\n            }\n            r[16]=0u; cc=0u; pc=at+4u; return 1;\n        }\n'''
    if needle not in s:
        raise RuntimeError('unable to add chmod syscall to runtime template')
    s = s.replace(needle, chmod + needle, 1)

    start = s.index('static void observe_inner_target(void)')
    run_start = s.index('int i860_run(void)', start)
    # Replace observation helper and everything from i860_run to EOF with a
    # generic bounded runner. All decode/syscall helpers before it are retained.
    generic_tail = r'''static void generic_print_counts(void)
{
    host_puts_out("''' + label + r''': traps write=0x"); host_puthex32(write_traps);
    host_puts_out(" read=0x"); host_puthex32(read_traps);
    host_puts_out(" open=0x"); host_puthex32(open_traps);
    host_puts_out(" close=0x"); host_puthex32(close_traps);
    host_puts_out(" brk=0x"); host_puthex32(brk_traps);
    host_puts_out(" lseek=0x"); host_puthex32(lseek_traps);
    host_puts_out(" signal=0x"); host_puthex32(signal_traps);
    host_puts_out("\r\n");
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
    brk_floor=i860_data_guest+i860_data_size+i860_bss_size; brk_current=brk_floor;
    r[2]=i860_stack_guest+i860_stack_size-16u;
    if (!setup_startup()) {
        host_puts_err("''' + label + r''': unable to construct i860 argc/argv/envp startup state\r\n");
        return 1;
    }
    startup_argc=r[16];
    pc=i860_entry;
    host_puts_out("''' + label + r''': i860 entry=0x"); host_puthex32(pc);
    host_puts_out(" synthetic-sp=0x"); host_puthex32(r[2]);
    host_puts_out(" argc=0x"); host_puthex32(r[16]);
    host_puts_out(" argv=0x"); host_puthex32(r[17]);
    host_puts_out(" envp=0x"); host_puthex32(r[18]); host_puts_out("\r\n");

    for (i=0u;i<STEP_LIMIT;i++) {
        rc=step_one();
        if (rc<0) {
            host_puts_err("''' + label + r''': i860 MEMORY FAULT kind=0x"); host_puthex32(fault_kind);
            host_puts_err(" address=0x"); host_puthex32(fault_addr); host_puts_err(" pc=0x"); host_puthex32(pc); host_puts_err("\r\n");
            generic_print_counts();
            return 1;
        }
        if (rc==2) {
            host_puts_out("''' + label + r''': guest exit status=0x"); host_puthex32(guest_exit_status);
            host_puts_out(" count=0x"); host_puthex32(icount); host_puts_out("\r\n");
            generic_print_counts();
            return 0x100u + guest_exit_status;
        }
        if (rc==0) {
            if (!read_mem(pc,4u,&w)) w=0u;
            host_puts_out("''' + label + r''': unsupported i860 instruction/service pc=0x"); host_puthex32(pc);
            host_puts_out(" insn=0x"); host_puthex32(w); host_puts_out(" count=0x"); host_puthex32(icount); host_puts_out("\r\n");
            if (opmatch(w,0x44000000u,0xb8000000u)) {
                host_puts_out("''' + label + r''': UNKNOWN TRAP r31=0x"); host_puthex32(r[31]);
                host_puts_out(" r16=0x"); host_puthex32(r[16]); host_puts_out(" r17=0x"); host_puthex32(r[17]);
                host_puts_out(" r18=0x"); host_puthex32(r[18]); host_puts_out(" r19=0x"); host_puthex32(r[19]); host_puts_out("\r\n");
            }
            generic_print_counts();
            return 1;
        }
    }
    host_puts_err("''' + label + r''': bounded i860 step limit reached without guest exit\r\n");
    generic_print_counts();
    return 1;
}
'''
    s = s[:start] + generic_tail
    return s

def generic_asm_source(iat_abs, payload_size, label, output_name):
    s = base.asm_source(iat_abs, payload_size)
    s = s.replace('SIM860 R10', label)
    s = s.replace('sim860-r10.exe', output_name)
    return s

def ensure_convertible(info):
    if info['outer']['magic'] != base.I386MAGIC:
        raise SystemExit('conversion requires an i386 COFF outer image')
    if not info['outer']['proven_intel_run860_wrapper']:
        raise SystemExit('conversion R1 supports only the proven Intel run860 SVR3 wrapper family; use inspect/traps for other COFF files')
    app = info['appended']
    if not app or app['magic'] != base.I860MAGIC:
        raise SystemExit('conversion requires an appended Intel i860 COFF payload')
    if app['nscns'] != 3 or app['opthdr_size'] != 36:
        raise SystemExit('R1 runtime currently requires the proven 3-section/36-byte i860 executable layout')

def convert(input_path, output_path, workdir, label, step_limit):
    input_path = Path(input_path)
    output_path = Path(output_path)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    info = inspect(input_path)
    ensure_convertible(info)

    data, outer, split, inner, wrapper, payload = parse_fat(input_path)
    text = base.secbytes(data, outer, '.text')
    dat = base.secbytes(data, outer, '.data')
    oc = outer['optional_common']
    if not oc or oc['entry'] != base.OLD_ENTRY or oc['text_start'] != base.OLD_TEXT_VA or oc['data_start'] != base.OLD_DATA_VA:
        raise SystemExit('proven wrapper fingerprint matched but SVR3 load oracle changed')

    idata, imp = base.make_idata(base.IDATA_RVA, base.FUNCS)
    iat_abs = {fn: base.IMAGE_BASE + rva for fn, rva in imp['iat_entries'].items()}
    asm = generic_asm_source(iat_abs, len(payload), label, output_path.name)
    cpu = generic_cpu_source(label, step_limit)
    host, hdata, asm_path, cpu_path, host_elf = base.assemble_host(
        workdir, asm, cpu, base.IMAGE_BASE + base.HOST_RVA, base.IMAGE_BASE + base.HOSTDATA_RVA)
    if len(host) > (base.HOSTDATA_RVA - base.HOST_RVA):
        raise SystemExit('generic host code exceeds reserved .host region (%d bytes)' % len(host))
    if len(hdata) > (base.SVTEXT_RVA - base.HOSTDATA_RVA):
        raise SystemExit('generic host data exceeds reserved .hdata region (%d bytes)' % len(hdata))

    nm = subprocess.run(['nm','-n',str(host_elf)], capture_output=True, text=True, check=True).stdout.splitlines()
    syms = {}
    for line in nm:
        p = line.split()
        if len(p) >= 3:
            try: syms[p[2]] = int(p[0],16)
            except ValueError: pass
    for req in ['host_entry','svr3_gate7','svr3_gate15']:
        if req not in syms: raise RuntimeError('missing host symbol '+req)
    patched, patches, delta = base.patch_text(text, syms['svr3_gate7'], syms['svr3_gate15'])

    header_data_off = base.OLD_DATA_VA - base.IMAGE_BASE
    if header_data_off + len(dat) > 0x1000:
        raise SystemExit('historical outer .data no longer fits proven PE header-page mapping')

    inventory = trap_inventory(data, inner)
    meta = {
        'format':'SVR3COFF2PE-R1',
        'scope':'proven Intel run860 fat-tool family',
        'input': info['input'],
        'wrapper': {'size':len(wrapper),'sha256':sha256(wrapper),'fingerprint_match':True},
        'payload': {'offset':split,'size':len(payload),'sha256':sha256(payload),
                    'entry':inner['optional_common']['entry'] if inner['optional_common'] else None,
                    'sections':section_summary(inner)},
        'static_i860_traps': inventory,
        'runtime': {
            'stack':'0x7FFF0000..0x7FFFFFFF',
            'low_heap_limit':'0x01000000',
            'step_limit':step_limit,
            'syscalls':'exit/read/write/open/close/creat/unlink/time/chmod/brk/stat/lseek/getpid/getuid/fstat/access/getgid/signal/utssys',
            'file_io':'binary-safe Win32 HANDLE backend; no CRT text translation',
            'unknown_traps':'diagnostic stop with r31/r16-r19',
        },
        'outer_patches': patches,
        'limitations': [
            'execution conversion requires the exact proven Intel SVR3 run860 wrapper fingerprint',
            'appended payload must be Intel i860 COFF with three sections and a 36-byte optional header',
            'signal registration is stub-success; asynchronous signal delivery is not implemented',
            'chmod validates existence and accepts Unix mode bits as a Win32 compatibility no-op',
            'unknown i860 opcodes/syscalls stop with diagnostics rather than being guessed',
            'this is not yet a universal arbitrary System V/386 COFF converter'
        ]
    }
    meta_json = (json.dumps(meta, sort_keys=True, indent=2)+'\n').encode()
    meta_rva = base.align(base.I860_RVA + len(payload), base.SECT_ALIGN)
    orig_rva = base.align(meta_rva + len(meta_json), base.SECT_ALIGN)
    sections = [
        ('.host', host, base.HOST_RVA, 0x60000020),
        ('.hdata', hdata, base.HOSTDATA_RVA, 0xC0000040),
        ('.svtext', patched, base.SVTEXT_RVA, 0x60000020),
        ('.idata', idata, base.IDATA_RVA, 0x40000040),
        ('.i860', payload, base.I860_RVA, 0x40000040),
        ('.meta', meta_json, meta_rva, 0x40000040),
        ('.orig386', wrapper, orig_rva, 0x40000040),
    ]
    pe, rows, size_image = base.build_pe(sections, imp, (header_data_off, dat))
    rowmap = {r['name']:r for r in base.parse_pe_sections(pe)}
    def ps(name):
        r=rowmap[name]; return pe[r['raw_offset']:r['raw_offset']+r['vsize']]
    checks = {
        'original_wrapper_preserved': ps('.orig386') == wrapper,
        'i860_payload_preserved': ps('.i860') == payload,
        'outer_data_exact_va': pe[header_data_off:header_data_off+len(dat)] == dat,
        'patched_text_same_size': len(ps('.svtext')) == len(text),
        'no_lcall7': b'\x9a\0\0\0\0\x07\0' not in ps('.svtext'),
        'no_lcall15': b'\x9a\0\0\0\0\x0f\0' not in ps('.svtext'),
        'host_rx_not_writable': (rowmap['.host']['chars'] & 0x80000000) == 0,
        'hdata_rw_not_executable': (rowmap['.hdata']['chars'] & 0x20000000) == 0,
    }
    if not all(checks.values()):
        raise RuntimeError('static verification failed: '+repr(checks))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(pe)
    report = dict(meta)
    report['output'] = {'path':str(output_path),'size':len(pe),'sha256':sha256(pe),'size_of_image':size_image,'sections':rowmap,'checks':checks}
    report_path = output_path.with_suffix(output_path.suffix + '.json')
    report_path.write_text(json.dumps(report, sort_keys=True, indent=2)+'\n')
    return report

def print_inspect(info, json_mode=False):
    if json_mode:
        print(json.dumps(info, sort_keys=True, indent=2)); return
    o=info['outer']
    print('input:', info['input']['path'])
    print('sha256:', info['input']['sha256'])
    print('outer: magic=0x%04X sections=%d extent=0x%X wrapper_sha256=%s' % (o['magic'],o['nscns'],o['extent'],o['wrapper_sha256']))
    print('proven Intel run860 wrapper:', 'YES' if o['proven_intel_run860_wrapper'] else 'NO')
    if info['appended']:
        a=info['appended']
        print('appended: offset=0x%X magic=0x%04X sections=%d size=%d sha256=%s' % (a['offset'],a['magic'],a['nscns'],a['size'],a['sha256']))
        if a['optional_common']:
            print('i860 entry=0x%08X text=0x%08X data=0x%08X' % (a['optional_common']['entry'],a['optional_common']['text_start'],a['optional_common']['data_start']))
        nums=sorted(set(t['syscall'] for t in a['traps'] if t['syscall'] is not None))
        print('static trap sites=%d distinct_syscalls=%d: %s' % (len(a['traps']),len(nums),', '.join('%d/%s'%(n,SYSCALL_NAMES.get(n,'unknown')) for n in nums)))

def main():
    ap=argparse.ArgumentParser(description='Analyze/convert proven Intel SVR3/i386 + i860 fat tools to PE32')
    sp=ap.add_subparsers(dest='cmd', required=True)
    p=sp.add_parser('inspect'); p.add_argument('input'); p.add_argument('--json',action='store_true')
    p=sp.add_parser('traps'); p.add_argument('input'); p.add_argument('--json',action='store_true')
    p=sp.add_parser('convert'); p.add_argument('input'); p.add_argument('-o','--output',required=True); p.add_argument('--workdir',default='.svr3coff2pe-build'); p.add_argument('--label',default='SVR3PE R1'); p.add_argument('--step-limit',type=int,default=2000000)
    args=ap.parse_args()
    if args.cmd=='inspect':
        print_inspect(inspect(args.input),args.json); return
    if args.cmd=='traps':
        info=inspect(args.input); traps=(info['appended'] or {}).get('traps',[])
        if args.json: print(json.dumps(traps,sort_keys=True,indent=2)); return
        for t in traps:
            sn='?' if t['syscall'] is None else str(t['syscall'])
            print('0x%08X  syscall=%s  %s' % (t['pc'],sn,t['name']))
        return
    if args.cmd=='convert':
        report=convert(args.input,args.output,args.workdir,args.label,args.step_limit)
        print('wrote',args.output)
        print('sha256',report['output']['sha256'])
        print('report',str(Path(args.output).with_suffix(Path(args.output).suffix+'.json')))

if __name__=='__main__':
    main()
