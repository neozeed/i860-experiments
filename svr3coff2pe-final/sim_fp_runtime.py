"""Exact SIM860 1.1 precision-exception bridge.

Only precision (#P) is masked during arithmetic wrappers. Other exception masks,
precision control and rounding modes retain Intel's values. At the common restore
helper, a formerly enabled precision event takes the original SIGFPE handler's
precision-only tail (c3f0). This clears sticky flags and reestablishes Intel's FP
policy before restoring the saved control word. No blanket exception swallowing.
"""
import struct
SITES=((0xc760,'25fffcffff','sim_fp_prepare',0xe8),
       (0xc784,'25fffcffff','sim_fp_prepare',0xe8),
       (0xc79c,'558becd92d70304100c9c3','sim_fp_finish',0xe9))
def asm_source():
 return r'''
.section .text
.global sim_fp_prepare
.global sim_fp_finish
sim_fp_prepare:
    and eax,0xfffffcff         /* displaced Intel precision-control mask */
    or eax,0x20               /* #P is delivered synchronously at finish */
    ret
sim_fp_finish:
    pushfd
    pushad
    fnstsw ax
    test ax,0x20
    jz sim_fp_restore
    test WORD PTR ds:[0x00413070],0x20
    jnz sim_fp_restore        /* originally masked: no synthetic signal */
    movzx eax,ax
    and eax,0x220             /* precision status and its rounding indication */
    mov DWORD PTR ds:[0x004134f0],eax
    /* Exact precision-only SIGFPE path: c0c0 -> c215 -> c2be -> c3f0.
       No register-stack fixups or invalid/overflow/underflow paths apply. */
    mov eax,0x0050c320        /* relocated original c3f0 */
    call eax
sim_fp_restore:
    popad
    popfd
    fldcw WORD PTR ds:[0x00413070]
    ret
'''
def patch(text,syms,old_text,new_text):
 t=bytearray(text);records=[]
 for va,encoding,symbol,opcode in SITES:
  off=va-old_text;expected=bytes.fromhex(encoding)
  assert t[off:off+len(expected)]==expected,(hex(va),'FP hook bytes differ')
  # The restore routine is wholly replaced, using complete instructions.
  replacement=bytes([opcode])+struct.pack('<I',(syms[symbol]-(new_text+off+5))&0xffffffff)
  replacement+=b'\x90'*(len(expected)-5)
  t[off:off+len(expected)]=replacement
  records.append({'kind':'sim_precision_bridge','old_va':va,'expected':encoding,
                  'replacement':replacement.hex(),'target':syms[symbol]})
 return bytes(t),records
