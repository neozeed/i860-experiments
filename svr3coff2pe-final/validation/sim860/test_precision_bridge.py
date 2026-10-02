"""Exercise exact assembled PE bridge with a pending x87 precision flag.
Unicorn does not reproduce native #P delivery, so this explicitly supplies FSW.
"""
from pathlib import Path
import contextlib,io,json,runpy,sys
from unicorn.x86_const import *
here=Path(__file__).resolve().parent;root=here.parents[1]
sys.argv=['pe_replay.py','exit860']
with contextlib.redirect_stdout(io.StringIO()):env=runpy.run_path(str(here/'pe_replay.py'))
u,wr,rd=env['u'],env['wr'],env['rd']
meta=json.loads((root/'sim860-i386-pe.exe.json').read_text())
target=next(x['target'] for x in meta['patches'] if x['kind']=='sim_precision_bridge' and x['old_va']==0xc79c)
results=[]
for cw,sw,deliver in [(0x0240,0x20,True),(0x0260,0x20,False),(0x0240,0,False)]:
 u.reg_write(UC_X86_REG_ESP,0x701e0000);wr(0x701e0000,0x6800fff0)
 wr(0x413070,cw);wr(0x4134f0,0xabcdef00);wr(0x411f60,0)
 u.reg_write(UC_X86_REG_FPCW,cw|0x20);u.reg_write(UC_X86_REG_FPSW,sw)
 for reg in [UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX,UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EBP]:u.reg_write(reg,0x13572468)
 u.emu_start(target,0x6800fff0,count=10000)
 assert u.reg_read(UC_X86_REG_EIP)==0x6800fff0
 assert u.reg_read(UC_X86_REG_FPCW)==cw
 assert rd(0x4134f0)==(0x20 if deliver else 0xabcdef00)
 if deliver:assert u.reg_read(UC_X86_REG_FPSW)&0xff==0
 for reg in [UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX,UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EBP]:assert u.reg_read(reg)==0x13572468
 results.append({'cw':hex(cw),'sw':hex(sw),'precision_tail_called':deliver})
 print('PASS precision bridge',results[-1])
(here/'precision-bridge-results.json').write_text(json.dumps(results,indent=2)+'\n')
