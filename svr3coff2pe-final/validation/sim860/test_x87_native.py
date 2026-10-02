"""Real x87 arithmetic test, complementary to exact PE bridge replay.
Requires x86/x86-64 Linux + gcc. It does not run the full PE on Linux.
"""
import json,resource,struct,subprocess,tempfile
from pathlib import Path
here=Path(__file__).resolve().parent
with tempfile.TemporaryDirectory() as tmp:
 exe=Path(tmp)/'probe'
 subprocess.run(['gcc','-O0',str(here/'x87_precision_probe.c'),'-o',str(exe)],check=True)
 def limits():resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 before=subprocess.run([str(exe)],capture_output=True,preexec_fn=limits)
 assert before.returncode==-8,('expected native SIGFPE',before.returncode,before.stdout,before.stderr)
 after=subprocess.run([str(exe),'masked-precision'],capture_output=True,preexec_fn=limits,check=True)
 bits,sw,cw=[int(x,16) for x in after.stdout.split()]
 assert bits==struct.unpack('<Q',struct.pack('<d',1.0/462.0))[0]
 assert sw&0x20 and cw==0x0240
 result={'unmasked_returncode':before.returncode,'masked_returncode':after.returncode,
         'reciprocal_bits':hex(bits),'precision_status':hex(sw),'restored_control_word':hex(cw),
         'scope':'Native x87 arithmetic sequence; exact PE bridge tested separately'}
 (here/'native-x87-results.json').write_text(json.dumps(result,indent=2)+'\n')
 print('PASS real x87: unmasked reciprocal raises SIGFPE; masked result correct; precision flag retained; original CW restored')
