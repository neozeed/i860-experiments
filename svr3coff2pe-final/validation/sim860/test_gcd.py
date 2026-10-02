"""Actual PE replay: corrected GCD plus wrong-answer controls."""
from pathlib import Path
import subprocess,sys,struct,json
here=Path(__file__).resolve().parent
root=here.parent.parent
original=(root/'examples/gcd/gcd-original').read_bytes()
fixed=(root/'examples/gcd/gcd-fixed').read_bytes()
p=bytearray(original)
assert struct.unpack_from('<II',p,0xd4)==(0x8a208000,0x7000000a)
struct.pack_into('<II',p,0xd4,0xf2208000,0x7800000a)
assert p==fixed
cases=[('gcd-original',original,1),('gcd-fixed',fixed,0)]
for expected in (20,22):
 p=bytearray(fixed);struct.pack_into('<I',p,0xd0,0x94110000|expected)
 cases.append(('gcd-expect-'+str(expected),p,1))
for name,data,status in cases:
 (here/'fixtures'/name).write_bytes(data)
 r=subprocess.run([sys.executable,str(here/'pe_replay.py'),name],check=True,capture_output=True,text=True)
 result=json.loads(r.stdout.strip().splitlines()[-1])
 assert result['exit']==status,(name,r.stdout)
 assert ('GCD PASS' if status==0 else 'GCD FAIL') in r.stdout
 print('PASS',name,'expected exit',status)
