#!/usr/bin/env python3
from pathlib import Path
import argparse, hashlib, json, shutil, subprocess, sys, tempfile
ROOT=Path(__file__).resolve().parent
EXPECTED_ORIGINALS={
 'as860':('1047696d2c6581bc2f99a2572ef62d1a0664156a3dd490d3e94e6d69ac85bf2f',179078),
 'ld860':('ee296b923cbf17af83e8b5dc4d5a47b2e24a2b713a98d271b891fefd5cebe0f4',108902),
 'size860':('ada5c8911cc7b3541a12c97da8b1d09322c857c7717d5bb12390c5229d8946e7',41592),
 'sim860':('faf27718654c64e0b9c4bc8ed0efea10d78239ffd6f62a0985a13290f1818137',351494),
}
WRAPPER='9c0007b43b93b13f1f06f75832c61a44c5276e59860113ebdc6b04896b784023'
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def fail(s): raise SystemExit('VERIFY FAIL: '+s)
for name,(want,n) in EXPECTED_ORIGINALS.items():
 p=ROOT/'originals'/name
 if not p.exists() or p.stat().st_size!=n or sha(p)!=want: fail('original '+name)
for name in EXPECTED_ORIGINALS:
 p=ROOT/'bin'/(name+'.exe'); rp=Path(str(p)+'.json')
 if not p.exists() or not rp.exists(): fail('missing output '+name)
 r=json.loads(rp.read_text())
 if r['wrapper']['sha256']!=WRAPPER or not r['wrapper']['fingerprint_match']: fail('wrapper '+name)
 if not all(r['output']['checks'].values()): fail('static checks '+name)
 if r['runtime']['step_limit']!=20000000: fail('step limit '+name)
 if 'I860_VERBOSE' not in r['runtime']['diagnostics']: fail('diagnostics '+name)
# Strong anti-drift assertion: generated CPU source is identical for all four profiles.
cpu_hashes={sha(ROOT/'build'/n/'sim860-r10-cpu.c') for n in EXPECTED_ORIGINALS}
if len(cpu_hashes)!=1: fail('tool-specific CPU source drift: '+repr(cpu_hashes))
cpu=(ROOT/'build'/'as860'/'sim860-r10-cpu.c').read_text()
for token in ('0x480001c9u','0x480001b0u','host_force_verbose','20000000u'):
 if token not in cpu: fail('common CPU missing '+token)
for n in EXPECTED_ORIGINALS:
 host=(ROOT/'build'/n/'sim860-r10-host.S').read_text()
 for token in ('I860_VERBOSE','host_force_verbose'):
  if token not in host: fail(n+' host missing '+token)
print('static verification PASS')
print('common CPU sha256',next(iter(cpu_hashes)))
if '--rebuild' in sys.argv:
 with tempfile.TemporaryDirectory(prefix='i860fat-verify-') as td:
  td=Path(td)
  for n in EXPECTED_ORIGINALS:
   out=td/(n+'.exe'); work=td/('build-'+n)
   subprocess.run([sys.executable,str(ROOT/'i860fat2pe.py'),'convert',str(ROOT/'originals'/n),'-o',str(out),'--workdir',str(work)],check=True,stdout=subprocess.DEVNULL)
   if out.read_bytes()!=(ROOT/'bin'/(n+'.exe')).read_bytes(): fail('non-deterministic rebuild '+n)
 print('deterministic rebuild PASS')
