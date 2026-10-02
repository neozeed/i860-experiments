"""Requires unicorn. Runs packaged PE code; only Win32 imports are modeled."""
import json,subprocess,sys
from pathlib import Path
here=Path(__file__).resolve().parent
results=[]
for args,expected in [(['exit860'],0),(['hello860'],0),(['-d','exit860'],0)]+[( [p.name], int(p.name.split('-')[1],16)%int(p.name.split('-')[2],16)) for p in sorted((here/'fixtures').glob('umod-*'))]:
 r=subprocess.run([sys.executable,str(here/'pe_replay.py'),*args],capture_output=True,text=True,check=True)
 result=json.loads(r.stdout.splitlines()[-1])
 assert result['target_r16']==expected,(args,result,expected)
 assert 'Process terminated, returned value:' in r.stdout,(args,r.stdout)
 assert result['exit']==(0 if args[0]=='-d' else expected),(args,result)
 if args==['hello860']:assert 'Native i386 SIM860 target write PASS' in r.stdout
 results.append({'args':args,'expected_r16':expected,'result':result})
 print('PASS',*args,'r16='+str(expected))
print('PASS', len(results), 'actual-PE replays; Windows APIs mocked')
(here/'replay-results.json').write_text(json.dumps(results,indent=2)+'\n')
