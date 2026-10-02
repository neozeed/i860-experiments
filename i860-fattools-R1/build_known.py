#!/usr/bin/env python3
from pathlib import Path
import subprocess, sys
ROOT=Path(__file__).resolve().parent
TOOLS=('as860','ld860','size860','sim860')
for tool in TOOLS:
    src=ROOT/'originals'/tool
    out=ROOT/'bin'/(tool+'.exe')
    work=ROOT/'build'/tool
    if not src.exists():
        raise SystemExit('missing original: %s' % src)
    out.parent.mkdir(parents=True,exist_ok=True)
    subprocess.run([sys.executable,str(ROOT/'i860fat2pe.py'),'convert',str(src),'-o',str(out),'--workdir',str(work)],check=True)
print('rebuilt:', ', '.join(t+'.exe' for t in TOOLS))
