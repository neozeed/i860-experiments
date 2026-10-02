#!/usr/bin/env python3
"""Rebuild every currently supported bundled native target from the same runtime."""
from pathlib import Path
import subprocess,sys
root=Path(__file__).resolve().parent
for source,output in [('ic','ic-pe.exe'),('icc','icc-pe.exe'),('as860.coff','as860-pe.exe'),('sim860.coff','sim860-i386-pe.exe')]:
 subprocess.run([sys.executable,str(root/'svr3coff2pe.py'),'convert',str(root/source),'-o',str(root/output),'--workdir',str(root/'build'/source)],check=True)
print('Rebuilt IC, ICC, PGC AS860 and native Intel SIM860. Preserved historical filenames are untouched.')
