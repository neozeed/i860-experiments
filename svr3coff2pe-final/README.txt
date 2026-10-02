SVR3COFF2PE — final toolkit / R4S runtime baseline
2026-10-02

Reusable, profile-based SVR3 COFF analyzer and Windows PE32 converter.
The delivered native binaries are unchanged from the live-tested R4S package.
This is a packaging/documentation milestone, not a new runtime revision.

QUICK START — WINDOWS
Extract the whole directory. No Python is needed to run the supplied EXEs.
From this directory:
  set SVR3COFF2PE_TRACE=
  sim860-i386-pe.exe examples\gcd\gcd-fixed
Expected: GCC i860 GCD PASS; returned value: 0.
  icc-pe.exe -v -c your-source.c -o your-source.o
Keep icc-pe.exe, ic-pe.exe and as860-pe.exe together and available in PATH.
Use the working directory/temp setup already used by your compiler installation.
Headers, libraries and a linker are not supplied as a complete SDK.

CURRENT TOOLS
  icc-pe.exe          compiler driver (launches converted child tools)
  ic-pe.exe           native i386-hosted i860 C compiler
  as860-pe.exe        native i386-hosted PGC assembler
  sim860-i386-pe.exe  native i386-hosted Intel simulator 1.1, R4S FP bridge
Historical binaries are also preserved: ic-pe-r4o.exe, as860-pgc.exe,
sim860-i386-r4r.exe. R4R simulator has the known Windows precision trap;
use the current simulator for execution.

GENERIC INTERFACE — LINUX / WSL
  python3 svr3coff2pe.py inspect INPUT
  python3 svr3coff2pe.py inspect INPUT --json
  python3 svr3coff2pe.py traps INPUT --json
  python3 svr3coff2pe.py convert INPUT -o OUTPUT.exe --workdir work/target
  python3 build_all.py
-o names an output FILE, not a directory. Give each build a separate workdir.

The interface accepts arbitrary input filenames. Successful native conversion
requires a recognized audited binary profile; renaming a file does not change
its fingerprint. Unknown native binaries are intentionally rejected.
--force-native-heuristic is a deprecated compatibility option, not a bypass.
The tool is extensible, not a universal arbitrary-COFF translator.

SUPPORTED FAMILIES
1. Exact native static SVR3/i386 profiles: IC, ICC, PGC AS860, Intel SIM860 1.1.
   These execute historical x86 machine code directly through a Windows runtime.
2. Intel run860 wrapper plus appended i860 COFF payload: retained fat_family.py
   converter path and bundled interpreter/runtime source. It requires the proven
   wrapper layout/fingerprint. Its retained runtime is not claimed equivalent
   to the later separately maintained N1.3/R10F simulator package.

This archive does not replace or include the separately delivered working
sim860.exe N1.3, LD860, SIZE860 or a complete GCC 1.40 installation. Keep those
existing tools. The native toolkit's previously bundled EXEs are all retained.

BUILD REQUIREMENTS
Python 3; GNU gcc with 32-bit object compilation support, as, ld, objcopy,
objdump, nm and readelf. Linux/WSL is the supported build workflow. No MinGW
compiler is required by this builder. The result is PE32 for Windows x86/WOW64.
The optional instruction replay tests require Python package unicorn.
  python3 build_all.py
  python3 verify_r4o.py ic-pe.exe
  python3 verify_as860.py as860-pe.exe
  python3 verify_sim860.py
  python3 validation/sim860/test_replay.py
  python3 validation/sim860/test_gcd.py
  python3 validation/sim860/test_precision_bridge.py
  python3 validation/sim860/test_x87_native.py
The last command tests native x87 behavior on a suitable x86 host, not Windows.

READ NEXT
HANDOFF.txt: architecture, profile extension, limitations and evidence.
examples/gcd/NOTES.txt: corrected startup and provenance.
validation/final-checks.txt: packaging verification output.
SHA256SUMS.txt: current archive contents; excludes itself.
BINARIES.json: executable inventory with hashes and roles.
history/: previous milestone notes; their status statements are historical.
