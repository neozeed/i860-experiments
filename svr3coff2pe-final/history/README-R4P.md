# SVR3COFF2PE R4P — native Portland Group as860 target

The included as860-pgc.exe is the Windows conversion of the uploaded native
SVR3/i386 Portland Group assembler. Keep the old Intel N1.3 assembler separately.

## Windows test

Use the same working directory and temp-directory settings as the successful IC
run. Use as860-pgc.exe to assemble the unmodified compiler-generated u.s:

    set SVR3COFF2PE_TRACE=3
    as860-pgc.exe -o u.o u.s > as860-pgc-run.txt 2>&1
    echo ExitCode=%ERRORLEVEL%>>as860-pgc-run.txt

Return as860-pgc-run.txt and u.o if created. This is the first native Windows
runtime test for this target. Do not treat a pre-existing u.o as new output.
The syntax dialect is expected to match PGC IC; that still requires live proof.
The spelling of mth_i_uimod versus _mth_i_uimod in the Intel runtime object also
needs checking in the newly assembled object's symbols before linking.

## Rebuild under Linux / WSL

    python3 svr3coff2pe.py inspect as860.coff
    python3 svr3coff2pe.py convert as860.coff -o as860-pgc.exe --workdir work-as860
    python3 verify_as860.py

No force flag is needed. The exact recognized SHA-256 is:
66c441db201bdc9f93f310b669ab3da22191004fcf5d70ec40187dbeed054288

Python 3 and GNU gcc/as/ld/objcopy/objdump/nm/readelf are required. The host stub
is compiled as a 32-bit object. IC and the native assembler share one syscall
runtime, PE builder, raw instruction decoder, COFF symbol reader and relocation
patch engine. native_as_profile.py holds the assembler's audited constants.

## Audited assembler layout

- Original text 0xD0, size 100400; entry 0xD4; relocated entry 0x500004.
- Initialized data 0x400900, size 37764; BSS 0x409C84, size 6592.
- Initial break and lower heap limit 0x40B644; upper limit 0x4F0000.
- libc current-break word 0x409C80; allocator state 0x409C68..0x409C78.
- 13 verified selector-7 gates; two qsort callback operands at original PCs
  0x42CC -> v_comp(0x44A0), 0x43AF -> p_comp(0x44D4).
- Six jump tables with lengths checked against preceding branch bounds:

| Jump PC | Data base | Entries |
| --- | --- | --- |
| 0xE0A | 0x404AC8 | 271 |
| 0xF30 | 0x404AA4 | 9 |
| 0x52E5 | 0x406378 | 8 |
| 0x5618 | 0x406398 | 18 |
| 0xFBF3 | 0x406900 | 13 |
| 0x16C4A | 0x40913C | 89 |

Total: 408 dispatch slots. Every target is checked against a decoded instruction
boundary. No arbitrary text-byte scans or data-symbol guesses are used.

Unknown native fingerprints now fail early with an actionable message, without
assembling a host stub or raising the old IC fingerprint traceback. The old
--force-native-heuristic option is retained solely for command-line compatibility;
it cannot bypass the audited-profile requirement.

## Verification and status

AS860: BUILD/STATIC VERIFIED, WINDOWS RUNTIME UNTESTED.
IC R4O: the supplied original executable is retained unchanged and was previously
proven by the user's void.c and u.c compilation runs. Rebuilding IC through R4P
produced byte-identical .svtext, .svmem, .host, .hdata, .idata and .orig386 sections.
Only release metadata differs. Its original R4O verifier also passes.

The assembler verifier reconstructs expected code/data changes independently of
the patch list and compares entire sections, checking that all other bytes remain
original. Converter layout/permission/gate/original-image checks pass as well.
The shared runtime's time result remains the deterministic compatibility value;
this release does not add new syscall semantics or claim linked i860 execution.

Contents include the frozen IC R4O executable and sources, the new assembler
executable and exact original input, converter sources and verification reports.
README-R4O.md documents the earlier compiler repair; this file is the current
release entry point.
