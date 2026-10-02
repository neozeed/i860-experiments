# R4S — native SIM860 precision-exception compatibility

Replace sim860-i386-pe.exe with this build. Keep the working N1.3 simulator.
From the directory containing gcd:

```bat
set SVR3COFF2PE_TRACE=
sim860-i386-pe.exe gcd
sim860-i386-pe.exe -d gcd
```

In the debugger: `:r _start`. Quit with `$q`.

## Diagnosis

The live R4R exception C000008F is STATUS_FLOAT_INEXACT_RESULT. The exception
PC 0050B83F maps to original B90F (`fstp qword [0041304c]`), after the reciprocal
FDIV at B909. The register evidence is consistent with an operand of 462.0.
Intel enables x87 precision exceptions and installs a Unix SIGFPE handler;
the native runtime did not deliver that signal. Unicorn's arithmetic replay
passed while physical x87 exception delivery on Windows terminated the process.

## Exact change

Only the fingerprinted SIM860 1.1 target gains three code hooks:

- C760 and C784: Intel's single/double precision preparation helpers temporarily
  mask precision exception #P, preserving all other exception masks and the
  original precision-control/rounding choices.
- C79C: the common restore helper checks the sticky precision flag. If precision
  was originally enabled, it records that condition and calls original C3F0,
  the precision-only cleanup tail used by Intel's SIGFPE handler. Intel clears
  sticky exceptions and restores its policy. The saved control word is then
  restored. Originally masked precision events do not synthesize delivery.

This defers precision handling to the arithmetic-helper boundary. It does not
skip the division or store, flush subnormals, mask all FP exceptions, or implement
general asynchronous signals. Invalid/divide-by-zero/overflow/underflow recovery
is still outside this fix. Some other FP paths may still need signal support.

The original COFF is preserved verbatim in the PE. verify_sim860.py accounts
for all prior relocations plus the three new hooks. Runtime code is in
sim_fp_runtime.py; the arithmetic opcode implementation remains Intel's.

## Validation

- Real x87 hardware probe with 1.0 / 462.0 and control word 0240: the unmasked
  sequence raises SIGFPE; precision-masked execution produces the correct bits,
  retains the precision status, clears it during cleanup, and restores 0240.
  This is a native arithmetic probe, not execution of the full Windows PE.
- Exact assembled PE bridge tested in Unicorn with an explicitly supplied FSW:
  enabled/pending precision dispatches the Intel cleanup tail; masked precision
  and no-exception cases do not. Registers and control word are preserved.
- Twelve full PE instruction replays (Win32 imports mocked): console output,
  direct exit, debugger operation, and nine remainder cases including 1071%462
  = 147 and the previous high-bit/boundary operands. This exercises the supplied
  u.o and uimod.o, not a replacement arithmetic helper.
- Independent byte accounting passes. Compiler, driver and assembler runtime
  sections remain identical to R4R. Earlier binaries are retained, including
  sim860-i386-r4r.exe for comparison.

**Windows live retest remains pending.** The user's actual gcd executable was
not available locally; the arithmetic fixtures are included in validation/sim860.

Rebuild with `python3 build_all.py`. Verify with:

```
python3 verify_sim860.py
python3 validation/sim860/test_replay.py
python3 validation/sim860/test_precision_bridge.py
python3 validation/sim860/test_x87_native.py
```

Replay tests require Unicorn; native probe requires x86 Linux and gcc.
See README-R4R.md for the original conversion audit and remaining runtime limits.
