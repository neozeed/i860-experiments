# SVR3COFF2PE R4R — native i386 Intel SIM860 1.1

New executable: **sim860-i386-pe.exe**. Keep your working i860-hosted N1.3
sim860.exe alongside it. This release runs Intel's x86 simulator directly on
Windows; there is no outer i860 interpreter and no appended i860 simulator.

## Windows test

Place sim860-i386-pe.exe beside your linked gcd file:

```bat
sim860-i386-pe.exe gcd
sim860-i386-pe.exe -d gcd
```

At the debugger prompt:

```
:r _start
$q
```

The expected target message is `GCC i860 GCD PASS`, followed by Intel's process
termination report. Your actual gcd binary is not included in this archive and
has NOT been tested here. The expected result follows your N1.3 live test;
Release 1.1 still needs that compatibility check on Windows.

For a self-contained first test, from the package directory:

```bat
sim860-i386-pe.exe validation\sim860\fixtures\hello860
```

Expected target line: `Native i386 SIM860 target write PASS`, then return 0.
For diagnostic logs use `set SVR3COFF2PE_TRACE=3` (see runtime source for trace setting)
and redirect stdout/stderr to a file. Clear the variable after testing.

## What passed locally

- PE layout, section permissions, exact original-file preservation and independent
  byte accounting for every changed historical text/data byte.
- Eleven runs of the actual PE machine code under Unicorn x86 emulation, mocking
  only imported Win32 APIs. This executes the bootstrap, relocated original
  simulator, syscall gate handlers, fd table and guest heap handling.
- Direct exit, target write/exit and debugger `:r _start` / `$q`.
- Eight unsigned remainder cases using the supplied compiled u.o wrapper and
  original uimod.o helper, with full 32-bit r16 checked (not truncated exit codes):
  0%7, 17%5, 5%17, 7%1, 0x80000000%7, 0xfffffffe%0xffffffff,
  0xffffffff%3, 0xffffffff%0x80000000.
- IC and PGC AS860 independent regression verifiers pass; ICC and all three
  other native targets rebuild with the same bundled runtime. Their historical
  executable-code and initialized-data sections match R4Q.

This is **static + emulated PE execution evidence**, not a Windows live run.
No speed measurement has been made. The nested interpreter layer is eliminated.

## Audit

Original SHA256: 928de5a562d0307ef94df5bd5078b10e3180439f5ae65c73db4dc38f51c6cb9a
Original size: 240752 bytes; stripped SVR3 i386 COFF; banner Release 1.1.
Native text: 163096 bytes at 0xd0, entry 0xd4; relocated to 0x500000.
Data stays at 0x400de8; initial break 0x418c48.

Exact manifest: 55 selector-7 gates, one selector-15 gate, seven complete
instruction operands and 809 unique data dispatch slots. The latter comprise
40 range-checked switch tables and the 64-entry main / 65-entry FP dispatch
arrays. The seven operands are five signal-handler arguments and two signal
return addresses. Input SHA256 and expected instruction encodings are checked.
No numeric-match relocation of unrelated integers is performed.

The special indirect call through 0x400ee0 is inside the main opcode array.
The final libc indirect call reads a runtime-populated argument block rather
than another initialized function-pointer table.

## Rebuild / verification

Linux/WSL: Python 3, GNU as/ld/objcopy/nm/objdump, and gcc with 32-bit compilation.

```
python3 build_all.py
python3 verify_sim860.py
python3 verify_r4o.py ic-pe.exe
python3 verify_as860.py as860-pe.exe
python3 validation/sim860/test_replay.py
```

Only the last command additionally requires Python package `unicorn`.
The fixture builder is deliberately specific to these known objects and the
single call relocation; it is not a general i860 linker. Fixture sources,
objects and generated executables are included under validation/sim860.

## Scope

Existing converted binaries remain included: IC, ICC, PGC AS860, and the
preserved historical IC R4O / AS860 R4P builds. build_all.py now includes the
native simulator. R10V/N1.3 is a separate project and is not replaced by this ZIP.

Existing runtime limitations still apply: no asynchronous Unix signal delivery
(Ctrl-C and floating-point signal recovery are not implemented); stat is a
compatibility subset; historical heap is bounded at 0x4f0000. Unsupported Unix
syscalls are diagnosed explicitly. These tests cover compiler-generated integer
arithmetic and the specific FP-assisted remainder helper, not the full i860 ISA.
