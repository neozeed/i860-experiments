# Handoff — unified Intel i860 N1.x tools on Win32

## What this package is

`i860fat2pe.py` is the canonical source for the recovered Intel N1.x fat-tool family. It recognizes the exact shared SVR3/i386 `run860` wrapper, preserves that wrapper and the appended i860 COFF payload byte-for-byte in the generated PE, redirects the historical wrapper syscall gates into a Win32-hosted SVR3 personality, and executes the untouched i860 payload with one common functional i860 interpreter.

Do not create new AS860/LD860/SIZE860/SIM860 CPU forks. If an opcode, syscall, diagnostic policy or execution rule changes, change the common runtime and rebuild all four.

## Proven historical inputs

- AS860 original: SHA256 `1047696d2c6581bc2f99a2572ef62d1a0664156a3dd490d3e94e6d69ac85bf2f`, 179,078 bytes.
- LD860 original: SHA256 `ee296b923cbf17af83e8b5dc4d5a47b2e24a2b713a98d271b891fefd5cebe0f4`, 108,902 bytes.
- SIZE860 original: SHA256 `ada5c8911cc7b3541a12c97da8b1d09322c857c7717d5bb12390c5229d8946e7`, 41,592 bytes.
- SIM860 original: SHA256 `faf27718654c64e0b9c4bc8ed0efea10d78239ffd6f62a0985a13290f1818137`, 351,494 bytes.
- Shared wrapper: 4,262 bytes, SHA256 `9c0007b43b93b13f1f06f75832c61a44c5276e59860113ebdc6b04896b784023`.

The package includes the exact originals under `originals/` for reproducibility.

## Live / independent proof history to preserve

1. SIM860's outer SVR3/i386 wrapper was converted to PE and its embedded i860 COFF payload was identified and executed.
2. The interpreter grew from a bounded integer/control smoke test into a substantial user-mode i860 core by stopping at the first unsupported real instruction and implementing only documented semantics.
3. AS860 N1.3 ran as untouched i860 code and assembled real sources. `hello.s` produced a real i860 COFF object; later GCC-generated input exposed `fiadd.dd/fmov.dd` and `fadd.dd` gaps.
4. LD860 N1.3 linked real objects. Its `chmod(15)` output-finalization call is part of the common personality.
5. SIZE860 independently processed a linked i860 executable and produced the expected size report; its predecessor package is build/static + independent replay proven, with Windows live test historically pending.
6. SIM860 N1.3 itself runs as i860 code inside the outer interpreter and then simulates another i860 program. A hand-written target printed `hi from i860` and exited 0 through Intel SIM860.
7. GCC 1.40's i860 backend generated an unmodified `gcd.s` that Intel AS860 N1.3 accepted. Intel LD860 linked the resulting objects, and a live Windows run under Intel SIM860 printed:

   `GCC i860 GCD PASS`

   and exited 0.

This establishes practical GCC 1.40 / Intel N1.3 assembler-linker-simulator interoperability for the tested integer case. GCC's own source later supplied the historical clue: its i860 backend had been substantially adjusted for the System V Release 4 assembler.

## Important correction from the exploration

An intermediate hand-written `___umodsi3` repeated-subtraction helper had its unsigned branch sense wrong and could underflow/spin. Do **not** treat that intermediate helper as canonical libgcc. It is intentionally omitted from this final package. Keep division/remainder helpers supplied by a known-correct runtime/system compiler or validate them independently.

## Production policy

- No target-specific success oracle inside production executables.
- A program is successful when the actual guest/tool exits successfully, not because it happens to reach a test PC/register pattern.
- Target-specific PC/register expectations belong only in tests.
- Default host scaffolding is quiet; `I860_VERBOSE=1` enables it.
- Faults and unsupported instructions must remain visible even in quiet mode.
- The 20M instruction count is a safety ceiling only.
- Unknown instructions and syscalls stop loudly. Do not guess semantics merely to get farther.

## What is *not* complete

This is not a full i860 machine emulator. The functional interpreter covers the scalar/user-mode subset encountered by real workloads so far. It does not claim complete pipeline-mode FP behavior, graphics instructions, MMU/TLB/cache/bus modeling, interrupts, precise exception/restart semantics, complete privileged state, or cycle accuracy.

The SVR3 personality is likewise narrow. Signals are not generally delivered asynchronously. Filesystem/path and metadata semantics are compatibility-oriented, not a complete Unix kernel personality.

`i860fat2pe.py` is generic across the **fingerprinted Intel run860 fat-tool family**, not arbitrary Xenix/SCO/SVR3 COFF executables. The separate native `svr3coff2pe` work on ICC/IC is a different family and should remain profile/audit driven.

## Recommended next steps

1. Windows smoke-test these unified binaries: `as860.exe hello.s`, `ld860.exe ...`, `size860.exe <linked-file>`, and `sim860.exe <target>`.
2. Freeze R1 if those regressions pass.
3. Any next opcode discovered by any tool goes into `runtime/proven_intel860_base.py`, followed by rebuilding and verifying all four.
4. Add runtime-configurable step-limit parsing only if 20M is genuinely inconvenient; do not reintroduce SIM-specific target-load heuristics.
5. If pursuing GCC/libgcc, recover or build correct i860 runtime helpers rather than relying on the discarded bootstrap remainder helper.
6. Keep the native ICC/IC COFF->PE work separate from this fat family. They share ideas but not the same binary architecture.

## Useful smoke tests

Assembler:

```bat
as860.exe examples\hello.s -o hello.o
```

Simulator, after producing/linking a target:

```bat
sim860.exe target
```

Expected clean output for the known hello target is Intel's simulator banner followed by `hi from i860` and exit status 0.

Verbose troubleshooting:

```bat
set I860_VERBOSE=1
sim860.exe target
```
