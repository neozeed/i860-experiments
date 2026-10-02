# i860fat2pe R1 — unified Intel N1.x fat-tool runtime

This is the consolidation/handoff package for the Intel i860 tool work.

The important architectural change is that **AS860, LD860, SIZE860 and SIM860 are no longer separate runtime forks**. They are four payloads built through the same converter and the same generated i860 CPU/System V personality.

The supported input family is the proven Intel N1.x “fat tool” format:

```
SVR3/i386 COFF run860 wrapper
        +
embedded Intel i860 COFF executable
```

All four supplied originals have the same 4,262-byte wrapper (SHA256 `9c0007b43b93b13f1f06f75832c61a44c5276e59860113ebdc6b04896b784023`). `i860fat2pe.py` fingerprints that wrapper before it will convert anything.

## Ready-to-run Windows builds

`bin/` contains PE32/i386 builds of:

- `as860.exe`
- `ld860.exe`
- `size860.exe`
- `sim860.exe`

They were all generated from the exact same CPU source. `verify.py` asserts that this remains true so an opcode fix cannot silently land in only one tool again.

## Diagnostics

Normal host/runtime scaffolding is quiet. Intel's own output and target-program output remain visible.

```bat
set I860_VERBOSE=1
sim860.exe gcd
```

enables the common loader/interpreter diagnostics for any of the four tools. Real faults force diagnostics on even when quiet.

The generic execution safety ceiling is **20,000,000 outer i860 instructions/services**. It is only a guardrail, never a success oracle. Rebuild a tool with `--step-limit N` if a legitimate workload needs more.

## Build

On Linux or WSL with GNU binutils and 32-bit GCC support:

```sh
python3 build_known.py
python3 verify.py --rebuild
```

The converter deliberately retains the proven ELF32 build scaffold (`as --32`, `gcc -m32`, `ld -m elf_i386`, `objcopy`). macOS's Apple assembler is not a drop-in replacement; use WSL/Linux or a compatible GNU ELF32 toolchain rather than changing object formats casually.

To convert another copy of a proven-family binary:

```sh
python3 i860fat2pe.py inspect path/to/tool
python3 i860fat2pe.py traps path/to/tool
python3 i860fat2pe.py convert path/to/tool -o tool.exe
```

## Current common runtime surface

The common System V personality includes the services reached by the recovered Intel tools, including exit/read/write/open/close/creat/unlink/time/chmod/brk/stat/lseek/getpid/getuid/fstat/access/getgid/signal/utssys. File I/O is binary-safe and backed by Win32 HANDLEs. `chmod` validates the path and accepts Unix mode bits as a Win32 compatibility no-op. Signal registration is compatibility-level only; asynchronous signal delivery is not a general implementation.

The i860 interpreter is workload-driven rather than architecturally complete. Important real-workload additions now shared by every tool include `ixfr`, `fxfr`, `fmlow.dd`, `bla`, floating loads/stores, `fiadd.ss/fmov.ss`, **`fiadd.dd/fmov.dd`**, **`fadd.dd`**, `fsub.dd`, `frcp.dd`, `fmul.dd`, and `ftrunc.dd`.

## Status wording

The underlying behavior is extensively proven in the predecessor builds, including the live GCC 1.40 -> Intel AS860 -> Intel LD860 -> Intel SIM860 GCD run. **These newly unified PE binaries are a deterministic build/static consolidation and still deserve one Windows smoke pass before being called live-proven as a package.**

See `docs/HANDOFF.md` for the chronology, exact proof boundary, known limitations, and recommended next steps.
