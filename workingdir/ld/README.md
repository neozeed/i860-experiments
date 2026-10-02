# LD860 PE R1 — ORIGINAL INTEL I860 LINKER RUNNING UNDER WIN32

## Status

BUILD / STATIC + INDEPENDENT END-TO-END ORACLE PASS. Windows runtime pending.

LD860 R1 applies the live-proven SIM860/AS860 execution architecture to Intel's original UNIX-hosted i860 linker. The outer SVR3/i386 wrapper is byte-for-byte identical to SIM860/AS860, so the proven PE vessel and wrapper syscall bridge transfer unchanged. The embedded i860 linker runs under the common bounded i860 CPU/System V personality.

The real `loop.o` produced by AS860 R3 is linked end-to-end by an independent replay into a genuine i860 COFF executable named `a.out`, and the linker exits status 0.

## Input identity

- original fat `ld860` SHA256: `ee296b923cbf17af83e8b5dc4d5a47b2e24a2b713a98d271b891fefd5cebe0f4`
- wrapper size: 4,262 bytes (`0x10A6`)
- wrapper SHA256: `9c0007b43b93b13f1f06f75832c61a44c5276e59860113ebdc6b04896b784023`
- wrapper is byte-for-byte identical to SIM860/AS860
- i860 linker payload size: 104,640 bytes
- i860 payload SHA256: `03515c06528a0268f68b5f934c3e601258c0fefc59ee3f81ccfcf7450143c349`

Linker payload layout:

- `.text`: guest `F04000C0`, size `000153C0`
- `.data`: guest `00001480`, size `00004440`
- `.bss`: guest `000058C0`, size `00000100`
- entry: `F040DBE0`
- identity string: `i860(TM) LINKER, Release N1.3`

## Static syscall inventory

There are 14 i860 `trap r31,r31,r0` sites in the complete linker text. Each has a literal syscall number loaded immediately before the trap.

Linked syscall surface:

- 1 `exit`
- 3 `read`
- 4 `write`
- 5 `open`
- 6 `close`
- 8 `creat`
- 10 `unlink`
- 13 `time`
- 15 `chmod`
- 17 `break` / `brk`
- 18 `stat`
- 19 `lseek`
- 28 `fstat`
- 57 `utssys` / `uname`

This is almost exactly the already-proven AS860 R3 personality. LD860 adds only syscall 15 (`chmod`) and does not link the AS860 `signal(48)` trap.

`chmod` is implemented as a deliberate compatibility semantic: the guest pathname is resolved and its existence validated, but the Unix execute/mode bits are not mapped onto Win32 attributes. This is sufficient for the linker's observed `chmod("a.out", 0755)` finalization.

File I/O remains binary-safe: Win32 `CreateFileA`, `ReadFile`, `WriteFile`, `SetFilePointer`, `CloseHandle`, and `DeleteFileA` are used directly rather than the Microsoft CRT text mode.

## Real link oracle

Input `loop.o`:

- size: 320 bytes
- SHA256: `a4ace9cbd76ef6b0ee508317d0e2bf54ab076827039c29ae7b151347bcc5b58b`
- Intel i860 COFF object produced by AS860 R3
- `.text`: 32 bytes
- `_start = 0`
- `loop = 0x0C`
- no relocations

Independent replay of:

```
ld860-r1.exe loop.o
```

executes **76,739 instructions/services** and exits status **0**.

Observed trap counts on this workload:

- `exit(1)`: 1
- `read(3)`: 2
- `write(4)`: 73 (72 console bytes + one 426-byte output-file write)
- `open(5)`: 3
- `close(6)`: 6
- `time(13)`: 1
- `chmod(15)`: 1
- `brk(17)`: 6
- `lseek(19)`: 7
- `utssys(57)`: 1

The historical linker banner is:

```
i860(TM) LINKER, Release N1.3
Copyright (C) 1989,1990 Intel Corporation
```

The file workflow opens `loop.o`, creates historical default output `a.out`, rereads the input while constructing output, writes `a.out`, closes it, then performs `chmod("a.out", 0755)`.

## Produced executable oracle

The linked `a.out` is a genuine Intel i860 COFF executable:

- size: **426 bytes**
- SHA256: `85b2531a8501e67731703cc2856515080338795d221b00c2985e83298e277528`
- COFF magic: `0x014D`
- sections: 3
- COFF timestamp: `1990-01-01 00:00:00 UTC`
- executable flags: `0x0003`
- entry: `F04000C0`
- `.text`: guest `F04000C0`, 32 bytes, zero relocations
- `.data`: guest `000010E0`, zero bytes
- `.bss`: guest `000010E0`, zero bytes
- symbol table: 11 entries including auxiliaries

The eight linked `.text` words are unchanged from the assembler output:

```
E410000A
E4110014
82328000
6BFFFFFF
A0000000
A0000000
A0000000
A0000000
```

`artifacts/a.out.oracle` is the exact independently replayed output.

## Windows runtime test

Put `ld860-r1.exe` and the supplied `loop.o` in the same directory and run:

```
ld860-r1.exe loop.o
echo %ERRORLEVEL%
```

Expected historical console output is the two-line Intel linker banner/copyright. The process should return **0** and create `a.out` in the current directory.

If WSL is available:

```
wsl sha256sum a.out
```

Expected:

```
85b2531a8501e67731703cc2856515080338795d221b00c2985e83298e277528  a.out
```

## Proof limitations

This is a narrow compatibility proof, not a general SVR3 implementation. `chmod` intentionally does not emulate Unix mode bits on NTFS; it validates the target and succeeds for the linker's historical executable-finalization step. `stat`/`fstat` expose only the compact SVR3 fields required by these Intel tools. Time and uname data are deterministic. Archive/library and relocation-heavy linker paths have not yet been runtime-proven.

## Files

- `artifacts/ld860-r1.exe` — converted PE32/i386 Intel linker
- `artifacts/ld860-r1-cpu.c` — generated i860 interpreter/personality
- `artifacts/ld860-r1-host.S` — generated Win32/SVR3 vessel
- `artifacts/ld860-r1-report.json` — conversion/build metadata
- `artifacts/ld860.wrapper386.coff` — preserved wrapper
- `artifacts/ld860.payload.i860.coff` — preserved linker payload
- `artifacts/a.out.oracle` — independently linked expected executable
- `loop.o` — real AS860 R3 input object
- `probe_link_r1.py` — independent end-to-end linker replay
- `tools/build_ld860_r1.py` — deterministic converter/builder
