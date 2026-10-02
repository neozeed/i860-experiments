# Intel i860 Tool Resurrection

**Running Intel's early-1990s UNIX i860 development tools on modern Windows.**

This project resurrects a collection of historical Intel i860 development tools originally built for **UNIX System V/386**, allowing them to run as ordinary 32-bit Windows PE executables.

The goal isn't to rewrite the tools.

It's to make the **original binaries run again**.

## The fun part

An original Intel i860 simulator can now run code produced by the recovered toolchain:

```text
C:\i860>sim860-i386-pe.exe gcd-fixed
SVR3 SIM860 i386: entering original UNIX System V/386 wrapper

i860(TM) SIMULATOR/DEBUGGER, Release 1.1
Copyright (C) 1989, Intel Corporation

GCC i860 GCD PASS
<< Process terminated, returned value: 0 >>
```

And the same binary runs under Intel's later simulator:

```text
C:\i860>sim860.exe gcd-fixed

i860(TM) SIMULATOR/DEBUGGER, Release N1.3
Copyright (C) 1989,1990 Intel Corporation

GCC i860 GCD PASS
<< Process terminated, returned value: 0 >>
```

That makes this more than a binary-format experiment: it provides a usable route into an **era-correct Intel i860 development environment**.

## What is this?

Several Intel i860 development tools were distributed as UNIX System V binaries.

Some are particularly interesting "fat" executables:

```text
+---------------------------+
| SVR3 / i386 wrapper       |
+---------------------------+
| Intel i860 COFF program   |
+---------------------------+
```

The outer program runs on the development workstation.

The embedded program runs on — or simulates — the i860.

This project provides enough machinery to bring those binaries back to life on Win32 without needing their original UNIX host.

Depending on the executable, this involves:

- parsing historical i386 COFF executables
- reconstructing their original memory layout
- relocating native i386 code where necessary
- translating old System V syscall entry points
- providing a small SVR3 compatibility personality
- preserving embedded i860 payloads
- loading Intel i860 COFF
- emulating the required i860 instruction set
- reproducing the original startup ABI
- implementing the observed System V calls
- supporting classic `fork -> exec -> wait` compiler-driver behaviour

The emphasis throughout is deliberately conservative:

**keep the historical program intact and emulate its environment rather than porting its source.**

## Why?

Mostly because it was there.

The Intel i860 occupies a wonderfully strange place in computing history. It appeared in graphics hardware, supercomputing systems and some very early operating-system development efforts, but its software ecosystem largely disappeared along with the machines that hosted it.

The binaries survived.

The machines they expected did not.

So the experiment became:

> How little of a 1990-era UNIX workstation do we need to recreate to make the original tools useful again?

The answer turned out to be: surprisingly little — although occasionally several thousand mysterious function pointers more than expected.

## What works?

The project has successfully exercised original Intel tooling including the i860 simulator and portions of the compiler toolchain.

Recovered functionality includes:

- native SVR3/i386 program execution
- historical COFF loading and relocation
- System V syscall translation
- file I/O
- heap / `brk` behaviour
- signal registration compatibility
- process orchestration for compiler drivers
- i860 COFF loading
- i860 integer/control execution
- floating-point instructions required by tested programs
- i860 System V syscall handling
- original Intel simulator execution
- GCC-generated i860 programs

The particularly satisfying end-to-end test is intentionally tiny:

```c
int gcd(int a, int b)
{
    while (b) {
        int t = a % b;
        a = b;
        b = t;
    }

    return a;
}
```

Compile it for the i860, feed the resulting binary to the resurrected simulator, and:

```text
GCC i860 GCD PASS
```

Thirty-five-year-old development software lives again.

## Architecture

There are really two compatibility problems here.

### SVR3/i386 host side

Historical native i386 tools are converted into PE32 vessels while preserving the original program logic.

The compatibility layer supplies the small part of UNIX System V that each program actually uses.

Conceptually:

```text
Original SVR3/i386 program
          |
          v
   syscall interception
          |
          v
  SVR3 personality layer
          |
          v
        Win32
```

This is **not** a general-purpose UNIX emulator.

Compatibility is implemented from observed requirements rather than by attempting to recreate an entire operating system.

### Intel i860 side

For tools containing an i860 executable:

```text
Original Intel tool
        |
        v
  i860 COFF loader
        |
        v
   i860 CPU core
        |
        +---- memory
        |
        +---- System V ABI
        |
        +---- syscall personality
```

Instruction and syscall support has similarly been added according to real execution boundaries encountered while running the historical software.

That turned debugging into a recurring ritual:

```text
"It got further!"

"...and now it crashes somewhere completely different."
```

Each new boundary told us what the original program actually needed next.

## A note about historical accuracy

This project tries to distinguish carefully between:

- behaviour observed from the original binaries
- compatibility behaviour supplied by this project
- approximations
- things that remain unknown

A program reaching its next execution boundary is evidence, not proof that every preceding historical behaviour has been perfectly reproduced.

Where something is stubbed, approximated or unexplained, it should remain documented as such.

That's particularly important when dealing with software this old: accidental compatibility can otherwise very quickly become imaginary documentation.

## Why not just rewrite the tools?

Because that would answer a different question.

There are modern assemblers, compilers and emulators that understand the i860.

This project is interested in the original artifacts themselves:

**Can we preserve the historical binaries and make their original behaviour observable again?**

Keeping them intact also makes them useful for software archaeology. They provide evidence about the development environment, ABI, object formats and toolchain assumptions of the period.

## Historical context

The i860 appeared during an especially interesting transition in workstation and operating-system history.

These tools date from the same broad period in which companies were experimenting with RISC development environments, cross-compilation and new operating-system architectures.

Having the original toolchain runnable again may therefore be useful beyond i860 experimentation itself: it provides another surviving reference point for understanding early-1990s compiler and operating-system development environments.

## Status

This is an experimental software-archaeology project.

It is not intended to be a complete SVR3 implementation or a cycle-perfect i860 emulator.

The objective is narrower:

> Preserve enough of the original environment that the historical software can execute and be studied.

And, occasionally, compile something.

## The mountain

This project involved considerably more:

```text
COFF
SVR3
far calls
syscalls
relocations
jump tables
instruction decoding
ABI archaeology
```

than originally anticipated.

Eventually, however:

```text
              GCC i860 GCD PASS
                     /\
                    /  \
                   / 🏁 \
                  /______\
```

**The mountain was summited.**

For now.
