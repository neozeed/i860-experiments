# Windows smoke pass for unified R1

The consolidated binaries are build/static/reproducibility verified. Run these once on Windows before freezing the unified package as live-proven.

## 1. AS860

Copy `examples/hello.s` beside `bin/as860.exe` and run:

```bat
as860.exe hello.s -o hello.o
echo %ERRORLEVEL%
```

Expected: Intel assembler banner, exit 0, real i860 COFF `hello.o`.

## 2. LD860

Use known-good i860 objects from the working GCC/Intel experiment and run the normal linker command. The linker should show only Intel's banner in quiet mode and exit 0. LD860's `chmod(15)` finalization call is implemented in the common personality.

## 3. SIZE860

```bat
size860.exe linked-file
```

The historical R1 independent oracle for the old `loop` executable is `32 + 0 + 0 = 32` with exit 0.

## 4. SIM860

```bat
sim860.exe target
```

Known live targets from the predecessor runtime include the hand-written stdout hello and the GCC GCD program. The latter printed `GCC i860 GCD PASS` and exited 0.

For troubleshooting only:

```bat
set I860_VERBOSE=1
sim860.exe target
```

If a real instruction/service is missing, preserve the reported PC, word, instruction count and trap registers. Add the documented semantic to the common runtime, rebuild all four, and rerun `verify.py --rebuild`.
