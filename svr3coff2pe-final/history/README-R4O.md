# SVR3COFF2PE R4O — repair unsafe IC operand relocation

## Run on Windows

Keep the working source and temporary-directory settings from R4N. Extract this
release separately, then run from your existing source directory:

    set SVR3COFF2PE_TRACE=3
    ic-pe-r4o.exe void.c -asm void.s > r4o-run.txt 2>&1
    echo ExitCode=%ERRORLEVEL%>>r4o-run.txt

Use the full path to ic-pe-r4o.exe if it is elsewhere. Return r4o-run.txt and
void.s, if produced. The R4N exception reporter, including EBP and stack words,
remains enabled.

## Evidence and correction

The user's R4N log reports EIP 0x00500AD7, EBP 0x00005001, and an invalid read
from 0x00004FF5. The instruction is mov eax,[ebp-12]; the address arithmetic is
consistent. This establishes a bad EBP, but does not identify its last writer.

The previous operand scanner used nm's symbols without filtering their section,
then searched every four-byte window within objdump's instruction bytes. This
was not a safe operand decoder. GNU BFD treats this SVR3 COFF as PE-flavoured
COFF, adding section VAs to already-absolute symbols. For example, the actual
_start n_value is 0xD4, while nm reports 0x1A4. Non-text .comment values were
also admitted into the candidate symbol set. objdump -d split instructions at
these misleading symbol boundaries.

A directly reproduced corruption at original IC PC 0x81FE:

    Original: C7 45 FC 01 00 00 00  mov DWORD PTR [ebp-4],1
    R4N:      C7 45 2C 01 50 00 00  mov DWORD PTR [ebp+0x2c],0x5001
    R4O:      C7 45 FC 01 00 00 00  mov DWORD PTR [ebp-4],1

The scanner mistook the overlapping bytes FC 01 00 00 for a pointer 0x1FC,
then added 0x4FFF30. This changes BOTH the stack displacement and the constant.
There are 93 original stores with that encoding; R4O preserves every one.
The exact store responsible for the user's EBP value has not been traced live.

R4O:

- Reads the original COFF symbol records directly, retaining actual absolute
  values only for real text symbols and excluding debug/section names.
- Decodes extracted text with GNU objdump binary mode, avoiding false symbol
  boundaries. No LLVM dependency is needed for IC relocation discovery.
- Replaces all 227 old guessed text patches with 14 audited pointer operands.
  Every entry checks the exact complete instruction bytes and target symbol.
  These are qsort/traversal callbacks and two stores to the function pointer at
  0x43D6C4. This exact IC profile is intentionally fingerprint-gated; unknown
  binaries fail rather than inheriting an unsafe heuristic manifest.
- Removes the two unsupported data-symbol guesses. Initialized data changes
  only at dispatch-table slots identified from decoded indirect jumps.
- Retains all 2,167 previous dispatch targets without changing their values.
- Adds the independently verified table at data 0x441358, reached by the
  instruction at original PC 0x8F59F. Its preceding bounds check admits indices
  0..5, and its six slots point to actual case labels.

Manifest: 14 syscall gates, 14 audited absolute text operands, 156 data jump
tables, 2,173 unique dispatch slots, no unproven data-symbol patches.

The syscall runtime, descriptor translation, heap semantics and PE layout
logic are inherited unchanged. The banner now identifies R4O. This remains
one converter and shared runtime, with the exact binary relocation evidence
kept in its profile.

## Validation and limitations

This release is BUILD/STATIC VERIFIED, WINDOWS RUNTIME UNTESTED. It is not yet
a demonstrated successful C compilation. There is no Windows/Wine runtime in
this execution environment.

verify_r4o.py checks full text and initialized-data preservation outside the
manifest, restored stack stores/tests/allocation, original input SHA-256,
callback relocation, manifest counts and direct COFF symbol interpretation.
With the optional original R4N executable, it also reproduces the corrupt
instruction and checks preservation of every previous dispatch slot.
The normal converter checks non-overlap, adjacent PE sections, permissions,
original-image preservation, and complete gate replacement.

Build with Python 3 and GNU gcc/as/ld/objcopy/objdump/nm/readelf (32-bit object
compilation support required):

    python3 svr3coff2pe.py convert ic -o ic-pe-r4o.exe --workdir build
    python3 verify_r4o.py

The embedded original IC is included as `ic` for reproducibility, SHA-256:
b03d634d16ffdd724d752d5aeb12831ba81423a9ab35e7216256bcb909b3ddab

Historical R4A–R4D count-based verification scripts are not shipped as current
checks: their old manifest assertions encode the bug corrected here. Use
verify_r4o.py and the included validation report.
