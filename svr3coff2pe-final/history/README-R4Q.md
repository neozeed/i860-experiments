# SVR3COFF2PE R4Q — restore ICC and fix small-host PE adjacency

Current binaries, all rebuilt from the shared runtime:
- icc-pe.exe: restored Intel compiler driver; native Windows execution untested.
- ic-pe.exe: IC compiler with R4O relocation corrections and R4Q PE envelope.
- as860-pe.exe: Portland Group assembler with R4P relocation profile and R4Q envelope.

Preserved binaries from the previous package:
- ic-pe-r4o.exe: original live-proven C-to-assembly compiler.
- as860-pgc.exe: original R4P assembler; live ran and diagnosed dialect errors.

The original COFF inputs ic, icc and as860.coff are included. No previously
included executable has been removed. Run python3 build_all.py to rebuild all
three current names from the same sources. The driver runtime maps Unix tool
basenames to NAME-pe.exe and then NAME.exe; keep current binaries together.
End-to-end driver execution, child launching and final linkage remain untested.
Other earlier tool families (N1.3 simulator/linker etc.) were not present in the
R4P input package and are not silently represented as rebuilt here.

## PE fix

The builder reserved five pages for .hdata before .idata, but emitted only the
actual .hdata contents. ICC's smaller runtime left an RVA gap, correctly caught
by sections_rva_adjacent. R4Q pads .hdata to the full reserved 0x5000 bytes.
The adjacency check remains enabled. All converter checks pass for all three
rebuilt targets. IC and assembler byte-preservation checks pass.
The ICC relocation manifest is inherited, not newly audited by this release.

## Dialect finding from original ICC disassembly

At original PC 0x170C the driver appends the string -astype. At 0x1722 it checks
its assembler-family selector. The default family selects as860 (string at
0x401170) and appends "1" (string at 0x400E0B). The alternate family selects
i860as (string at 0x4011D0) and appends "0" (string at 0x400E0D).
The driver also appends the Boolean -reentrant option at PC 0x174A.

A direct test of the observed driver options, avoiding unproven driver execution:

    set SVR3COFF2PE_TRACE=3
    ic-pe.exe u.c -astype 1 -reentrant -asm u-intel.s > ic-dialect-run.txt 2>&1
    as860-pe.exe -o u-intel.o u-intel.s > as-dialect-run.txt 2>&1

Run the second command only after successful compilation. Return both logs,
u-intel.s and u-intel.o if generated. This dialect correction is established
from driver code, but these new commands have not been run on Windows here.

To exercise the restored driver separately:

    icc-pe.exe -S u.c > icc-run.txt 2>&1

-S handling / normal driver operation can encounter additional compatibility
issues; keep logs. lcpp has been inspected but is not converted or required by
our present direct IC test. No unsupported preprocessor success is claimed.

To rebuild only the driver under Linux/WSL:

    python3 svr3coff2pe.py convert icc -o icc-pe.exe --workdir work-icc

The force-native-heuristic option is unnecessary for recognized inputs.
