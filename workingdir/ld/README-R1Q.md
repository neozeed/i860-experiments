# LD860 PE R1Q — quiet linker runtime + current i860 core

This build continues from the dedicated LD860 R1 personality rather than the generic AS860-derived converter path.

Changes:
- quiet by default; Intel LD860 guest output remains visible
- set `LD860_VERBOSE=1` for loader/interpreter diagnostics
- real failures force full diagnostic output even when quiet
- preserves LD860 R1 `chmod(15)` compatibility semantics
- adds `fiadd.dd` / `fmov.dd`
- adds scalar `fadd.dd`

No original Intel code was changed. The SVR3/i386 wrapper and i860 LD860 payload remain byte-identical.

## Regression results

The original `loop.o` oracle remains unchanged:
- linked output size: 426 bytes
- SHA256: `85b2531a8501e67731703cc2856515080338795d221b00c2985e83298e277528`
- guest exit status 0
- one `chmod(15)` call

GCC 1.40 i860 interoperability link oracle:

```
ld860.exe start.o gcd.o umodsi3.o -o gcd
```

Independent execution of the untouched Intel LD860 N1.3 payload:
- clean guest exit 0 after 175,353 instructions/services
- output `gcd`: 1,219-byte i860 COFF
- output SHA256: `71e87529fe20fd1d198c1620bf93ab280c8ecb82819d57c6a65947beb407f477`
- `chmod(15)` reached exactly once

Input object SHA256:
- start.o: `ffc0c402b7388201c6658a40dccae64b63d9e5d29dfbf8d9bf30dbe70e3c5c2e`
- gcd.o: `ecf999bfb290006137578e83a05a690649b45fa52601bc36a1c896ca2e79221e`
- umodsi3.o: `763953fa13e08ddd1f30be9d44e3c28ab81fda110519a35b34df26044dedf84b`
