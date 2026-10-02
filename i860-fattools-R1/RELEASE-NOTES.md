# i860fat2pe R1 release notes

- Consolidates AS860, LD860, SIZE860 and SIM860 onto one CPU/personality source.
- Adds the real-workload `fiadd.dd/fmov.dd` and `fadd.dd` semantics discovered during GCC/Intel interoperability work.
- Carries linker `chmod(15)` into the common syscall personality.
- Removes SIM860-specific target PC/register success oracles from production execution.
- Uses one `I860_VERBOSE=1` switch for host scaffolding across the family.
- Real faults force diagnostic output even when normal verbosity is off.
- Raises the generic safety ceiling to 20,000,000 outer i860 instructions/services.
- Keeps the GNU ELF32/i386 build scaffold intact.
- Includes deterministic rebuild verification and a hard assertion that all four generated CPU sources are byte-identical.
- Omits the experimentally incorrect hand-written `___umodsi3` helper from final examples.
