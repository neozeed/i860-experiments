# Building i860fat2pe R1

The generated executable is Windows PE32/i386, but the converter uses a GNU **ELF32/i386 build scaffold** internally to manufacture the freestanding host runtime blob.

Required commands:

- Python 3
- GNU `as` with `--32`
- GCC with `-m32`
- GNU `ld` supporting `-m elf_i386`
- GNU `objcopy`, `nm`, `readelf`

On Debian/Ubuntu/WSL, `gcc-multilib` plus `binutils` is the expected setup.

The macOS system assembler is Clang/Apple tooling and does not accept the GNU `as --32` interface. Do not casually replace the ELF intermediate with Mach-O or PE/COFF; the current build path is proven and deterministic. Use Linux/WSL, a container, or a compatible cross GNU ELF32 toolchain.

`build_known.py` rebuilds the four supplied tools. `verify.py --rebuild` performs a second clean build and requires byte-identical PE output.
