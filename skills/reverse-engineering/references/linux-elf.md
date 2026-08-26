# Linux ELF Analysis Reference

Deep reference for analyzing ELF binaries: executables, shared objects (`.so`), kernel modules (`.ko`), and core dumps.

## Contents

- [ELF structure overview](#elf-structure-overview)
- [Triage commands](#triage-commands)
- [Security mitigations (checksec)](#security-mitigations-checksec)
- [Symbols and stripping](#symbols-and-stripping)
- [Dynamic analysis with GDB](#dynamic-analysis-with-gdb)
- [Anti-analysis tricks](#anti-analysis-tricks)
- [Core dumps](#core-dumps)

## ELF structure overview

| Region | What it tells you |
|--------|-------------------|
| ELF header | Magic `0x7F 'E' 'L' 'F'`, class (32/64-bit), endianness, type (`EXEC`, `DYN` = PIE/shared object, `REL`, `CORE`), architecture, entry point. |
| Program headers (segments) | What gets mapped into memory (`PT_LOAD`, `PT_DYNAMIC`, `PT_INTERP`, ...). |
| Section headers | `.text` (code), `.data`, `.rodata`, `.bss`, `.dynsym`/`.symtab` (symbols), `.dynamic`, `.got`/`.plt` (imports). Sections are for linking; malware sometimes corrupts them while keeping segments valid. |
| `.interp` | The dynamic loader path (e.g. `/lib64/ld-linux-x86-64.so.2`). An unusual value can indicate a custom/embedded loader. |

Architecture values (`e_machine`): `0x03` x86, `0x3E` x86-64, `0x28` ARM, `0xB7` AArch64, `0x08` MIPS.

## Triage commands

```bash
file sample                        # type, arch, stripped?
python scripts/triage.py sample    # bundled triage script
readelf -h sample                  # ELF header
readelf -S sample                  # sections
readelf -l sample                  # segments
readelf -d sample                  # dynamic section (needed libs, RPATH)
readelf -s sample                  # symbols
ldd sample                         # shared library dependencies (do NOT run on untrusted code outside a VM; use objdump -p instead)
objdump -p sample                  # safer dependency listing
strings -a -n 6 sample             # strings
nm -D sample                       # dynamic symbols
```

## Security mitigations (checksec)

```bash
checksec --file=sample
```

| Mitigation | Meaning | Exploitation impact |
|------------|---------|---------------------|
| `RELRO` | Read-only GOT after relocation | Full RELRO blocks GOT overwrite |
| `Stack canary` | Stack smash detection | Blocks naive stack overflows |
| `NX` | Non-executable stack | Forces ROP instead of shellcode |
| `PIE` | Position-independent executable | Randomizes code base with ASLR |
| `FORTIFY` | Checked libc calls | Catches some overflows at runtime |

`DYN` type + PIE is the modern default; `EXEC` + no canary + no NX on a network-facing binary is a red flag (and a CTF gift).

## Symbols and stripping

- **Not stripped**: `nm sample` shows function names — analysis is much easier.
- **Stripped**: no `.symtab`. You still get dynamic symbols (`nm -D`) and imports via `.dynsym`.
- Find `main` in a stripped binary: disassemble `_start`; the argument passed to `__libc_start_main` in register `rdi` (x86-64) is `main`.
- Function identification libraries: Ghidra's Function ID, IDA's FLIRT, or rizin's `zignatures` recover names by byte-pattern matching.

## Dynamic analysis with GDB

Use with [gef](https://github.com/hugsy/gef) or [pwndbg](https://github.com/pwndbg/pwndbg) — they make GDB beginner-friendly.

```bash
gdb -q ./sample
```

Essential session:

```gdb
gef➤  start                     # run and stop at entry
gef➤  break main                # breakpoint
gef➤  break *0x401234           # breakpoint at address
gef➤  ni / si                   # next instruction / step into
gef➤  info registers            # CPU state
gef➤  x/20gx $rsp               # examine stack
gef➤  x/s $rdi                  # examine string
gef➤  vmmap                     # memory map
gef➤  telescope $rsp            # dereference stack chains
gef➤  pattern create 100        # cyclic pattern (offset finding)
gef➤  checksec                  # mitigations
```

Watch syscalls without source:

```bash
strace -f -o trace.txt ./sample    # system calls
ltrace -f ./sample                 # library calls
```

## Anti-analysis tricks

| Trick | How it looks | Counter |
|-------|--------------|---------|
| `ptrace(PTRACE_TRACEME)` self-check | Exits or misbehaves under a debugger | Patch the check (`NOP` it) or use `catch syscall ptrace` and force return 0 |
| Corrupted section headers | `readelf -S` errors but the file runs | Analyze via segments (`readelf -l`); sections are irrelevant at runtime |
| `LD_PRELOAD` rootkits | Malicious `.so` loaded everywhere | Check `/etc/ld.so.preload`, env vars |
| Timing checks | `gettimeofday`/`clock` deltas | Patch or run deterministically |
| Environment checks | Looks for `VBOX`, `VMWARE`, sandbox artifacts | Rename artifacts, patch checks |

## Core dumps

```bash
gdb ./sample core          # post-mortem analysis
readelf -n core            # notes: process info, registers
eu-stack --core core       # backtrace without gdb
```

Useful when malware crashed your VM or when you forced a dump (`gcore <pid>`) of a decrypted in-memory payload.
