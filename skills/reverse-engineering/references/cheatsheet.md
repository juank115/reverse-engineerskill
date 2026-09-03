# Reverse Engineering Cheatsheet

Quick command lookup. Load this when the user needs a specific command or shortcut.

## Choose a level

| Level | Prefer | Use it for |
|-------|--------|------------|
| Beginner | Bundled `triage.py`, `file`, `strings`, Detect It Easy, PE-bear | First-pass facts and packer clues |
| Guided visual | Ghidra, IDA Free, Cutter; Procmon after the execution gate | Cross-references, decompilation, and monitored behavior |
| Advanced | radare2, GDB/gef/pwndbg, WinDbg, x64dbg, Scylla | Manual control-flow work, anti-analysis, unpacking, and IAT repair |

Start at the first level and move deeper only when needed. Commands that run or continue a target (`start`, `c`, `ood`, `dc`, `g`, `F9`, debugger stepping, and similar) are **dynamic execution**. For an unknown sample, do not provide or use them until the mandatory execution gate in `SKILL.md` is fully verified. Explain an advanced command's goal and expected result before asking a beginner to use it.

## Contents

- [x64dbg](#x64dbg)
- [GDB (+ gef/pwndbg)](#gdb--gefpwndbg)
- [radare2 / Cutter](#radare2--cutter)
- [Ghidra](#ghidra)
- [WinDbg](#windbg)
- [Static triage one-liners](#static-triage-one-liners)

## x64dbg

| Key | Action |
|-----|--------|
| `F2` | Toggle breakpoint |
| `F7` | Step into |
| `F8` | Step over |
| `F9` | Run |
| `Ctrl+F9` | Run until return |
| `Alt+F9` | Run until user code |
| `Ctrl+G` | Go to address/expression |
| `Ctrl+E` | Edit memory/instruction (patch) |
| `-` / `+` | Previous / next view |

Breakpoints beyond `F2`:

```text
bp VirtualAlloc                    # on API
bp 00401000                        # on address
bphw 00401000, r                   # hardware breakpoint on read
SetMemoryBPX <addr>, 1, a          # memory breakpoint on access
bpcnd 00401000, eax==5             # conditional
```

Useful views: **Memory Map** (find RWX regions → dump), **Call Stack**, **References** (find string xrefs: right-click string → Follow in Disassembler). Dump unpacked payloads: Memory Map → right-click region → Dump Memory to File. Fix imports with the built-in **Scylla** plugin.

## GDB (+ gef/pwndbg)

| Command | Action |
|---------|--------|
| `start` | Run, stop at entry |
| `b main` / `b *0x401234` | Breakpoint |
| `ni` / `si` | Step over / into (instruction level) |
| `c` | Continue |
| `i r` | Info registers |
| `x/20gx $rsp` | Dump 20 qwords at stack |
| `x/s $rdi` | Read string |
| `x/10i $pc` | Disassemble at PC |
| `disas main` | Disassemble function |
| `set $eax = 0` | Modify register |
| `vmmap` | Memory map (gef) |
| `telescope $rsp` | Smart stack dump (gef) |
| `pattern create/offset` | Cyclic patterns (gef) |
| `checksec` | Binary protections (gef) |
| `catch syscall ptrace` | Catch anti-debug calls |

Force a function to return a value (defeats anti-debug checks):

```gdb
finish
set $rax = 0
ni
```

## radare2 / Cutter

```bash
r2 -A sample              # open with full analysis (aaa)
```

| Command | Action |
|---------|--------|
| `iI` | Binary info (arch, bits, PIE) |
| `iS` | Sections |
| `ii` | Imports |
| `iz` | Strings in data sections |
| `afl` | List functions |
| `s main` | Seek to function |
| `pdf` | Print disassembly of current function |
| `VV` | Graph view (interactive) |
| `s sym.imp.strcpy` | Seek to import |
| `axt @ sym.imp.system` | Cross-references to `system` |
| `/ /bin/sh` | Search for string |
| `wx 9090 @ 0x401234` | Patch with NOPs |
| `ood` | Reopen in debug mode |
| `dc` / `ds` / `dso` | Debug continue / step / step-over |

## Ghidra

| Key | Action |
|-----|--------|
| `G` | Go to address |
| `L` | Rename symbol/function |
| `;` | Set comment |
| `Ctrl+Shift+E` | Find references to address |
| `Ctrl+Shift+F` | Search strings |
| Middle-click | Highlight all occurrences |
| Decompiler panel | `P` retype variable, `Ctrl+L` rename |

Workflow: import → auto-analyze (defaults are fine) → Window → Defined Strings → double-click interesting string → right-click address → References → Show References to Address → jump to the code that uses it.

## WinDbg

| Command | Action |
|---------|--------|
| `bp kernel32!CreateFileW` | Breakpoint on API |
| `g` | Go |
| `t` / `p` | Trace (into) / step (over) |
| `k` | Call stack |
| `lm` | List loaded modules |
| `r` | Registers |
| `da <addr>` / `du <addr>` | Dump ASCII / Unicode string |
| `!address <addr>` | Memory region info |
| `.dump /ma C:\out.dmp` | Full memory dump |
| `s -a 0 L?80000000 "string"` | Search memory for ASCII |

## Static triage one-liners

```bash
# Hashes
sha256sum sample
certutil -hashfile sample.exe SHA256        # Windows built-in

# Strings
strings -a -n 6 sample | less
strings -a -e l sample                      # UTF-16LE (Windows common)

# PE
objdump -x sample.exe | less
python scripts/triage.py sample.exe         # bundled: hashes, entropy, sections, strings

# ELF
readelf -h -S -l -d sample
objdump -d -M intel sample | less

# Capabilities & packers
capa sample.exe
diec sample                                 # Detect It Easy CLI

# Network baseline (VM, before running)
sudo tcpdump -i any -w baseline.pcap
```
