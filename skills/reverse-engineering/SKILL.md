---
name: reverse-engineering
description: Analyze, disassemble, debug, decompile, or understand any binary, executable, DLL, malware sample, firmware image, or obfuscated/packed code. Use whenever the user mentions reverse engineering, a suspicious or unknown file, unpacking, Ghidra/IDA/radare2/x64dbg/GDB, IOCs, YARA, or asks "what does this file do" — even if they never say "reverse engineering". Guides safe static and dynamic analysis step by step, from first triage to the final report.
license: MIT
compatibility: claude-code, opencode, codex, cursor
metadata:
  author: juank.ai12
  version: 1.1.0
  audience: beginners
  language: en
  topics: static-analysis, dynamic-analysis, malware, firmware, disassembly, debugging
---

# Reverse Engineering Skill for Beginners

This skill helps you analyze unknown binaries, executables, malware samples, firmware images, and obfuscated code step by step. It assumes you are a beginner and prioritizes safety, clarity, and repeatable workflows.

## When to use this skill

- The user drops a suspicious file, binary, or executable and asks "what does this do?"
- The user wants to understand how a program works without source code.
- The user mentions disassembly, decompilation, debugging, malware, firmware, obfuscation, or unpacking.
- The user needs help choosing tools or interpreting output from reverse engineering utilities.

## Quick start: run the triage script first

On any unknown file, start with the bundled triage script (read-only, pure Python, no dependencies):

```bash
python "${CLAUDE_SKILL_DIR}/scripts/triage.py" <sample>
```

If `CLAUDE_SKILL_DIR` is not set in your environment, run it from this skill's directory instead. It reports hashes, entropy, format (PE/ELF/Mach-O), sections, packer hints, and extracted strings — enough to decide the next step.

## Bundled resources

This skill ships supporting files. Load a reference only when the task matches its domain:

| Resource | Load when... |
|----------|--------------|
| `references/windows-pe.md` | Analyzing Windows PE files (.exe, .dll, .sys): headers, imports, packers, manual unpacking |
| `references/linux-elf.md` | Analyzing Linux/Unix ELF binaries: headers, symbols, GDB workflow, anti-analysis |
| `references/malware-analysis.md` | The sample may be malicious: lab setup, unpacking tactics, MITRE-mapped behaviors, YARA |
| `references/firmware-iot.md` | Firmware images or embedded devices: binwalk extraction, emulation, UART/JTAG |
| `references/cheatsheet.md` | You need a specific command: x64dbg, GDB, radare2, Ghidra, WinDbg shortcuts |
| `assets/report-template.md` | Writing the final analysis report |

## Safety first

Reverse engineering can involve malicious code. Never run unknown executables on a host machine.

1. **Isolate everything**: use a dedicated virtual machine (VM) or sandbox for dynamic analysis.
2. **No network by default**: disconnect the analysis VM from the internet unless you explicitly need it.
3. **Snapshot first**: take a VM snapshot before running any sample.
4. **Handle with hashes**: identify files by SHA-256 and search them in VirusTotal, MalwareBazaar, or Hybrid Analysis before execution.
5. **Ask before running**: if the user asks you to execute a binary, confirm the risk and environment first.
6. **No credential reuse**: never use production passwords, keys, or tokens inside an analysis VM.

## Beginner's reverse engineering workflow

Always follow this order unless there is a good reason to skip ahead:

1. **Triage**: identify file type, architecture, packing, and entropy.
2. **Static analysis**: read strings, headers, imports, and metadata without executing.
3. **Disassembly / decompilation**: convert machine code to readable form.
4. **Dynamic analysis**: run under controlled observation in a sandbox/VM.
5. **Behavioral analysis**: record network, filesystem, registry, and process activity.
6. **Reporting**: summarize findings with IOCs, MITRE ATT&CK mappings, and recommendations.

## Phase 1: Triage & static analysis

Start here for every sample.

### Identify the file

Run on the host or a safe analysis VM:

- `file <sample>` — file type and architecture.
- `exiftool <sample>` — metadata, compiler hints, timestamps.
- `sha256sum <sample>` — cryptographic hash for lookups.
- `ssdeep <sample>` — fuzzy hash for similar samples.

### Check for packing / obfuscation

- High entropy sections suggest packing or encryption.
- Few imports combined with large `.text` or `.data` sections suggest a packer.
- Look for section names like `UPX0`, `UPX1`, `.vmp`, `.themida`, `.petite`.

### Useful static tools

| Tool | Purpose |
|------|---------|
| `file` | Identify file type and architecture |
| `strings` | Extract readable strings |
| `exiftool` | Metadata extraction |
| `binwalk` | Signature analysis and carving |
| `hexdump -C` | Raw byte inspection |
| `pefile` (Python) | Parse PE headers |
| `pyelftools` (Python) | Parse ELF headers |
| `capstone` (Python) | Lightweight disassembly |
| `yara` | Rule-based pattern matching |

## Phase 2: Disassembly & decompilation

Use these tools depending on budget and platform:

| Tool | Type | Best for |
|------|------|----------|
| **Ghidra** | Free, open source | Static analysis, decompilation, cross-platform |
| **IDA Free** | Freemium | Disassembly, beginner-friendly graph view |
| **radare2 / Cutter** | Free, open source | Command-line workflows, scripting |
| **Binary Ninja** | Commercial | Fast analysis, excellent IL |
| **x64dbg** | Free debugger | Windows dynamic analysis |
| **GDB + gef/pwndbg** | Free debugger | Linux dynamic analysis |

### Decompilation tips for beginners

- Rename functions and variables as you understand them.
- Look for `main`, `WinMain`, or entry-point functions first.
- Trace user input (network, files, registry, command line) to dangerous APIs.
- Search for suspicious API calls: `CreateRemoteThread`, `VirtualAllocEx`, `InternetOpenUrl`, `RegSetValueEx`, `WriteProcessMemory`.

## Phase 3: Dynamic analysis & debugging

Only run samples in an isolated VM.

### Before execution

1. Take a VM snapshot.
2. Disable network or route through an isolated fake-net.
3. Prepare monitoring tools.

### Monitoring tools

| Tool | Platform | What it records |
|------|----------|-----------------|
| **Procmon** | Windows | Registry, file, process events |
| **Process Hacker / System Informer** | Windows | Processes, memory, handles |
| **Wireshark** | Cross-platform | Network traffic |
| **strace / ltrace** | Linux | Syscalls and library calls |
| **x64dbg / WinDbg** | Windows | Live debugging |
| **GDB** | Linux | Live debugging |

### Debugging checklist

- Set breakpoints on suspicious APIs.
- Step through unpacking stubs if packed.
- Dump unpacked payloads from memory when safe.
- Record the full command-line arguments and environment variables.

## Phase 4: Behavioral analysis (malware)

If the sample is potentially malicious, document behavior systematically.

### Persistence mechanisms

- Registry run keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).
- Scheduled tasks (`schtasks`).
- Startup folders.
- Services and drivers.
- WMI event subscriptions.

### Network indicators

- DNS queries.
- HTTP/HTTPS C2 callbacks.
- IP addresses and ports.
- User-Agent strings.

### Data theft / impact

- File enumeration.
- Screenshot capture.
- Keylogging hooks.
- Credential dumping (`lsass`, SAM hive).
- Encryption/ransomware file extensions.

### IOCs to collect

- SHA-256 hashes.
- File paths created.
- Registry keys modified.
- Network indicators.
- Mutexes / event names.
- Dropped filenames.

## Phase 5: Firmware / IoT analysis

For firmware images, routers, IP cameras, and embedded devices.

### Extraction

- `binwalk -e <firmware.bin>` — extract filesystems.
- `binwalk -M <firmware.bin>` — recursive extraction.
- `firmadyne` — emulate firmware for dynamic analysis.
- `fatcat` / `unsquashfs` — inspect SquashFS images.

### Static inspection

- Identify OS (often Linux-based) and architecture (MIPS, ARM, x86).
- Look at `/etc/passwd`, startup scripts (`rcS`, `init`), and crontabs.
- Search for hardcoded credentials, backdoors, and debug shells.

### Hardware basics

- UART is the most common debug interface (look for 4-pin headers).
- Use a USB-to-TTL adapter at 3.3 V.
- JTAG is less common but powerful for deep analysis.
- Never connect unknown hardware to a trusted network.

## Phase 6: Reporting

End every session with a clear report (use `assets/report-template.md` as the deliverable structure):

1. **Executive summary**: what is the sample and why it matters.
2. **Indicators of Compromise (IOCs)**: hashes, IPs, domains, file paths.
3. **Behavior summary**: what the sample does when executed.
4. **MITRE ATT&CK mapping** (for malware): Tactics and Techniques observed.
5. **Tools used**: list of tools and commands.
6. **Recommendations**: containment, detection, and prevention steps.

## Output format

When helping the user, structure your response like this:

```markdown
## TL;DR
One-paragraph summary of the finding or next step.

## Analysis
Step-by-step reasoning, tool output, and interpretation.

## Findings
- Bullet 1
- Bullet 2

## IOCs (if malware)
| Type | Value |
|------|-------|
| SHA-256 | ... |
| IP | ... |

## Next steps
1. Do this next.
2. Then do this.

## Safety reminders
- Reminder 1
- Reminder 2
```

## Example prompts

- "Analyze this executable. Is it malicious?"
- "Decompile this function and explain what it does."
- "Help me unpack this UPX sample."
- "What IOCs can I extract from this memory dump?"
- "Walk me through reversing this firmware image."
- "Explain this assembly snippet line by line."

## Resources

- [Ghidra](https://ghidra-sre.org/)
- [radare2](https://rada.re/n/)
- [Cutter](https://cutter.re/)
- [x64dbg](https://x64dbg.com/)
- [MalwareBazaar](https://bazaar.abuse.ch/)
- [VirusTotal](https://www.virustotal.com/)
- [MITRE ATT&CK](https://attack.mitre.org/)
