# Windows PE Analysis Reference

Deep reference for analyzing Windows Portable Executable (PE) files: `.exe`, `.dll`, `.sys`, `.scr`, `.ocx`, `.cpl`.

## Contents

- [PE structure overview](#pe-structure-overview)
- [Triage tools](#triage-tools)
- [Import analysis](#import-analysis)
- [Suspicious API categories](#suspicious-api-categories)
- [Packing and unpacking](#packing-and-unpacking)
- [Sections and entropy](#sections-and-entropy)
- [Resources](#resources-section)
- [Digital signatures](#digital-signatures)

## PE structure overview

A PE file is laid out like this:

| Region | Offset | What it tells you |
|--------|--------|-------------------|
| DOS header | `0x00` | Starts with `MZ` (`4D 5A`). Field `e_lfanew` at `0x3C` points to the PE header. |
| DOS stub | varies | Legacy code; usually prints "This program cannot be run in DOS mode." Malware sometimes hides data here. |
| PE signature | `e_lfanew` | The bytes `PE\0\0`. |
| COFF header | `+0x04` | Machine type (`0x14C` = x86, `0x8664` = x64, `0x1C0` = ARM), number of sections, timestamp, characteristics. |
| Optional header | `+0x18` | Magic `0x10B` = PE32, `0x20B` = PE32+. Entry point address, image base, subsystem (GUI/console/driver), DLL characteristics (ASLR, DEP/NX). |
| Section table | after optional header | One 40-byte entry per section: name, virtual size/address, raw size/offset, flags. |
| Sections | varies | `.text` (code), `.data` (initialized data), `.rdata` (read-only data, imports/exports), `.rsrc` (resources), `.reloc` (relocations). |

Key fields for a beginner:

- **AddressOfEntryPoint**: where execution starts. If it points into the last section (common in packed files), suspect a packer.
- **Characteristics**: tells you if the file is a DLL (`0x2000`), executable (`0x0002`), or driver.
- **Timestamp**: compile time. Note: trivially forgeable; a 1992 timestamp on a "new" file is a red flag, not proof.

## Triage tools

Run these before opening a disassembler:

| Tool | Purpose |
|------|---------|
| `pestudio` | All-in-one static triage: imports, strings, sections, entropy, VirusTotal score. Beginner-friendly. |
| `Detect It Easy (DIE)` | Packer/compiler/protector identification. |
| `PE-bear` | Header inspection with a clean UI. |
| `CFF Explorer` | Header editing and inspection. |
| `sigcheck` (Sysinternals) | Signature verification, VirusTotal lookup (`-v`), entropy. |
| `capa` | Detects capabilities automatically ("encrypts data using AES", "injects into processes"). Highly recommended. |

Quick commands:

```powershell
sigcheck -accepteula -v -h sample.exe      # signature + VT + hashes
python scripts/triage.py sample.exe        # bundled triage script
```

## Import analysis

The Import Address Table (IAT) reveals what the binary *can* do. Zero or near-zero imports usually means packing or dynamic API resolution (look for `LoadLibrary` + `GetProcAddress`).

What to extract:

1. Which DLLs are imported (`kernel32.dll`, `ws2_32.dll`, `wininet.dll`, `advapi32.dll`, `ntdll.dll`, ...).
2. Which functions per DLL.
3. Mismatches: a "PDF reader" importing `CreateRemoteThread` deserves attention.

Imports can be resolved at runtime instead of appearing in the IAT. In that case, find where API names are constructed (stack strings, XOR loops) or where hashes of API names are compared.

## Suspicious API categories

Not proof of malice on their own — context matters — but combinations are telling.

| Category | APIs | Why it matters |
|----------|------|----------------|
| Process injection | `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`, `SetWindowsHookEx` | Code execution inside another process |
| Process hollowing | `CreateProcess` (suspended), `NtUnmapViewOfSection`, `WriteProcessMemory`, `ResumeThread` | Replaces a legit process's memory |
| Networking (low) | `socket`, `connect`, `send`, `recv` (`ws2_32.dll`) | Raw C2 traffic |
| Networking (HTTP) | `InternetOpen`, `InternetOpenUrl`, `InternetReadFile` (`wininet.dll`), `WinHttpSendRequest` (`winhttp.dll`), `URLDownloadToFile` (`urlmon.dll`) | Downloaders, web C2 |
| Persistence (registry) | `RegCreateKeyEx`, `RegSetValueEx` | Run keys, services config |
| Services | `OpenSCManager`, `CreateService`, `StartService` | Service-based persistence |
| Crypto | `CryptEncrypt`, `CryptAcquireContext` (`advapi32.dll`), BCrypt* | Ransomware, encrypted C2 |
| Credential theft | `LsaEnumerateLogonSessions`, `SamIConnect`, `MiniDumpWriteDump` targeting `lsass.exe` | Dumping credentials |
| Anti-analysis | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `GetTickCount`/`Sleep` (timing) | Debugger/sandbox evasion |
| File operations | `CreateFile`, `WriteFile`, `DeleteFile`, `MoveFile`, `FindFirstFile` | Dropping payloads, enumerating data |

## Packing and unpacking

### Detect

- Very few imports + high-entropy sections = packed.
- Known section names: `UPX0`, `UPX1`, `.aspack`, `.adata`, `MPRESS1`, `MPRESS2`, `.vmp0`, `.vmp1` (VMProtect), `.themida`, `.petite`, `.enigma1`.
- `Detect It Easy` usually names the packer directly.

### Unpack UPX (trivial)

```bash
upx -d sample.exe
```

### Unpack manually (generic method)

1. Load in x64dbg.
2. Set a breakpoint on `VirtualAlloc` / `VirtualProtect` — unpackers allocate writable+executable memory.
3. Run; watch for a large `jmp` or `call` into freshly written memory (the "tail jump" to the Original Entry Point, OEP).
4. At the OEP, dump the process with **Scylla** (built into x64dbg: Plugins → Scylla).
5. In Scylla: "IAT Autosearch" → "Get Imports" → "Dump" → "Fix Dump".

### Common mistakes

- Dumping before the OEP (you get the unpacker, not the payload).
- Forgetting to fix imports (the dump won't analyze cleanly).
- Running outside a VM.

## Sections and entropy

- Normal code entropy: ~5.0–6.5. Packed/encrypted: 7.0–8.0.
- A section with raw size 0 but large virtual size = unpacked-at-runtime.
- Writable + executable section flags (`0xE0000020`) are suspicious.
- Odd section names or no section names at all = packer or manual crafting.

## Resources section

`.rsrc` can hide entire payloads (common for droppers).

- Extract with **Resource Hacker** or `pestudio`.
- Look for large `RT_RCDATA` entries, embedded PE files (they start with `MZ`), or images with appended data.

## Digital signatures

- `sigcheck -i sample.exe` shows signature details.
- An **unsigned** binary is normal for malware; a **stolen or invalid** signature is a strong indicator.
- A valid signature from a real company can still be abuse of a compromised cert — check the signer name against expectations.
