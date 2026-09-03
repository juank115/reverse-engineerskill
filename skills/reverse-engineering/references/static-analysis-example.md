# Static Analysis Example Session

This example shows how to use the reverse engineering skill to triage an unknown executable without running it.

## User prompt

> I found this file called `invoice.exe` in my Downloads. Can you help me understand what it is without running it?

## Expected skill behavior

The skill should guide the user through safe static analysis.

### Step 1: File identification

```bash
file invoice.exe
sha256sum invoice.exe
exiftool invoice.exe
```

Interpret the output:

- `PE32 executable (GUI) Intel 80386, for MS Windows` — Windows 32-bit binary.
- High entropy sections — possible packing or encryption.
- Suspicious metadata — fake company name, unusual timestamps.

### Step 2: String extraction

```bash
strings -n 8 invoice.exe | head -100
strings -el invoice.exe          # UTF-16 strings on Windows
```

Look for:

- URLs or IP addresses.
- File paths.
- Registry keys.
- API names.
- Command-line arguments.

### Step 3: Import table review

Open in `pefile`:

```python
import pefile
pe = pefile.PE("invoice.exe")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(entry.dll.decode())
    for func in entry.imports:
        print("  ", func.name.decode() if func.name else "ordinal")
```

Suspicious imports might include:

- `WinExec`, `CreateProcess`
- `InternetOpenUrl`, `URLDownloadToFile`
- `VirtualAlloc`, `WriteProcessMemory`
- `RegSetValueEx`

### Step 4: Packed or not?

```bash
ent invoice.exe                  # entropy check
pecheck invoice.exe              # if available
```

If entropy is high (>7.0) and imports are few, the binary may be packed; verify with section names, imports, and a packer detector.

## Sample report output

```markdown
## TL;DR
`invoice.exe` is a 32-bit Windows PE with high entropy and suspicious network-related imports. It is likely a downloader or dropper.

## Findings
- SHA-256: `...`
- Packed: probably yes (entropy 7.8).
- Suspicious imports: `InternetOpenUrlA`, `URLDownloadToFileA`, `WinExec`.
- Strings include: `http://185.x.x.x/payload.bin`, `C:\Users\Public\update.exe`.

## Next steps
1. Search the hash on VirusTotal and MalwareBazaar.
2. If safe to proceed, unpack in a VM and analyze the payload dynamically.
3. Do not run the binary on a host machine.
```
