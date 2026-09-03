# Dynamic Analysis Example Session

This example shows how to analyze a binary by executing it safely inside an isolated virtual machine.

## User prompt

> I have a malware sample in my VM. How do I observe what it does when it runs?

## Mandatory execution gate

Before giving any run, continue, step, or debugger command, the user must confirm:

- [ ] Analysis is running inside a dedicated, disposable VM with host integrations disabled.
- [ ] A clean snapshot was taken before execution.
- [ ] Network is disabled or routed only through an isolated fake-net.
- [ ] Monitoring tools are installed and already started.
- [ ] The VM contains no production credentials, personal data, or tokens.

If any item is unconfirmed, stop and offer static analysis instead.

## Expected skill behavior

The skill should provide a step-by-step dynamic analysis plan.

### Step 1: Prepare monitoring

On Windows:

- Start **Procmon** and filter by process name.
- Start **Process Hacker** or **System Informer**.
- Start **Wireshark** on the isolated VM/fake-net interface if network observation is needed; never capture or expose a trusted LAN.
- Prepare **x64dbg** if live debugging is planned.

On Linux, these commands execute the sample and are allowed only after the gate is verified:

```bash
sudo strace -f -o sample.strace ./sample
sudo ltrace -f -o sample.ltrace ./sample
```

### Step 2: Execute with observation

Run the sample in the VM. Do **not** interact with it unnecessarily.

Capture:

- Process tree changes.
- Files created or modified.
- Registry changes.
- Network connection attempts.
- Injected processes.

### Step 3: Extract behavioral indicators

From Procmon:

```text
Process Create: C:\Users\Public\update.exe
RegSetValue: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Update
TCP Connect: 185.x.x.x:443
```

From Wireshark:

```text
DNS query: malicious-c2.example.com
TLS handshake SNI: malicious-c2.example.com
```

### Step 4: Memory dump if needed

If the sample unpacks itself in memory:

```text
In x64dbg:
1. Set breakpoint on VirtualAlloc / WriteProcessMemory.
2. Run until payload is decrypted.
3. Dump the allocated memory region to disk.
4. Hash and statically analyze the dumped payload.
```

## Sample report output

```markdown
## TL;DR
The sample creates a persistence entry, downloads a second-stage payload, and contacts a C2 server.

## Behavioral findings
- Drops: `C:\Users\Public\update.exe`
- Persistence: `HKCU\...\Run\Update`
- Network: DNS `malicious-c2.example.com`, IP `185.x.x.x:443`
- Process injection: observed into `explorer.exe`

## IOCs
| Type | Value |
|------|-------|
| SHA-256 | `...` |
| Domain | `malicious-c2.example.com` |
| IP | `185.x.x.x` |
| File path | `C:\Users\Public\update.exe` |

## MITRE ATT&CK
- T1547.001 — Registry Run Keys
- T1055 — Process Injection
- T1071.001 — Web Protocols C2

## Recommendations
1. Revert the VM snapshot.
2. Block IOCs at the network perimeter.
3. Hunt for the persistence mechanism on production hosts.
```
