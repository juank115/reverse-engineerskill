# Firmware & IoT Analysis Playbook

Analyzing firmware images and embedded devices: routers, cameras, DVRs, printers, smart gadgets.

## Contents

- [Acquisition](#acquisition)
- [Extraction](#extraction)
- [Filesystems](#filesystems)
- [What to look for](#what-to-look-for)
- [Emulation](#emulation)
- [Hardware interfaces](#hardware-interfaces)
- [Safety](#safety)

## Acquisition

In order of preference:

1. **Vendor download**: get the update image from the manufacturer's site or an update server (check for HTTPS endpoints in mobile app traffic).
2. **Device dump**: read the SPI/NAND flash directly with a programmer (CH341A + SOIC8 clip for SPI; more complex for NAND).
3. **Console access**: UART shell → `cat /dev/mtdblock0 > /tmp/dump.bin` over network or serial.

Always verify the image: `file firmware.bin`, `binwalk firmware.bin`, and compare size against the flash chip's capacity.

## Extraction

```bash
binwalk firmware.bin                 # signature scan: what's inside?
binwalk -e firmware.bin              # extract known filesystems
binwalk -Me firmware.bin             # recursive extraction (Matryoshka)
binwalk --dd='.*' firmware.bin       # carve everything
sasquatch -v firmware.bin            # non-standard SquashFS variants
jefferson -d outdir firmware.bin     # JFFS2
ubireader_extract_files image.ubi    # UBIFS
```

When binwalk finds nothing: the image may be encrypted (check for high, flat entropy with no structure — `binwalk -E`), or use a custom header. Look for the update mechanism in an older unencrypted firmware, or pull the filesystem from a running device instead.

## Filesystems

| Filesystem | Magic | Tool |
|------------|-------|------|
| SquashFS | `hsqs` / `sqsh` | `unsquashfs`, `sasquatch` |
| JFFS2 | `0x1985` markers | `jefferson` |
| UBIFS | `UBI#` | `ubireader` |
| cramfs | `Compressed ROMFS` | `cramfsck`, `fsck.cramfs` |
| ext2/3/4 | `0x53EF` at 0x438 | `mount -o loop,ro` |
| YAFFS2 | OOB-heavy, no single magic | `yaffshiv` |

After extraction you usually get a Linux rootfs: `bin/ etc/ lib/ usr/ www/`.

## What to look for

Prioritized hunting list:

1. **Credentials**: `/etc/passwd`, `/etc/shadow` (crack with `john`/`hashcat`), hardcoded passwords in `www/` configs, `config.json`, `.conf` files.
2. **Private keys & certs**: `grep -r "PRIVATE KEY" .` — shipped private TLS keys are a classic finding.
3. **Startup logic**: `/etc/init.d/`, `/etc/inittab`, `/etc/rc.local`, rcS scripts — what services start? Any debug backdoors (`telnetd -l /bin/sh`)?
4. **Web interface**: `www/` — look for unauthenticated CGI endpoints, command injection in form handlers, hardcoded session tokens.
5. **Custom binaries**: anything not from busybox/standard packages. `file` them, note architecture, run the triage script, analyze the interesting ones (updaters, proprietary daemons).
6. **Debug leftovers**: test accounts, commented-out backdoors, `/bin/sh` binds, leftover private build scripts.
7. **Update mechanism**: signature verification? Plain HTTP? `curl | sh` patterns? Unsigned updates = remote compromise vector.

## Emulation

Run binaries without the device:

```bash
# Identify architecture first
file ./bin/busybox

# User-mode QEMU (single binary)
qemu-arm -L ./rootfs ./rootfs/bin/some-daemon

# chroot into the extracted rootfs
sudo chroot ./rootfs /bin/sh        # only if host arch matches or via qemu-*-static
```

- **[Firmadyne](https://github.com/firmadyne/firmadyne)** — automated full-system emulation for Linux-based firmware.
- **[FirmAE](https://github.com/pr0v3rbs/FirmAE)** — Firmadyen successor with better success rate.
- Emulation failing is normal: missing NVRAM is the #1 cause. Use `libnvram` hooks/fakes or patch the NVRAM-read calls.

## Hardware interfaces

Physical access when you have the device:

| Interface | What it gives you | Gear |
|-----------|-------------------|------|
| **UART** | Serial console: boot logs, often a root shell | USB-to-TTL adapter (3.3 V!), multimeter to find TX/RX/GND |
| **JTAG/SWD** | CPU-level debug, memory dump, flash read | JTAGulator (pin finding), OpenOCD + adapter |
| **SPI flash** | Direct firmware read/write | CH341A + SOIC8 clip, `flashrom` |
| **I2C/SPI buses** | Sensor/config EEPROM data | Bus Pirate, logic analyzer (Saleae) |

UART quick start:

1. Power off. Find 3–4 pin headers or labeled pads (`TX`, `RX`, `GND`, `VCC`).
2. **Never connect VCC.** Connect GND↔GND, adapter RX↔board TX, adapter TX↔board RX.
3. Verify 3.3 V logic with a multimeter before connecting (5 V can kill the port).
4. Try baud rates: 115200 8N1 is most common; `screen /dev/ttyUSB0 115200` or PuTTY.
5. Boot the device and watch the console — interrupt U-Boot for a bootloader shell if possible.

## Safety

- Analyze in an isolated network — IoT malware (Mirai family) scans and spreads.
- Don't connect a compromised device to your home LAN.
- Respect the hardware: ESD strap, correct voltages, don't poke mains-powered devices (routers' PSUs are usually fine; anything with a big transformer is not a beginner target).
- Legality: analyze devices you own or have permission to test. Check local law for circumventing technical protections (research exemptions often exist, e.g. DMCA §1201 security research exemption).
