#!/usr/bin/env python3
"""
triage.py — automated first-pass static triage for an unknown file.

Part of the reverse-engineering skill. Pure Python standard library:
no dependencies to install, safe to run anywhere (it only reads the file).

Usage:
    python triage.py <file> [--strings N] [--min-len N] [--json]

Reports:
    - Size and hashes (MD5, SHA-1, SHA-256)
    - Overall entropy (packing/encryption indicator)
    - Format: PE, ELF, Mach-O, or unknown
    - PE: architecture, type, section table with per-section entropy,
      suspicious section names (known packers), and section anomalies
    - ELF: class, endianness, architecture, type
    - Possible anti-analysis string indicators for supported formats
    - Top printable ASCII and UTF-16LE strings
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import string
import struct
import sys
from pathlib import Path

ASCII_PRINTABLE = set(bytes(string.printable, "ascii")) - {0x0B, 0x0C}

PACKER_SECTIONS = {
    b"upx0": "UPX", b"upx1": "UPX", b"upx!": "UPX",
    b".aspack": "ASPack", b".adata": "ASPack",
    b"mpress1": "MPRESS", b"mpress2": "MPRESS",
    b".vmp0": "VMProtect", b".vmp1": "VMProtect", b".vmp2": "VMProtect",
    b".themida": "Themida", b".winlice": "Themida",
    b".petite": "Petite", b".enigma1": "Enigma", b".enigma2": "Enigma",
    b".nsp0": "NsPack", b".nsp1": "NsPack", b".neolite": "NeoLite",
    b".packed": "generic packer", b".boom": "Boomerang", b".y0da": "y0da crypter",
}

ANTI_ANALYSIS_PATTERNS = {
    "debugger detection": (
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "ptrace", "TracerPid",
        "/proc/self/status",
    ),
    "timing evasion": (
        "QueryPerformanceCounter", "GetTickCount64", "NtDelayExecution",
        "clock_gettime", "rdtsc",
    ),
    "virtualization or sandbox detection": (
        "VBoxGuest", "VBoxService", "VirtualBox", "vmtoolsd", "VMware",
        "Sandboxie", "SbieDll", "QEMU",
    ),
}

PE_SECTION_MEM_EXECUTE = 0x20000000
PE_SECTION_MEM_WRITE = 0x80000000

PE_MACHINES = {
    0x014C: "x86 (32-bit)", 0x8664: "x86-64", 0x01C0: "ARM",
    0x01C4: "ARMv7", 0xAA64: "ARM64",
}

ELF_MACHINES = {
    0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64",
    0x08: "MIPS", 0xF3: "RISC-V", 0x14: "PowerPC",
}

ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared object / PIE", 4: "core dump"}


def entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte: 0.0 = uniform, 8.0 = random."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    result = 0.0
    length = len(data)
    for count in counts:
        if count:
            p = count / length
            result -= p * math.log2(p)
    return result


def ascii_strings(data: bytes, min_len: int) -> list[str]:
    found, current = [], bytearray()
    for byte in data:
        if byte in ASCII_PRINTABLE:
            current.append(byte)
        else:
            if len(current) >= min_len:
                found.append(current.decode("ascii", errors="replace"))
            current.clear()
    if len(current) >= min_len:
        found.append(current.decode("ascii", errors="replace"))
    return found


def utf16le_strings(data: bytes, min_len: int) -> list[str]:
    found, current = [], bytearray()
    for i in range(0, len(data) - 1, 2):
        char, null = data[i], data[i + 1]
        if null == 0 and char in ASCII_PRINTABLE:
            current.append(char)
        else:
            if len(current) >= min_len:
                found.append(current.decode("ascii", errors="replace"))
            current.clear()
    if len(current) >= min_len:
        found.append(current.decode("ascii", errors="replace"))
    return found


def detect_anti_analysis(data: bytes) -> list[dict[str, object]]:
    """Find conservative anti-analysis string clues without claiming intent."""
    lowered = data.lower()
    indicators: list[dict[str, object]] = []
    for category, patterns in ANTI_ANALYSIS_PATTERNS.items():
        evidence = []
        for pattern in patterns:
            ascii_pattern = pattern.encode("ascii").lower()
            utf16_pattern = pattern.encode("utf-16le").lower()
            if ascii_pattern in lowered or utf16_pattern in lowered:
                evidence.append(pattern)
        if evidence:
            indicators.append({
                "category": category,
                "evidence": evidence,
                "note": "string evidence only; confirm through code or runtime behavior",
            })
    return indicators


def parse_pe(data: bytes) -> dict:
    """Minimal PE parser: headers + section table. No third-party deps."""
    info: dict = {"format": "PE"}
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"format": "PE", "error": "missing MZ header"}
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return {"format": "PE", "error": "missing PE signature"}

    machine, num_sections = struct.unpack_from("<HH", data, e_lfanew + 4)
    timestamp = struct.unpack_from("<I", data, e_lfanew + 8)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    characteristics = struct.unpack_from("<H", data, e_lfanew + 22)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]

    info["architecture"] = PE_MACHINES.get(machine, f"unknown (0x{machine:04x})")
    info["pe_type"] = "PE32+" if magic == 0x20B else "PE32" if magic == 0x10B else f"unknown (0x{magic:04x})"
    info["compile_timestamp"] = timestamp
    kinds = []
    if characteristics & 0x0002:
        kinds.append("executable")
    if characteristics & 0x2000:
        kinds.append("DLL")
    if characteristics & 0x1000:
        kinds.append("driver (.sys)")
    info["kind"] = ", ".join(kinds) or "object/other"

    sections = []
    table = e_lfanew + 24 + opt_size
    for i in range(num_sections):
        off = table + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b"\x00")
        virtual_size, _vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        section_characteristics = struct.unpack_from("<I", data, off + 36)[0]
        raw = data[raw_ptr:raw_ptr + raw_size] if raw_ptr < len(data) else b""
        sec_entropy = entropy(raw)
        packer = PACKER_SECTIONS.get(name.lower())
        is_writable_executable = bool(
            section_characteristics & PE_SECTION_MEM_EXECUTE
            and section_characteristics & PE_SECTION_MEM_WRITE
        )
        zero_raw_large_virtual = raw_size == 0 and virtual_size >= 4096
        notes = []
        if packer:
            notes.append(f"known packer/protector section: {packer}")
        if sec_entropy > 7.0:
            notes.append("high entropy")
        if is_writable_executable:
            notes.append("writable + executable")
        if zero_raw_large_virtual:
            notes.append("zero raw data + large virtual size")
        sections.append({
            "name": name.decode("ascii", errors="replace") or "(unnamed)",
            "virtual_size": virtual_size,
            "raw_size": raw_size,
            "entropy": round(sec_entropy, 2),
            "packer_hint": packer or ("high entropy" if sec_entropy > 7.0 else None),
            "writable_executable": is_writable_executable,
            "zero_raw_large_virtual": zero_raw_large_virtual,
            "notes": notes,
        })
    info["sections"] = sections
    return info


def parse_elf(data: bytes) -> dict:
    info: dict = {"format": "ELF"}
    ei_class, ei_data = data[4], data[5]
    endian = "<" if ei_data == 1 else ">"
    e_type, e_machine = struct.unpack_from(f"{endian}HH", data, 16)
    info["class"] = "64-bit" if ei_class == 2 else "32-bit"
    info["endianness"] = "little" if ei_data == 1 else "big"
    info["architecture"] = ELF_MACHINES.get(e_machine, f"unknown ({e_machine})")
    info["kind"] = ELF_TYPES.get(e_type, f"other ({e_type})")
    return info


def parse_macho(data: bytes) -> dict:
    magics = {0xFEEDFACE: "Mach-O 32-bit", 0xFEEDFACF: "Mach-O 64-bit",
              0xCAFEBABE: "Mach-O universal (fat)"}
    magic = struct.unpack_from(">I", data, 0)[0]
    return {"format": magics.get(magic, "Mach-O")}


def triage(path: Path, max_strings: int, min_len: int) -> dict:
    data = path.read_bytes()
    overall_entropy = entropy(data)
    report: dict = {
        "file": str(path),
        "size_bytes": len(data),
        "hashes": {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "entropy": round(overall_entropy, 2),
        "entropy_note": "high — possibly packed/encrypted" if overall_entropy > 7.0 else "normal",
    }

    if data[:2] == b"MZ":
        report.update(parse_pe(data))
    elif data[:4] == b"\x7fELF":
        report.update(parse_elf(data))
    elif data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
        report.update(parse_macho(data))
    else:
        report["format"] = "unknown / data"

    report["anti_analysis_indicators"] = detect_anti_analysis(data)

    warnings = []
    if overall_entropy > 7.0:
        warnings.append("High overall entropy may indicate packing or encryption.")
    for section in report.get("sections", []):
        section_name = section["name"]
        if section.get("packer_hint") and section["packer_hint"] != "high entropy":
            warnings.append(
                f"Section {section_name!r} matches {section['packer_hint']} naming."
            )
        if section.get("entropy", 0.0) > 7.0:
            warnings.append(f"Section {section_name!r} has high entropy.")
        if section.get("writable_executable"):
            warnings.append(f"Section {section_name!r} is writable and executable.")
        if section.get("zero_raw_large_virtual"):
            warnings.append(
                f"Section {section_name!r} has no raw data but a large virtual size; "
                "it may receive unpacked code at runtime."
            )
    for indicator in report["anti_analysis_indicators"]:
        evidence = ", ".join(indicator["evidence"])
        warnings.append(
            f"Possible {indicator['category']} strings found: {evidence}. "
            "Confirm in code before drawing conclusions."
        )
    report["warnings"] = warnings
    report["ascii_strings"] = ascii_strings(data, min_len)[:max_strings]
    report["utf16le_strings"] = utf16le_strings(data, min_len)[:max_strings]
    return report


def print_report(report: dict) -> None:
    print(f"File:      {report['file']}")
    print(f"Size:      {report['size_bytes']:,} bytes")
    for algo, digest in report["hashes"].items():
        print(f"{algo.upper():7s}  {digest}")
    print(f"Entropy:   {report['entropy']}  ({report['entropy_note']})")
    print(f"Format:    {report.get('format', '?')}")

    for key in ("architecture", "pe_type", "kind", "class", "endianness", "compile_timestamp"):
        if key in report:
            print(f"{key.replace('_', ' ').title():18s} {report[key]}")
    if "error" in report:
        print(f"Parse error: {report['error']}")

    if "sections" in report:
        print("\nSections:")
        print(f"  {'Name':10s} {'Raw size':>10s} {'Entropy':>7s}  Note")
        for sec in report["sections"]:
            note = "; ".join(sec.get("notes") or [])
            print(f"  {sec['name']:10s} {sec['raw_size']:>10,} {sec['entropy']:>7.2f}  {note}")

    indicators = report.get("anti_analysis_indicators") or []
    if indicators:
        print("\nPossible anti-analysis indicators (verify; strings are not proof):")
        for indicator in indicators:
            print(f"  {indicator['category']}: {', '.join(indicator['evidence'])}")

    warnings = report.get("warnings") or []
    if warnings:
        print("\nTriage warnings:")
        for warning in warnings:
            print(f"  - {warning}")

    for key, label in (("ascii_strings", "ASCII"), ("utf16le_strings", "UTF-16LE")):
        strings = report.get(key) or []
        if strings:
            print(f"\nTop {label} strings:")
            for s in strings:
                print(f"  {s[:120]}")

    print("\nNext steps: verify the warnings with static analysis and search the SHA-256 "
          "on VirusTotal/MalwareBazaar. Do not execute the sample until the mandatory "
          "isolation gate in SKILL.md is confirmed.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Static triage for an unknown file (read-only, safe).")
    parser.add_argument("file", type=Path, help="file to analyze")
    parser.add_argument("--strings", type=int, default=20, help="max strings to show (default: 20)")
    parser.add_argument("--min-len", type=int, default=5, help="minimum string length (default: 5)")
    parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    args = parser.parse_args()

    if not args.file.is_file():
        print(f"error: not a file: {args.file}", file=sys.stderr)
        return 2

    report = triage(args.file, args.strings, args.min_len)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
