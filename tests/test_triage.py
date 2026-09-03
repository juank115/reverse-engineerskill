import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TRIAGE_PATH = ROOT / "skills" / "reverse-engineering" / "scripts" / "triage.py"
SPEC = importlib.util.spec_from_file_location("triage_script", TRIAGE_PATH)
triage_script = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(triage_script)


class TriageTests(unittest.TestCase):
    def test_detects_ascii_and_utf16_anti_analysis_strings(self):
        data = b"IsDebuggerPresent\x00" + "VBoxService".encode("utf-16le")

        indicators = triage_script.detect_anti_analysis(data)
        found = {
            evidence
            for indicator in indicators
            for evidence in indicator["evidence"]
        }

        self.assertIn("IsDebuggerPresent", found)
        self.assertIn("VBoxService", found)

    def test_pe_triage_warns_about_packer_rwx_and_anti_analysis(self):
        sample = bytearray(0x300)
        sample[:2] = b"MZ"
        struct.pack_into("<I", sample, 0x3C, 0x80)
        sample[0x50:0x61] = b"IsDebuggerPresent"
        sample[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HH", sample, 0x84, 0x8664, 1)
        struct.pack_into("<I", sample, 0x88, 0)
        struct.pack_into("<H", sample, 0x94, 0xE0)
        struct.pack_into("<H", sample, 0x96, 0x0002)
        struct.pack_into("<H", sample, 0x98, 0x20B)

        section_offset = 0x80 + 24 + 0xE0
        sample[section_offset:section_offset + 8] = b"UPX0\0\0\0\0"
        struct.pack_into("<IIII", sample, section_offset + 8, 0x2000, 0x1000, 0x100, 0x200)
        struct.pack_into("<I", sample, section_offset + 36, 0xE0000020)
        sample[0x200:0x300] = bytes(range(256))

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.exe"
            path.write_bytes(sample)
            report = triage_script.triage(path, max_strings=20, min_len=5)

        section = report["sections"][0]
        self.assertEqual(section["packer_hint"], "UPX")
        self.assertTrue(section["writable_executable"])
        self.assertTrue(report["anti_analysis_indicators"])
        self.assertTrue(any("UPX" in warning for warning in report["warnings"]))
        self.assertTrue(any("writable and executable" in warning for warning in report["warnings"]))
        self.assertTrue(any("debugger detection" in warning for warning in report["warnings"]))


if __name__ == "__main__":
    unittest.main()
