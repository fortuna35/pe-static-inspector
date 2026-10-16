"""Tests use synthetic bytes only; no real executable is included or run."""

import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pe_static_inspector.inspector import PEFormatError, inspect_file, inspect_stream
from tests.fixtures import make_pe


class InspectorTests(unittest.TestCase):
    def inspect_bytes(self, data: bytes, entropy: bool = False) -> dict[str, object]:
        return inspect_stream(io.BytesIO(data), len(data), include_entropy=entropy)

    def test_valid_pe32_metadata_and_section_sizes(self) -> None:
        result = self.inspect_bytes(make_pe())
        self.assertEqual(result["optional_header"], "PE32")
        self.assertEqual(result["machine_name"], "I386")
        self.assertEqual(result["architecture"], "x86")
        self.assertEqual(result["bitness"], 32)
        self.assertEqual(result["section_count"], 1)
        section = result["sections"][0]
        self.assertEqual(section["virtual_size"], 0x1234)
        self.assertEqual(section["raw_size"], 0x200)

    def test_valid_pe32_plus_metadata(self) -> None:
        result = self.inspect_bytes(make_pe(machine=0x8664, optional_magic=0x020B))
        self.assertEqual(result["optional_header"], "PE32+")
        self.assertEqual(result["machine_name"], "AMD64")
        self.assertEqual(result["architecture"], "x86_64")
        self.assertEqual(result["bitness"], 64)

    def test_truncated_headers_are_rejected(self) -> None:
        fixture = bytearray(make_pe())
        fixture[0x3C:0x40] = (0x3F0).to_bytes(4, "little")
        with self.assertRaisesRegex(PEFormatError, "outside the file"):
            self.inspect_bytes(bytes(fixture[:0x100]))

    def test_invalid_section_raw_bounds_are_rejected(self) -> None:
        fixture = bytearray(make_pe(section_raw_pointer=0x3F0))
        with self.assertRaisesRegex(PEFormatError, "extends beyond end of file"):
            self.inspect_bytes(bytes(fixture))

    def test_entropy_is_optional_and_bounded_to_section(self) -> None:
        plain = self.inspect_bytes(make_pe())
        measured = self.inspect_bytes(make_pe(), entropy=True)
        self.assertNotIn("entropy_bits_per_byte", plain["sections"][0])
        self.assertEqual(measured["sections"][0]["entropy_bits_per_byte"], 8.0)

    def test_cli_json_is_deterministic_for_same_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "synthetic-pe.bin"
            path.write_bytes(make_pe(machine=0x8664, optional_magic=0x020B))
            command = [sys.executable, "-m", "pe_static_inspector", str(path)]
            first = subprocess.run(command, check=True, capture_output=True, text=True)
            second = subprocess.run(command, check=True, capture_output=True, text=True)
            self.assertEqual(first.stdout, second.stdout)
            payload = json.loads(first.stdout)
            self.assertEqual(payload["architecture"], "x86_64")
            self.assertEqual(len(payload["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
