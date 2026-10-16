"""Static, read-only inspection of Portable Executable (PE) files."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import BinaryIO


class PEFormatError(ValueError):
    """Raised when a file is truncated or has inconsistent PE structure."""


_MACHINE_NAMES = {
    0x014C: ("I386", "x86"),
    0x01C0: ("ARM", "ARM32"),
    0x01C4: ("ARMNT", "ARM32"),
    0x0200: ("IA64", "Itanium"),
    0x8664: ("AMD64", "x86_64"),
    0xAA64: ("ARM64", "ARM64"),
    0xA641: ("ARM64EC", "ARM64EC"),
    0xA64E: ("ARM64X", "ARM64X"),
}


def _read_at(stream: BinaryIO, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0:
        raise PEFormatError(f"Invalid {label} range.")
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise PEFormatError(f"Truncated {label}.")
    return data


def _entropy(stream: BinaryIO, offset: int, size: int) -> float:
    """Calculate Shannon entropy in bits per byte using bounded memory."""
    counts: Counter[int] = Counter()
    remaining = size
    stream.seek(offset)
    while remaining:
        chunk = stream.read(min(1024 * 1024, remaining))
        if not chunk:
            raise PEFormatError("Truncated section data while calculating entropy.")
        counts.update(chunk)
        remaining -= len(chunk)
    if size == 0:
        return 0.0
    return round(-sum((count / size) * math.log2(count / size) for count in counts.values()), 6)


def inspect_stream(stream: BinaryIO, file_size: int, include_entropy: bool = False) -> dict[str, object]:
    """Inspect PE headers and section metadata without executing the input."""
    if file_size < 64:
        raise PEFormatError("File is too short to contain a DOS header.")
    dos = _read_at(stream, 0, 64, "DOS header")
    if dos[:2] != b"MZ":
        raise PEFormatError("Missing DOS MZ signature.")

    pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
    if pe_offset < 64 or pe_offset + 24 > file_size:
        raise PEFormatError("PE header offset is outside the file.")
    signature = _read_at(stream, pe_offset, 4, "PE signature")
    if signature != b"PE\0\0":
        raise PEFormatError("Missing PE signature.")

    coff = _read_at(stream, pe_offset + 4, 20, "COFF header")
    machine, section_count, _timestamp, _symbol_ptr, _symbol_count, optional_size, characteristics = struct.unpack(
        "<HHIIIHH", coff
    )
    if section_count == 0:
        raise PEFormatError("COFF header declares no sections.")

    optional_offset = pe_offset + 24
    if optional_size < 2 or optional_offset + optional_size > file_size:
        raise PEFormatError("Optional header is truncated or outside the file.")
    optional_magic = struct.unpack("<H", _read_at(stream, optional_offset, 2, "optional-header magic"))[0]
    if optional_magic == 0x010B:
        optional_kind = "PE32"
    elif optional_magic == 0x020B:
        optional_kind = "PE32+"
    else:
        raise PEFormatError(f"Unsupported optional-header magic: 0x{optional_magic:04X}.")

    section_table_offset = optional_offset + optional_size
    table_size = section_count * 40
    if section_table_offset + table_size > file_size:
        raise PEFormatError("Section table is truncated or outside the file.")

    machine_name, architecture = _MACHINE_NAMES.get(machine, ("UNKNOWN", "unknown"))
    sections: list[dict[str, object]] = []
    for index in range(section_count):
        raw = _read_at(stream, section_table_offset + index * 40, 40, f"section header {index}")
        name_bytes = raw[:8].split(b"\0", 1)[0]
        name = name_bytes.decode("ascii", errors="replace")
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", raw, 8)
        section_characteristics = struct.unpack_from("<I", raw, 36)[0]
        if raw_size and (raw_pointer > file_size or raw_size > file_size - raw_pointer):
            raise PEFormatError(f"Section {index} raw data extends beyond end of file.")
        item: dict[str, object] = {
            "name": name,
            "virtual_address": virtual_address,
            "virtual_size": virtual_size,
            "raw_pointer": raw_pointer,
            "raw_size": raw_size,
            "characteristics": f"0x{section_characteristics:08X}",
        }
        if include_entropy:
            item["entropy_bits_per_byte"] = _entropy(stream, raw_pointer, raw_size)
        sections.append(item)

    return {
        "format": "PE/COFF",
        "file_size": file_size,
        "machine": f"0x{machine:04X}",
        "machine_name": machine_name,
        "architecture": architecture,
        "bitness": 32 if optional_kind == "PE32" else 64,
        "optional_header": optional_kind,
        "characteristics": f"0x{characteristics:04X}",
        "section_count": section_count,
        "sections": sections,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_file(path: str | Path, include_entropy: bool = False) -> dict[str, object]:
    """Return static PE metadata and SHA-256 for a file path."""
    file_path = Path(path)
    file_size = file_path.stat().st_size
    with file_path.open("rb") as source:
        result = inspect_stream(source, file_size, include_entropy)
    result["sha256"] = _sha256_file(file_path)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pe-static-inspector",
        description="Read PE/COFF headers and section metadata. The input is never executed.",
    )
    parser.add_argument("file", type=Path, help="path to the PE file to inspect")
    parser.add_argument("--entropy", action="store_true", help="calculate Shannon entropy for each raw section")
    args = parser.parse_args(argv)
    try:
        result = inspect_file(args.file, include_entropy=args.entropy)
    except (OSError, PEFormatError) as exc:
        print(f"pe-static-inspector: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
