"""Build small synthetic PE files for tests; no executable fixture is stored."""

import struct


def make_pe(machine: int = 0x014C, optional_magic: int = 0x010B, section_raw_pointer: int = 0x200) -> bytes:
    optional_size = 224 if optional_magic == 0x010B else 240
    pe_offset = 0x80
    section_table = pe_offset + 24 + optional_size
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, pe_offset + 4, machine, 1, 0, 0, 0, optional_size, 0x0002)
    struct.pack_into("<H", data, pe_offset + 24, optional_magic)
    section = bytearray(40)
    section[:8] = b".text\0\0\0"
    struct.pack_into("<IIII", section, 8, 0x1234, 0x1000, 0x200, section_raw_pointer)
    struct.pack_into("<I", section, 36, 0x60000020)
    data[section_table:section_table + 40] = section
    data[0x200:0x400] = bytes(range(256)) * 2
    return bytes(data)
