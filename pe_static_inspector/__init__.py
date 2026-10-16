"""Read-only PE/COFF metadata inspection."""

from .inspector import PEFormatError, inspect_file, inspect_stream

__all__ = ["PEFormatError", "inspect_file", "inspect_stream"]
