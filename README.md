# 🟠 PE Static Inspector

A small, read-only command-line utility for inspecting Portable Executable (PE/COFF) structure. It reports header metadata, section virtual/raw sizes, and SHA-256. Optional section entropy can help describe byte distributions during static review.

The tool parses file bytes only. It does not execute the input, inspect process memory, inject code, bypass anti-cheat controls, or alter the file.

## Requirements

Python 3.10 or newer. The implementation and tests use only the Python standard library; no third-party runtime dependencies are required.

## Run

From the repository directory:

```powershell
python -m pe_static_inspector path\to\sample.exe
```

Add `--entropy` to include Shannon entropy for each section's raw bytes:

```powershell
python -m pe_static_inspector path\to\sample.exe --entropy
```

Output is deterministic JSON for the same file and options. Malformed or truncated files produce a concise error on stderr and exit code 2.

## Example JSON

```json
{
  "architecture": "x86_64",
  "bitness": 64,
  "characteristics": "0x0002",
  "file_size": 1024,
  "format": "PE/COFF",
  "machine": "0x8664",
  "machine_name": "AMD64",
  "optional_header": "PE32+",
  "section_count": 1,
  "sections": [
    {
      "characteristics": "0x60000020",
      "name": ".text",
      "raw_pointer": 512,
      "raw_size": 512,
      "virtual_address": 4096,
      "virtual_size": 4660
    }
  ],
  "sha256": "<64-character SHA-256 hex digest>"
}
```

Entropy is omitted unless requested. The digest placeholder above is illustrative and is not a real file hash.

## Tests

Run the synthetic fixture tests with:

```powershell
python -m unittest discover -s tests -v
```

Fixtures are assembled in memory and written only to temporary test directories. No real executable is bundled or launched.

## Scope and limitations

This is a metadata reader, not a full PE validator, malware classifier, signature verifier, disassembler, or compatibility checker. It checks key header and section-table boundaries and section raw-data bounds. It does not verify every PE directory, relocation, certificate, overlay, or loader rule. Unknown machine types are reported as `unknown`. Entropy is a descriptive statistic and does not establish that a file is benign or malicious.

## License

MIT. See [LICENSE](LICENSE).
