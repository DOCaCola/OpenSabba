"""Regenerate src/ntlm_uppercase.inc from Unicode 16.0.0 UnicodeData.txt.

Download https://www.unicode.org/Public/16.0.0/ucd/UnicodeData.txt, then run:
    python3 tools/generate_ntlm_uppercase.py UnicodeData.txt src/ntlm_uppercase.inc
The source data and generated mapping are licensed under Unicode-3.0.
"""
from pathlib import Path
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: generate_ntlm_uppercase.py UnicodeData.txt OUTPUT")
source, destination = (Path(arg) for arg in sys.argv[1:])
pairs = []
for line in source.read_text(encoding="ascii").splitlines():
    fields = line.split(";")
    if fields[12]:
        pairs.append((int(fields[0], 16), int(fields[12], 16)))
if len(pairs) != 1477 or pairs != sorted(pairs):
    raise SystemExit("expected sorted Unicode 16.0.0 simple uppercase mappings")
lines = [
    "// SPDX-License-Identifier: Unicode-3.0",
    "// Copyright (c) 1991-2024 Unicode, Inc.",
    "// Unicode 16.0.0 simple uppercase mappings (UnicodeData.txt field 12).",
    "// Source: https://www.unicode.org/Public/16.0.0/ucd/UnicodeData.txt",
    "// Regenerate: python3 tools/generate_ntlm_uppercase.py UnicodeData.txt src/ntlm_uppercase.inc",
    "// License: LICENSES/Unicode-3.0.txt",
    "constexpr std::pair<std::uint32_t, std::uint32_t> uppercase_map[] = {",
]
for offset in range(0, len(pairs), 4):
    group = pairs[offset:offset + 4]
    lines.append("    " + " ".join(f"{{0x{src:04x}, 0x{dst:04x}}}," for src, dst in group))
lines.append("};")
destination.write_text("\n".join(lines) + "\n", encoding="ascii")
