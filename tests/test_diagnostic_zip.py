"""Read the production ZIP64 writer using Python's independent ZIP reader."""
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

with tempfile.TemporaryDirectory(prefix="opensabba-zip-") as directory:
    output = Path(directory) / "test.zip"
    subprocess.run([sys.argv[1], str(output)], check=True, timeout=20)
    with zipfile.ZipFile(output) as archive:
        assert archive.testzip() is None
        assert archive.namelist() == ["empty", "diagnostics.json", "agent_log/log.txt"]
        assert archive.read("empty") == b""
        assert archive.read("diagnostics.json") == b'{"format":1}\n'
        assert archive.read("agent_log/log.txt") == b"x" * 150000 + b"\n"
        assert all((entry.external_attr >> 16) & 0o777 == 0o600 for entry in archive.infolist())
