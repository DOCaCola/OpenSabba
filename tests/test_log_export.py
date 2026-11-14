"""Offline Linux archive, collection and historical rotation fixtures."""
import os
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import zipfile


def main():
    driver = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="opensabba-log-export-") as temporary:
        base = Path(temporary)
        system = base / "system"
        state = base / "state"
        logs = state / "log"
        logs.mkdir(parents=True, mode=0o700)
        state.chmod(0o700)

        def put(path, content):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o600)

        put(system / "etc/os-release", b"NAME=Fixture\n")
        put(system / "etc/Synology/settings.conf", b"safe=yes\npassword=UNKNOWN_SECRET\n")
        put(system / "var/log/kern.log", b"kernel message\nPRIVATE_TOKEN\n")
        put(system / "var/log/kern.log.1", b"rotated OS file is not selected\n")
        put(system / "var/crash/core", b"\0PRIVATE_TOKEN")
        put(logs / "log.txt", b"safe history\n" + b"x" * 1024 * 1024 + b"\n")
        put(logs / "log.txt_0", b"old history PRIVATE_USER\n")
        put(logs / "log.txt_48", b"oldest\n")
        put(logs / "unexpected", b"PRIVATE_TOKEN")
        (system / "etc/machine-id").symlink_to(system / "etc/os-release")
        (logs / "log.txt_1").symlink_to(system / "etc/os-release")
        output = base / "report.zip"

        def run(destination, success=True):
            result = subprocess.run([driver, str(system), str(destination), str(logs)],
                                    capture_output=True, text=True, timeout=10)
            assert (result.returncode == 0) == success, result.stderr

        run(output)
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        with zipfile.ZipFile(output) as archive:
            assert archive.testzip() is None
            names = archive.namelist()
            assert "diagnostics.json" in names
            assert "agent_log/log.txt" in names and "agent_log/log.txt_0" in names
            assert "agent_log/unexpected" not in names
            assert "etc/machine-id" not in names
            assert "var/log/kern.log.1" not in names
            assert "var/crash/core" not in names
            assert "modinfo" not in names and "journalctl" in names
            assert all(not n.startswith("/") and ".." not in Path(n).parts for n in names)
            for name in names:
                text = archive.read(name)
                assert b"PRIVATE_" not in text and b"UNKNOWN_SECRET" not in text, name
            manifest = archive.read("collection.txt")
            assert b"binary crash data omitted" in manifest and b"command exit=127" in manifest
        starts = [json.loads(line.split("activity=", 1)[1]) for line in
                  (logs / "log.txt").read_text().splitlines() if "activity=" in line]
        assert [entry["log_type"] for entry in starts] == [1101, 1115, 1101]
        assert all(entry["log_time"] and set(entry) == {"log_type", "log_time", "parameters"}
                   for entry in starts)
        assert starts[0]["parameters"] == starts[2]["parameters"] == dict(
            task_name='Fixture "task"\n', trigger_type=1, trigger_event=0)
        assert starts[1]["parameters"] == dict(
            task_name='Fixture "task"\n', trigger_type=3, trigger_event=9)
        current = (logs / "log.txt_0").read_bytes()
        assert b"phase=upload" in current and b"offset=512" in current
        assert b"PRIVATE_" not in current
        assert not (logs / "log.txt_49").exists()
        before = output.read_bytes()
        run(output, False)
        assert output.read_bytes() == before
        target = base / "destination-link"
        target.symlink_to(output)
        run(target, False)
        run(base / "missing/report.zip", False)
        # Exact syslog/messages presence suppresses the 30-day journal query.
        put(system / "var/log/syslog", b"system history\n")
        run(base / "syslog.zip")
        with zipfile.ZipFile(base / "syslog.zip") as archive:
            assert "journalctl" not in archive.namelist()


if __name__ == "__main__":
    main()
