"""Offline Linux CLI coverage: private files and synthetic journals only."""
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import zipfile
from test_probe import wire


def main():
    executable = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="opensabba-diagnostics-") as temporary:
        root = Path(temporary)
        config = root / "config"
        env = dict(os.environ, XDG_CONFIG_HOME=str(config))

        def export(output, success=True):
            result = subprocess.run([executable, "--export-log", "--output-file", str(output)],
                                    env=env, capture_output=True, text=True, timeout=120)
            assert (result.returncode == 0) == success, result.stderr
            if success:
                assert stat.S_IMODE(output.stat().st_mode) == 0o600
                with zipfile.ZipFile(output) as archive:
                    return json.loads(archive.read("diagnostics.json"))

        first = export(root / "fresh.json")
        assert not config.exists(), "export created session storage"
        assert all(j["status"] == "missing" for j in first["journals"].values())
        store = config / "opensabba"
        store.mkdir(parents=True, mode=0o700)
        session = store / "session.pstream"
        session.write_bytes(wire(dict(format=2, token="PRIVATE_TOKEN", username="PRIVATE_USER")))
        session.chmod(0o600)
        corrupt = store / "backup-job.pstream"
        corrupt.write_bytes(b"corrupt PRIVATE_ERROR")
        corrupt.chmod(0o600)
        (store / "service-machine-event.pstream").symlink_to(session)
        before = session.read_bytes()
        # A running service owns the directory lock; export must not need it.
        directory = os.open(store, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
            output = root / "report.json"
            report = export(output)
        finally:
            os.close(directory)
        with zipfile.ZipFile(output) as archive:
            assert "PRIVATE" not in archive.read("diagnostics.json").decode()
        assert session.read_bytes() == before
        assert report["journals"]["backup-job.pstream"]["status"] == "unreadable"
        assert report["journals"]["service-machine-event.pstream"]["status"] == "unreadable"
        assert report["journals"]["session.pstream"]["summary"]["format"] == 2
        exported = output.read_bytes()
        export(output, False)
        assert output.read_bytes() == exported, "overwrote existing report"
        link = root / "output-link"
        link.symlink_to(session)
        export(link, False)
        assert session.read_bytes() == before, "followed output symlink"
        export(root / "absent-parent" / "report.json", False)
        assert set(p.name for p in store.iterdir()) == {
            "session.pstream", "backup-job.pstream", "service-machine-event.pstream"}


if __name__ == "__main__":
    main()
