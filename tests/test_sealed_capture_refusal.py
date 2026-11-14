"""Old sealed capture records are unsupported."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from test_probe import check, wire

exe = sys.argv[1]
with tempfile.TemporaryDirectory(prefix="opensabba-sealed-refusal-") as temporary:
    root = Path(temporary)
    config = root / "config"
    private = config / "opensabba"
    private.mkdir(parents=True, mode=0o700)
    session = dict(format=2, host="127.0.0.1", port=1, ca_file="", username="test-user",
                   device_uuid="test-device", token="test-token", ds_id="test-nas",
                   registration_state="confirmed")
    saved = private / "session.pstream"
    saved.write_bytes(wire(session))
    saved.chmod(0o600)
    capture = root / ("capture-" + "a" * 32)
    capture.mkdir(mode=0o700)
    env = dict(os.environ, XDG_CONFIG_HOME=str(config))
    for schema in range(1, 5):
        for phase in ("ready", "snapshot-intent"):
            journal = dict(schema=schema, id="a" * 32,
                           boot_id="00000000-0000-0000-0000-000000000001", phase=phase,
                           failure="", plan={}, snapshot=dict(released=1),
                           reservation=dict(directory=str(capture), snapshot_released=1),
                           artifact=dict(length=512, sha256="a" * 64))
            if schema == 4:
                journal.update(failure_disposition="", logs=[])
            saved = capture / "capture.pstream"
            saved.write_bytes(wire(journal))
            saved.chmod(0o600)
            result = subprocess.run([exe, "service", "bind-machine", str(capture),
                                     "--task", "2", "--image-name", "machine-disk"],
                                    env=env, capture_output=True, text=True, timeout=5)
            check(result.returncode != 0 and "unsupported capture journal schema" in result.stderr,
                  f"schema {schema} {phase}: {result.stdout}{result.stderr}")
            check(not (private / "service-source.pstream").exists(), "sealed capture was bound")
    print("Old sealed captures refused before network mutation")
