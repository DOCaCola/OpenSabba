"""Double-fork/PID lifecycle without root, a driver, or a network peer."""
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time


def wait_for(predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('daemon lifecycle timed out')


def main():
    executable = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='opensabba-daemon-') as directory:
        root = Path(directory)
        pid_file, evidence = root / 'service.pid', root / 'evidence'
        output, errors = root / 'stdout', root / 'stderr'
        for stop in (signal.SIGQUIT, signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            pid = None
            evidence.unlink(missing_ok=True)
            pid_file.write_text('stale PID contents must be truncated')
            with output.open('w') as stdout, errors.open('w') as stderr:
                process = subprocess.Popen([executable, str(pid_file), str(evidence), 'run'],
                                           cwd=root, stdout=stdout, stderr=stderr, umask=0o077)
                assert process.wait(timeout=5) == 0
                # systemd reads PIDFile= when the launcher exits; it must be complete then.
                launched = pid_file.read_text()
                assert launched.endswith('\n') and launched[:-1].isdigit(), launched
                try:
                    wait_for(lambda: evidence.exists() and len(evidence.read_text().splitlines()) == 5)
                    lines = evidence.read_text().splitlines()
                    pid, sid, group = map(int, lines[:3])
                    assert pid_file.read_text() == launched == f'{pid}\n'
                    assert pid != process.pid and sid != pid and group == sid
                    assert sid != os.getsid(0), 'daemon retained caller session'
                    assert lines[3] == str(root), 'daemon changed cwd'
                    assert int(lines[4]) == 0o077, 'daemon changed umask'
                    assert stat.S_IMODE(pid_file.stat().st_mode) == 0o644
                    wait_for(lambda: 'daemon standard output retained' in output.read_text())
                    os.kill(pid, stop)
                    wait_for(lambda: not pid_file.exists())
                    pid = None
                    assert not errors.read_text(), errors.read_text()
                finally:
                    if pid is not None:
                        os.kill(pid, signal.SIGKILL)
        # An initialization exception unwinds PID ownership after daemonization.
        with output.open('w') as stdout, errors.open('w') as stderr:
            process = subprocess.Popen([executable, str(pid_file), str(evidence), 'fail'],
                                       cwd=root, stdout=stdout, stderr=stderr)
            assert process.wait(timeout=5) == 0
            wait_for(lambda: 'initialization failed' in errors.read_text())
            assert not pid_file.exists()
        # A daemon that ends before its PID file exists fails the launcher.
        with output.open('w') as stdout, errors.open('w') as stderr:
            process = subprocess.Popen([executable, str(pid_file), str(evidence), 'early-fail'],
                                       cwd=root, stdout=stdout, stderr=stderr)
            assert process.wait(timeout=5) == 1
            wait_for(lambda: 'failed before PID file' in errors.read_text())
            assert not pid_file.exists()
        print('daemon double fork, PID mode/content/cleanup, inherited process state, and stop signals passed')


if __name__ == '__main__':
    main()
