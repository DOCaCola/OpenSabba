"""The official agent logout authenticates first; lock timeout never schedules deletion."""
import fcntl
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from test_probe import check, wire
from test_registration import Nas
from pstream_peer import Reader, value

with tempfile.TemporaryDirectory(prefix="opensabba-logout-timeout-") as directory:
    root = Path(directory)
    cert, key = root/'cert.pem', root/'key.pem'
    subprocess.run([sys.argv[2], 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                    '-days', '1', '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=IP:127.0.0.1'],check=True,capture_output=True)
    nas = Nas(cert,key)
    private = root / "opensabba"
    private.mkdir(mode=0o700)
    session = private / "session.pstream"
    original = wire(dict(format=2,host='127.0.0.1',port=nas.port,ca_file=str(cert),
                         username='test-user',device_uuid='test-device',ds_id=nas.ds_id,token=nas.token,
                         registration_state='confirmed'))
    session.write_bytes(original)
    session.chmod(0o600)
    fd = os.open(private, os.O_RDONLY | os.O_DIRECTORY)
    process = None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        stat = os.fstat(fd)
        address = f"\0opensabba-{os.getuid()}-{stat.st_dev}-{stat.st_ino}"
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
            server.bind(address)
            server.listen(1)
            server.settimeout(8)
            started = time.monotonic()
            process = subprocess.Popen(
                [sys.argv[1], "--logout", "--quiet", "--username", "test-admin", "--password", "admin-password-837"],
                env=dict(os.environ, XDG_CONFIG_HOME=str(root)),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            with server.accept()[0] as peer:
                request = peer.recv(65536)
                check(request.startswith(b"auth:"), "wrong authorization request")
                credentials = value(Reader(request[5:]))
                check(credentials == dict(username="test-admin", password="admin-password-837", otp=""),
                      "wrong administrator credentials")
                peer.sendall(b"authorized:timeout-fixture")
            with server.accept()[0] as peer:
                check(peer.recv(64) == b"stop:timeout-fixture", "wrong control request")
                peer.sendall(b"accepted")
            out, err = process.communicate(timeout=35)
            check(process.returncode == 1 and "logout not performed" in err, out + err)
            check(29 <= time.monotonic() - started < 36, "incorrect logout deadline")
            check(session.read_bytes() == original, "timeout erased credentials")
            check(not nas.requests, 'CLI bypassed service authorization or unlinked NAS')
            fcntl.flock(fd, fcntl.LOCK_UN)
            time.sleep(.2)
            check(session.read_bytes() == original, "late unlock caused credential deletion")
            print("PASS logout timeout: credentials retained after authorization, acknowledgment and late unlock")
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        os.close(fd)
        nas.close()
