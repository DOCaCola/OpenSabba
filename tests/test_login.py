"""Linux PTY + loopback TLS tests. All credentials and sessions are disposable."""
import argparse
import errno
import os
from pathlib import Path
import pty
import select
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import termios
import time

from pstream_peer import value
from test_probe import check, exact, request, wire


def terminal(command, env, password="test-password-742", otp="123456", cancel=False, approval="",
             retry_otp=None, certificate_answer=None, logout_answer=None, admin=False, address=None):
    if "--connect" in command and "--otp" not in command:
        command = command + ["--otp", otp]
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(command[0], command, env)
    original_terminal = termios.tcgetattr(fd)
    output = b""
    password_sent = otp_sent = False
    approval_sent = False
    retry_sent = False
    certificate_sent = logout_sent = admin_user_sent = False
    address_sent = False
    deadline = time.monotonic() + 12
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], .1)[0]:
                try:
                    chunk = os.read(fd, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output += chunk
                if b"Enter server address:" in output and not address_sent:
                    check(address is not None, "unexpected address prompt")
                    os.write(fd,address.encode()+b"\n")
                    address_sent = True
                if b"Proceed anyway?" in output and not certificate_sent:
                    check(certificate_answer is not None, "unexpected certificate prompt")
                    os.write(fd, certificate_answer.encode() + b"\n")
                    certificate_sent = True
                if b"Once signed out," in output and not logout_sent:
                    check(logout_answer is not None, "unexpected logout prompt")
                    os.write(fd,logout_answer.encode()+bytes([10]))
                    logout_sent = True
                if b"Enter admin username:" in output and not admin_user_sent:
                    check(admin, "unexpected administrator prompt")
                    os.write(fd,b"test-admin"+bytes([10]))
                    admin_user_sent = True
                if b"Enter admin password:" in output and not password_sent:
                    check(admin, "unexpected administrator password prompt")
                    os.write(fd,b"admin-password-837"+bytes([10]))
                    password_sent = True
                if b"Enter password:" in output and not password_sent:
                    os.write(fd, b"\x03" if cancel else password.encode() + b"\n")
                    password_sent = True
                if b"OTP (Enter if not enabled): " in output and not otp_sent:
                    os.write(fd, otp.encode() + b"\n")
                    otp_sent = True
                if b"OTP retry (Enter to cancel): " in output and not retry_sent:
                    check(retry_otp is not None, "unexpected OTP retry")
                    os.write(fd, retry_otp.encode() + b"\n")
                    retry_sent = True
                if (b"Confirm authentication? [y/n](default: y): " in output or
                    b"Enter [y/n](default: y): " in output) and not approval_sent:
                    check(approval is not None, "unexpected registration prompt")
                    os.write(fd, bytes([3]) if approval == "__interrupt__" else bytes([4])
                             if approval == "__eof__" else approval.encode() + b"\n")
                    approval_sent = True
        else:
            os.kill(pid, 9)
            raise AssertionError("interactive login hung")
    finally:
        restored_terminal = termios.tcgetattr(fd)
        os.close(fd)
        _, status = os.waitpid(pid, 0)
    mask = termios.ECHO | termios.ICANON | termios.ISIG
    check((restored_terminal[3] & mask) == (original_terminal[3] & mask),
          "interactive prompt left terminal echo, canonical input or signals disabled")
    text = output.decode(errors="replace")
    check("admin-password-837" not in text, "admin password echoed")
    check(password not in text and (not otp or otp not in text), "credential echoed")
    check(not retry_otp or retry_otp not in text, "retry OTP echoed")
    return os.waitstatus_to_exitcode(status), text


def run_mock(executable, env, cert, key, mode, scripted=False):
    errors, received = [], []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(8)
        port = listener.getsockname()[1]

        def server():
            try:
                rounds = 2 if mode in ("otp-required", "otp-invalid", "otp-rejected") else 1
                for action in (("query_server_info", "auth") * rounds +
                               (("query_server_info", "confirm_auth") if mode == "pending" else ())):
                    with listener.accept()[0] as peer:
                        peer.settimeout(5)
                        check(value(peer) == {"action": "encrypt_channel", "agent": {
                            "version": {"major": 3, "minor": 2, "mini": 1, "build": "5059"}}},
                            "credentials or unexpected metadata before TLS")
                        peer.sendall(wire({}))
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        context.load_cert_chain(cert, key)
                        with context.wrap_socket(peer, server_side=True) as secured:
                            message = value(secured)
                            received.append(message)
                            check(message["action"] == action, "wrong auth sequence")
                            # Server version parsing reads agent.version.build, not
                            # the official agent client's internal "_agent" field.
                            check(message.get("agent", {}).get("version", {}).get("build") == "5059",
                                  "wire request lacks server-readable agent version")
                            check("_agent" not in message, "internal map key leaked onto wire")
                            if action == "query_server_info":
                                secured.sendall(wire({"ds_id": "mock-nas-1"}))
                            elif action == "confirm_auth":
                                check(message["template_id"] == 7 and message["connect_type"] == "backup",
                                      "wrong registration selection")
                                secured.sendall(wire({}))
                            elif mode.startswith("otp-") and (len(received) == 2 or mode == "otp-rejected"):
                                secured.sendall(wire({"error": {"code": 4101 if mode in
                                    ("otp-required", "otp-empty") else 4102}}))
                            elif mode.startswith("reject-"):
                                secured.sendall(wire({"error": {"code": int(mode.split("-")[1]),
                                                               "message": "UNTRUSTED-ERROR-TEXT"}}))
                            elif mode == "missing-token":
                                secured.sendall(wire({"auth_type": 5}))
                            else:
                                reply = {
                                    "token": "mock-secret-token-985",
                                    "auth_type": 1 if mode == "pending" else 5}
                                if mode == "pending":
                                    reply.update(temp_device={"backup_type": 2},
                                                 task_template={"id": 7, "template_name": "Linux test",
                                                                "share_name": "test-backups"})
                                secured.sendall(wire({"type": "keep_alive"}) + wire(reply))
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=server, daemon=True)
        worker.start()
        command = [executable, "--connect", "--address", "127.0.0.1", "--username", "test-user",
                   "--port", str(port), "--ca-file", str(cert)]
        if scripted:
            options = ["--password-fd", "0", "--quiet"]
            if scripted != "no-otp":
                options += ["--otp-fd", "0"]
            result = subprocess.run(command + options,
                                    env=env, input="test-password-742" if scripted == "no-otp"
                                    else "test-password-742\r\n123456\r\n",
                                    capture_output=True, text=True, timeout=10, start_new_session=True)
            code, output = result.returncode, result.stdout + result.stderr
            check(not result.stdout and "OTP retry" not in output and "Password:" not in output,
                  "scripted login prompted or ignored quiet mode")
            check("test-password-742" not in output and "123456" not in output, "scripted credentials leaked")
        else:
            code, output = terminal(command, env,
                                    retry_otp="" if mode == "otp-empty" else "654321" if mode.startswith("otp-") else None)
        worker.join(8)
        check(not worker.is_alive() and not errors, f"mock failure: {errors}; {output}")
        check(code == (3 if mode.startswith("reject-") or mode in
                      ("missing-token", "otp-rejected", "otp-empty") else 0), output)
        descriptions = {
            "reject-4096": "Authentication denied",
            "reject-4098": "username or password you entered is incorrect",
            "reject-4100": "user account has expired",
            "reject-4103": "OTP is enforced by the administrator",
            "reject-4106": "User token or temporary device registration not found",
            "reject-4118": "managed by",
            "reject-8193": "Running backup task not found",
            "reject-16385": "requires a newer client version",
            "reject-53250": "server identity (ds_id) has changed",
            "reject-59999": "server rejected auth (code 59999)",
        }
        if mode in descriptions:
            check(descriptions[mode] in output, f"missing error description: {output}")
        check("UNTRUSTED-ERROR-TEXT" not in output, "raw server error printed")
        check("mock-secret-token-985" not in output, "token printed")
        auth = next(message for message in reversed(received) if message["action"] == "auth")
        check(auth["password"] == "test-password-742" and auth["otp"] ==
              ("" if scripted == "no-otp" else "654321" if mode in
               ("otp-required", "otp-invalid", "otp-rejected") else "123456"),
              "incorrect password or OTP")
        check(auth["driver_status"] == "disable", "incorrect driver availability")
        check(len(auth["device_uuid"]) == 36 and auth["host_name"] and auth["os_name"],
              "missing device metadata")
        if mode == "pending" and not scripted:
            check("Successfully connected" in output and "Linux test" in output,
                  "connect did not display and confirm selected template")
        print(f"login {mode}: passed")
        return auth["device_uuid"], port


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("executable")
    parser.add_argument("openssl")
    args = parser.parse_args()
    executable = str(Path(args.executable).resolve())
    with tempfile.TemporaryDirectory(prefix="opensabba-login-") as directory:
        root = Path(directory)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
                        "-days", "1", "-keyout", str(key), "-out", str(cert),
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"],
                       check=True, capture_output=True)
        env = dict(os.environ, XDG_CONFIG_HOME=str(root / "config"))
        def cli(*options):
            return subprocess.run([executable, *options], env=env, text=True,
                                  capture_output=True, timeout=10)
        uuid, _ = run_mock(executable, env, cert, key, "success")
        store = root / "config" / "opensabba"
        session = store / "session.pstream"
        check(stat.S_IMODE(store.stat().st_mode) == 0o700, "directory not private")
        check(stat.S_IMODE(session.stat().st_mode) == 0o600, "session not private")
        before = session.read_bytes()
        check(b"test-password-742" not in before and b"123456" not in before,
              "password or OTP persisted")
        check(b"mock-secret-token-985" in before, "token not saved")
        run_mock(executable, env, cert, key, "success", scripted="no-otp")
        for mode in ("success", "pending", "reject-4101", "reject-4102", "reject-4096"):
            saved = session.read_bytes()
            same_uuid, _ = run_mock(executable, env, cert, key, mode, scripted=True)
            check(same_uuid == uuid, "scripted login changed identity")
            if mode.startswith("reject-"):
                check(session.read_bytes() == saved, "scripted failure replaced session")
            check(b"test-password-742" not in session.read_bytes() and
                  b"123456" not in session.read_bytes(), "scripted credentials persisted")
        before = session.read_bytes()
        for data, expected in (("", "password cannot be empty"), ("x"*4097+"\n", "size limit"),
                               ("secret\0value\n", "NUL byte")):
            result = subprocess.run([executable, "--connect", "--address", "localhost", "--username", "test",
                                     "--password-fd", "0", "--quiet"], env=env, input=data,
                                    capture_output=True, text=True, timeout=5, start_new_session=True)
            check(result.returncode == 1 and expected in result.stderr, result.stderr)
            check(session.read_bytes() == before, "invalid descriptor input changed session")
        for mode in ("reject-4096", "reject-4098", "reject-4100", "reject-4103", "reject-4106", "reject-4118",
                     "reject-8193", "reject-16385", "reject-53250", "reject-59999",
                     "missing-token", "otp-rejected", "otp-empty"):
            same_uuid, _ = run_mock(executable, env, cert, key, mode)
            check(same_uuid == uuid, "device identity changed")
            check(session.read_bytes() == before, "failure replaced saved session")
        for mode in ("otp-required", "otp-invalid"):
            same_uuid, _ = run_mock(executable, env, cert, key, mode)
            check(same_uuid == uuid, "OTP retry changed device identity")
            check(b"654321" not in session.read_bytes(), "retry OTP persisted")
        same_uuid, _ = run_mock(executable, env, cert, key, "pending")
        check(same_uuid == uuid, "device identity changed on login")
        result = cli("--status")
        check(result.returncode == 2 and not result.stdout and
              result.stderr == "Cannot access synology-backupd\n", result.stderr)
        check("mock-secret-token-985" not in result.stdout, "status leaked token")
        # Saved endpoint is used by probe; the auth mock listener is now closed.
        result = cli("probe")
        check(result.returncode == 1 and "TCP connection failed" in result.stderr,
              "probe did not use the saved endpoint")
        session.chmod(0o644)
        check(cli("reconnect").returncode == 1, "insecure token permissions accepted")
        session.chmod(0o600)
        original = session.read_bytes()
        session.unlink()
        victim = root / "victim"
        victim.write_bytes(original)
        victim.chmod(0o600)
        session.symlink_to(victim)
        check(cli("reconnect").returncode == 1, "session symlink followed")
        check(cli("--logout").returncode == 8 and victim.read_bytes() == original,
              "logout accepted an unsafe recovery credential")
        session.unlink()
        check(cli("--status").returncode == 2, "logout left session")
        check((store / "identity.pstream").exists(), "logout removed device identity")
        code, output = terminal([executable, "--connect", "--address", "127.0.0.1", "--username", "test"], env,
                                cancel=True)
        check(code == 7 and "cancelled" in output, "Ctrl-C cancellation failed")
        check(not session.exists(), "cancelled login saved session")
        for options in (["--password", "secret", "--password-fd", "0"], ["--port", "0"], ["--username"],
                        ["--otp-fd", "0"], ["--password-fd", "-1"], ["--password-fd", "bad"],
                        ["--password-fd", "999999"], ["--quiet", "--quiet"]):
            check(cli("--connect", "--address", "localhost", "--username", "test", *options).returncode == 1,
                  "invalid login options accepted")
        code, output = terminal([executable, "--connect", "--address", "localhost", "--username", "test",
                                 "--password-fd", "0"], env)
        check(code == 1 and "must not refer to a terminal" in output, "terminal descriptor accepted")
        print("persistence, permissions, symlinks, cancellation, and validation: passed")


if __name__ == "__main__":
    main()
