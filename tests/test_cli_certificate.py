"""Linux-only PTY + persistent certificate store, with an offline loopback NAS."""
import hashlib
import os
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import tempfile

from test_login import terminal
from test_probe import check, wire
from test_registration import Nas


def main():
    executable, openssl = sys.argv[1:]
    executable = str(Path(executable).resolve())
    with tempfile.TemporaryDirectory(prefix="opensabba-cli-trust-") as temporary:
        root = Path(temporary)
        pairs = []
        for index in range(2):
            cert, key = root / f"certificate-{index}.pem", root / f"key-{index}.pem"
            subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
                            "-days", "1", "-keyout", str(key), "-out", str(cert),
                            "-subj", "/CN=offline.invalid", "-addext",
                            "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
            pairs.append((cert, key))
        first, key = pairs[0]
        second, second_key = pairs[1]
        nas = Nas(first, key)
        nas.allow_client_disconnect = True
        env = dict(os.environ, XDG_CONFIG_HOME=str(root / "config"), TZ="CET-1")
        command = ["--connect", "--address", "127.0.0.1", "--port", str(nas.port),
                   "--username", "test-user", "--password", "private-password-987"]

        def cli(*options, expected=0):
            if options and options[0] == "--logout":
                options += (("--quiet",) if "-q" not in options else ()) + ("--username", "test-admin", "--password", "admin-password-837")
            result = subprocess.run([executable, *options], env=env, capture_output=True,
                                    text=True, timeout=10, start_new_session=True)
            check(result.returncode == expected, result.stdout + result.stderr)
            check("private-password-987" not in result.stdout + result.stderr, "password leaked")
            return result

        def certificate_bytes(cert):
            digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            return wire({f"127.0.0.1:{nas.port}": {"sha256": digest}})

        try:
            cli("--connect", "--quiet", expected=1)
            code, output = terminal([executable, *command], env, certificate_answer="n")
            check(code == 13 and not nas.requests, output)
            check(not (root / "config/opensabba/session.pstream").exists(), "declined trust saved session")
            code, output = terminal([executable, *command], env, certificate_answer="\x03")
            check(code == 7 and not nas.requests, "cancelled certificate trust sent application data")
            check(not (root / "config/opensabba/session.pstream").exists(), "cancelled trust saved session")
            code, output = terminal([executable, *command], env, certificate_answer="")
            check(code == 0 and "SHA-256:" in output, "default-yes certificate trust failed")
            check(not cli(*command, "-q").stdout, "quiet pinned connect printed success")
            private = root / "config/opensabba"
            trusted = private / "certificates.pstream"
            session = private / "session.pstream"
            check(trusted.read_bytes() == certificate_bytes(first), "fingerprint not persisted")
            check(stat.S_IMODE(trusted.stat().st_mode) == 0o600, "trust file is public")
            check(b"private-password-987" not in trusted.read_bytes(), "trust file contains password")
            saved_session = session.read_bytes()
            cli("probe")
            check(not cli("--status", "--quiet", expected=2).stdout, "quiet status printed output")
            check(cli("--version", "--quiet").stdout, "quiet version lost explicit version output")
            check(not cli("--help", "--quiet").stdout, "quiet help printed output")
            nas.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            nas.context.load_cert_chain(second, second_key)
            count = len(nas.requests)
            result = cli(*command, "-q", expected=12)
            check("interactively" in result.stderr and len(nas.requests) == count,
                  "changed certificate sent application data")
            check(session.read_bytes() == saved_session and
                  trusted.read_bytes() == certificate_bytes(first), "rejection changed saved state")
            cli("reconnect", expected=1)
            code, output = terminal([executable, *command], env, certificate_answer="n")
            check(code == 12 and len(nas.requests) == count, output)
            code, output = terminal([executable, *command], env, certificate_answer="YES")
            check(code == 0 and "SHA-256:" in output and
                  trusted.read_bytes() == certificate_bytes(second), output)
            cli("probe")
            # A CA-verified replacement renews without an interactive prompt.
            trusted.write_bytes(certificate_bytes(first))
            cli(*command, "--ca-file", str(second), "-q")
            check(trusted.read_bytes() == certificate_bytes(second), "CA renewal did not update pin")
            nas.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            nas.context.load_cert_chain(first, key)
            count = len(nas.requests)
            cli(*command, "--ca-file", str(second), "-q", expected=13)
            check(len(nas.requests) == count, "custom CA was bypassed")
            # A rejected custom-CA handshake produces a deliberate server alert.
            for client in nas.clients:
                client.join(6)
            check(all(isinstance(error, ssl.SSLError) for error in nas.errors), str(nas.errors))
            nas.errors.clear()
            nas.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            nas.context.load_cert_chain(second, second_key)
            check(not cli("--logout", "-q").stdout and not session.exists(), "quiet logout failed")
            check(trusted.exists(), "logout removed persisted trust")
        finally:
            nas.close()
        print("PASS CLI quiet mode, PTY trust, durable pins and CA renewal")


if __name__ == "__main__":
    main()
