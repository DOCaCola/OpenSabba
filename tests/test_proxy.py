"""Independent CONNECT relay: encrypted login, persistence, failures and TLS identity."""
import os
import base64
import zipfile
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile

from test_probe import check
from test_registration import Nas
from test_service import wait_for


from proxy_peer import Proxy


exe, openssl = sys.argv[1:]
with tempfile.TemporaryDirectory(prefix="opensabba-proxy-") as temporary:
    root = Path(temporary)
    cert, key = root/"cert.pem", root/"key.pem"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
                    "-days", "1", "-keyout", str(key), "-out", str(cert),
                    "-subj", "/CN=nas.test.invalid", "-addext",
                    "subjectAltName=DNS:nas.test.invalid"], check=True, capture_output=True)
    nas = Nas(cert, key)
    nas.allow_client_disconnect = True
    proxy = Proxy(nas.port)
    env = dict(os.environ, XDG_CONFIG_HOME=str(root/"config"), TZ="CET-1")

    def cli(*args, expected=0, proxy_password="proxy-secret-927"):
        if args and args[0] == "--logout":
            args += ("--quiet", "--username", "test-admin", "--password", "admin-password-837")
        result = subprocess.run([exe, *args], env=env, input="test-password-742\n123456\n"+proxy_password+"\n",
                                text=True, capture_output=True,
                                timeout=30 if args[0] == "--export-log" else 8, start_new_session=True)
        check(result.returncode == expected, result.stdout + result.stderr)
        check("test-password-742" not in result.stdout + result.stderr, "credential leaked")
        check("proxy-secret-927" not in result.stdout + result.stderr, "proxy password leaked")
        check(base64.b64encode(b"proxy-user:proxy-secret-927").decode() not in
              result.stdout + result.stderr, "encoded proxy credentials leaked")
        return result

    options = ["--proxy-address", "127.0.0.1", "--proxy-port", str(proxy.port), "--ca-file", str(cert)]
    try:
        cli("--connect", "--address", "nas.test.invalid", "--username", "test-user", "--password-fd", "0",
            "--otp-fd", "0", "--quiet", *options)
        cli("reconnect")
        cli("tasks")
        cli("probe")
        proxy.response = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.0 204 \r\n\r\n"
        cli("probe")
        before = len(proxy.requests)
        for response, error in [
            (b"HTTP/1.1 407 Secret proxy detail\r\n\r\n", "authentication is required"),
            (b"HTTP/1.1 403 Secret proxy detail\r\n\r\n", "status 403"),
            (b"NOT-HTTP 200 invalid\r\n\r\n", "invalid HTTP proxy response"),
            (b"HTTP/1.1 200 OK\r\nX: "+b"x"*16384, "headers exceed size limit")]:
            proxy.response = response
            result = cli("probe", expected=1)
            check(error in result.stderr and "Secret proxy detail" not in result.stderr,
                  result.stderr)
        check(len(proxy.requests) == before + 4, "saved proxy ignored")
        proxy.response = b"HTTP/1.1 200 Connection established\r\n\r\n"
        # Trusting the issuer is still required inside the tunnel.
        result = cli("probe", "nas.test.invalid", "--proxy-address", "127.0.0.1",
                     "--proxy-port", str(proxy.port), expected=1)
        check("certificate" in result.stderr, "proxy bypassed TLS trust")
        proxy.authority = b"wrong.test.invalid:5510"
        result = cli("probe", "wrong.test.invalid", *options, expected=1)
        check("certificate" in result.stderr, "proxy bypassed NAS hostname verification")
        proxy.authority = b"nas.test.invalid:5510"
        cli("--logout")
        check(len(nas.errors) == 2 and all(isinstance(e, ssl.SSLError) and
              ("ALERT_UNKNOWN_CA" in str(e) or "ALERT_BAD_CERTIFICATE" in str(e))
              for e in nas.errors), str(nas.errors))
        nas.errors.clear()  # These two TLS alerts are intentional negative tests.
        proxy.credentials = b"proxy-user:proxy-secret-927"
        login = ["--connect", "--address", "nas.test.invalid", "--username", "test-user", "--password-fd", "0",
                 "--otp-fd", "0", "--quiet", *options, "--proxy-username", "proxy-user",
                 "--proxy-password-fd", "0"]
        cli(*login)
        cli("reconnect")
        cli("probe")
        cli("--status", expected=2)
        before_auth = sum(r["action"] == "auth" for r in nas.requests)
        service = subprocess.Popen([exe, "service", "run"], env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            wait_for(lambda: sum(r["action"] == "auth" for r in nas.requests) > before_auth,
                     "proxied service did not authenticate")
            cli("--reload")
            wait_for(lambda: sum(r["action"] == "auth" for r in nas.requests) > before_auth+1,
                     "proxied service did not reload")
        finally:
            service.terminate()
            out, err = service.communicate(timeout=5)
        check(service.returncode == 0 and "proxy-secret-927" not in out+err, out+err)
        report = root/"diagnostics.zip"
        cli("--export-log", "--output-file", str(report))
        with zipfile.ZipFile(report) as archive:
            contents = b"".join(archive.read(name) for name in archive.namelist())
        check(b"proxy-secret-927" not in contents and
              base64.b64encode(b"proxy-user:proxy-secret-927") not in contents,
              "diagnostics leaked proxy credentials")
        private = root/"config/opensabba"
        session = private/"session.pstream"
        check(session.stat().st_mode & 0o777 == 0o600, "proxy credentials not private")
        saved = session.read_bytes()
        before = len(nas.requests)
        proxy.response = b"HTTP/1.1 407 Authentication required\r\nProxy-Authenticate: NTLM\r\n\r\n"
        rejected = cli(*login, expected=3)
        check("rejected Basic authentication" in rejected.stderr, rejected.stderr)
        check(session.read_bytes() == saved and len(nas.requests) == before,
              "proxy rejection changed session or reached NAS")
        proxy.response = b"HTTP/1.1 200 Connection established\r\n\r\n"
        for password in ("bad\tpassword", "bad\rpassword"):
            cli(*login, proxy_password=password, expected=3)
        invalid_user = login.copy()
        invalid_user[invalid_user.index("--proxy-username")+1] = "bad:user"
        cli(*invalid_user, expected=3)
        check(session.read_bytes() == saved, "invalid proxy credentials changed session")
        cli("--logout")
        cli(*login)
        before = len(proxy.requests)
        proxy.respond.clear()
        service = subprocess.Popen([exe, "service", "run"], env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            wait_for(lambda: len(proxy.requests) > before, "service did not reach held CONNECT")
            proxy.respond.set()
            cli("--logout")
            out, err = service.communicate(timeout=5)
            check(service.returncode == 0 and not session.exists(), out+err)
        finally:
            proxy.respond.set()
            if service.poll() is None:
                service.kill()
                service.communicate()
        check(not proxy.errors and not nas.errors, str(proxy.errors + nas.errors))
        print("PASS HTTP CONNECT login, saved routing, NAS TLS verification and bounded failures")
    finally:
        proxy.close()
        nas.close()
