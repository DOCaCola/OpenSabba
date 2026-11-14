"""Loopback-only protocol/TLS integration tests; never connects to a NAS."""
import argparse
import json
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def wire(value):
    """Independent test-peer encoder from docs/pstream.md."""
    if value is None:
        return b"\x00\x00"
    if isinstance(value, int):
        width = next(n for n in (1, 2, 4, 8) if value < 1 << (8 * n))
        return b"\x01" + bytes([width]) + value.to_bytes(width, "big")
    if isinstance(value, str):
        data = value.encode("utf-8")
        return b"\x10" + len(data).to_bytes(2, "big") + data
    if isinstance(value, bytes):
        return b"\x20" + len(value).to_bytes(4, "big") + value
    if isinstance(value, dict):
        return b"\x42" + b"".join(wire(k) + wire(v) for k, v in sorted(value.items())) + b"\x40"
    if isinstance(value, list):
        return b"\x41" + b"".join(wire(v) for v in value) + b"\x40"
    raise TypeError(value)


def exact(peer, count):
    data = b""
    while len(data) < count:
        part = peer.recv(count - len(data))
        if not part:
            raise EOFError("peer closed early")
        data += part
    return data


def request(action):
    return wire({"agent": {"version": {"major": 3, "minor": 2, "mini": 1, "build": "5059"}},
                 "action": action})


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def run_case(executable, cert, key, mode, host="127.0.0.1", trust=True):
    errors = []
    stages = []
    with socket.socket(socket.AF_INET6 if host == "::1" else socket.AF_INET) as listener:
        bind_host = host if host in ("::1", "127.0.0.2") else "127.0.0.1"
        listener.bind((bind_host, 0))
        listener.listen(1)
        listener.settimeout(6)
        port = listener.getsockname()[1]

        def server():
            try:
                with listener.accept()[0] as peer:
                    stages.append("accepted")
                    peer.settimeout(5)
                    expected = request("encrypt_channel")
                    check(exact(peer, len(expected)) == expected, "wrong cleartext upgrade request")
                    stages.append("upgrade received")
                    if mode == "eof":
                        peer.sendall(b"\x42\x10")
                        return
                    if mode == "timeout":
                        time.sleep(2)
                        return
                    if mode == "reject":
                        peer.sendall(wire({"error": {"code": 4096}}))
                        check(peer.recv(1) == b"", "client continued after upgrade rejection")
                        return
                    if mode == "bad-root":
                        peer.sendall(wire(7))
                        return
                    # Concatenation tests message boundaries; writes fragment the acknowledgment.
                    response = wire({"type": "keep_alive"}) + wire({})
                    for offset in range(0, len(response), 3):
                        peer.sendall(response[offset:offset + 3])
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(cert, key)
                    stages.append("acknowledgment sent")
                    try:
                        secured = context.wrap_socket(peer, server_side=True)
                        stages.append("TLS established")
                    except ssl.SSLError:
                        if mode in ("untrusted", "wrong-host"):
                            return
                        raise
                    with secured:
                        check(mode not in ("untrusted", "wrong-host"),
                              "client accepted an invalid certificate")
                        expected = request("query_server_info")
                        check(exact(secured, len(expected)) == expected, "wrong encrypted info request")
                        stages.append("query received")
                        if mode == "tls-timeout":
                            time.sleep(2)
                            return
                        if mode == "info-error":
                            secured.sendall(wire({"error": {"code": 16386}}))
                        elif mode == "oversize":
                            secured.sendall(b"\x20\xff\xff\xff\xff")
                        elif mode == "keepalive-flood":
                            try:
                                secured.sendall(wire({"type": "keep_alive"}) * 257)
                            except (ssl.SSLError, ConnectionError):
                                pass  # Client may close as soon as its cap is reached.
                        else:
                            response = wire({"type": "keep_alive"}) + wire({
                                "data": {"package_version": {"build": "25059"}},
                            })
                            for offset in range(0, len(response), 2):
                                secured.sendall(response[offset:offset + 2])
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=server, daemon=True)
        worker.start()
        command = [executable, "probe", host, "--port", str(port),
                   "--timeout", "1" if mode in ("timeout", "tls-timeout") else "5"]
        if trust:
            command += ["--ca-file", str(cert)]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=8)
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(f"{mode}: client hung; stages={stages}, errors={errors}; "
                                 f"stderr={exc.stderr!r}") from exc
        worker.join(timeout=6)
        check(not worker.is_alive(), f"{mode}: server did not finish")
        check(not errors, f"{mode}: mock failed: {errors!r}; client stderr: {result.stderr}")
        if mode == "success":
            check(result.returncode == 0, result.stderr)
            check(json.loads(result.stdout)["data"]["package_version"]["build"] == "25059",
                  "incorrect server-info output")
        else:
            check(result.returncode == 1, f"{mode}: unexpected exit {result.returncode}")
            check(not result.stdout, f"{mode}: reported success output")
            expected_error = {
                "reject": "server rejected encrypt_channel (code 4096)",
                "info-error": "server rejected query_server_info (code 16386)",
                "timeout": "timed out", "tls-timeout": "timed out",
                "bad-root": "server response must be a map",
                "oversize": "byte limit exceeded",
                "keepalive-flood": "too many keep_alive",
                "untrusted": "certificate", "wrong-host": "certificate",
                "eof": "peer closed",
            }[mode]
            check(expected_error in result.stderr,
                  f"{mode}: expected {expected_error!r}, got {result.stderr!r}")
        print(f"{mode}: passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("executable")
    parser.add_argument("openssl")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="opensabba-probe-") as directory:
        cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
        # Ephemeral self-signed test certificate for loopback only.
        subprocess.run([
            args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
            "-days", "1", "-keyout", str(key), "-out", str(cert),
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
        ], check=True, capture_output=True)
        for mode in ("success", "reject", "info-error", "eof", "bad-root",
                     "oversize", "keepalive-flood", "timeout", "tls-timeout"):
            run_case(args.executable, cert, key, mode)
        run_case(args.executable, cert, key, "untrusted", trust=False)
        run_case(args.executable, cert, key, "wrong-host", host="127.0.0.2")
        run_case(args.executable, cert, key, "success", host="localhost")
        if socket.has_ipv6:
            with socket.socket(socket.AF_INET6) as ipv6:
                try:
                    ipv6.bind(("::1", 0))
                    ipv6_available = True
                except OSError:
                    ipv6_available = False
            if ipv6_available:
                run_case(args.executable, cert, key, "success", host="::1")
            else:
                print("IPv6 loopback unavailable: IPv6 case skipped")
        for options in (["--port", "0"], ["--port", "65536"], ["--port", "-1"],
                        ["--timeout", "0"], ["--timeout", "301"], ["--timeout"],
                        ["--insecure"], ["--ca-file", str(Path(directory) / "missing.pem")]):
            result = subprocess.run([args.executable, "probe", "localhost", *options],
                                    capture_output=True, timeout=5)
            check(result.returncode == 1, f"invalid options accepted: {options}")
        print("CLI validation: passed")


if __name__ == "__main__":
    main()
