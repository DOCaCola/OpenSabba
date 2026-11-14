"""official agent get_timezone request and response handling against loopback TLS."""
import argparse
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pstream_peer import value
from test_probe import check, wire


def run(driver, cert, key, mode):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    errors, actions = [], []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(10)

        def serve():
            try:
                for expected in ("query_server_info", "get_timezone"):
                    peer, _ = listener.accept()
                    with peer:
                        peer.settimeout(10)
                        check(value(peer)["action"] == "encrypt_channel", "missing TLS upgrade")
                        peer.sendall(wire({}))
                        with context.wrap_socket(peer, server_side=True) as tls:
                            request = value(tls)
                            check(request["action"] == expected, "wrong action")
                            actions.append(expected)
                            if expected == "query_server_info":
                                reply = {"ds_id": "test-nas"}
                            else:
                                check(request["token"] == "test-token" and request["ds_id"] == "test-nas",
                                      "wrong authentication")
                                if mode == "error":
                                    reply = {"error": {"code": 8193, "message": "denied"}}
                                elif mode == "invalid-epoch":
                                    reply = {"timezone": "3600", "epoch": ""}
                                elif mode == "overflow-timezone":
                                    reply = {"timezone": "9223372036854775808", "epoch": str(int(time.time()))}
                                else:
                                    epoch = int(time.time()) + 1000
                                    reply = {"timezone": "-3600" if mode == "string" else (1 << 64) - 3600,
                                             "epoch": str(epoch) if mode == "string" else epoch}
                            tls.sendall(wire(reply))
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        result = subprocess.run([driver, str(listener.getsockname()[1]), str(cert)],
                                capture_output=True, text=True, timeout=20)
        worker.join(15)
        check(not worker.is_alive() and not errors, f"mock failed: {errors}")
        check(actions == ["query_server_info", "get_timezone"], "unexpected requests")
        if mode == "error":
            check(result.returncode == 1 and
                  "server rejected get_timezone (code 8193)" in result.stderr and
                  "get timezone failed (8193: 'denied')" in result.stderr and
                  result.stderr.count("denied") == 1,
                  f"wrong error: {result}")
        elif mode in ("invalid-epoch", "overflow-timezone"):
            expected = ("invalid server time field: epoch" if mode == "invalid-epoch" else
                        "server time field out of range: timezone")
            check(result.returncode == 1 and expected in result.stderr,
                  f"missing numeric field diagnostic: {result}")
        else:
            check(result.returncode == 0, result.stderr)
            zone, difference, offset = map(int, result.stdout.split())
            check(zone == -3600 and 995 <= difference <= 1002 and offset == difference + zone,
                  f"wrong conversion: {result.stdout}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("driver")
    parser.add_argument("openssl")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="opensabba-server-time-") as directory:
        root = Path(directory)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
                        "-days", "1", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=IP:127.0.0.1"], capture_output=True, check=True)
        for mode in ("string", "integer", "error", "invalid-epoch", "overflow-timezone"):
            run(str(Path(args.driver).resolve()), cert, key, mode)
            print(f"{mode}: passed")


if __name__ == "__main__":
    main()
