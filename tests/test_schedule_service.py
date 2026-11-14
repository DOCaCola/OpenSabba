"""A deterministic scheduled event creates a official agent online backup handshake."""
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from pstream_peer import value
from test_probe import check, wire


def run(driver, cert, key, base):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    stopped = threading.Event()
    requests, errors = [], []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(.2)

        def serve():
            try:
                while not stopped.is_set():
                    try:
                        peer, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with peer:
                        peer.settimeout(5)
                        check(value(peer)["action"] == "encrypt_channel", "missing TLS upgrade")
                        peer.sendall(wire({}))
                        with context.wrap_socket(peer, server_side=True) as tls:
                            req = value(tls)
                            action = req.get("subaction", req["action"])
                            requests.append(req)
                            if action == "query_server_info":
                                reply = dict(ds_id="test-nas")
                            elif action == "get_base_version":
                                reply = dict(base_version_id=base)
                            elif action == "add_backup_task":
                                check(req["task_id"] == 2 and req["trigger_type"] == 2,
                                      "scheduled trigger identity/type changed")
                                check(req["base_version_id"] == base and req["is_cbt"] == bool(base) and
                                      req["is_cache"] == 0 and req["check_point_backup"] == 0,
                                      "scheduled backup handshake flags changed")
                                reply = dict(running_task_id=27, version_id=9, result_id=112, data_format=1)
                            else:
                                raise AssertionError(f"unexpected scheduled request: {req}")
                            tls.sendall(wire(reply))
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            completed = subprocess.run([driver, str(listener.getsockname()[1]), str(cert), str(base)],
                                       capture_output=True, text=True, timeout=20)
            check(completed.returncode == 0, completed.stdout + completed.stderr)
        finally:
            stopped.set()
            worker.join(3)
        if errors:
            raise errors[0]
        check(sum(r.get("subaction") == "add_backup_task" for r in requests) == 1,
              "scheduled event was lost or repeated")
        check(not any(r.get("subaction") == "update_backup_task" for r in requests),
              "scheduled event incorrectly required a NAS-created job")


def main():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run([sys.argv[2], "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", str(key), "-out", str(cert), "-subj", "/CN=127.0.0.1",
                        "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
        for base in (0, 8):
            run(sys.argv[1], cert, key, base)
    print("scheduled service fixture passed")


if __name__ == "__main__":
    main()
