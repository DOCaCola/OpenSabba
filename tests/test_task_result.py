"""official agent task-result event request shape and durable acknowledgment ordering."""
import argparse
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
from pstream_peer import Reader, value
from test_probe import check, wire


def run(driver, cert, key, root, result_id, response, failure=False):
    journal = root / "events.pstream"
    actions, errors = [], []
    stopped = threading.Event()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
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
                            request = value(tls)
                            action = request["action"]
                            actions.append(action)
                            if action == "query_server_info":
                                reply = {"ds_id": "test-nas"}
                            elif action == "pull_event":
                                reply = {"event_list": [{"id": 42, "action": "get_running_task_result",
                                                        "task_id": 2, "version_id": 9}]}
                            elif action == "get_running_task_result":
                                check(set(request) == {"action", "agent", "token", "ds_id"} |
                                      ({"result_id"} if result_id else set()), "wrong result request shape")
                                check(request.get("result_id", 0) == result_id, "wrong history result")
                                saved = value(Reader(journal.read_bytes()))
                                check(saved["receipts"][0]["state"] == "pending", "receipt not durable")
                                reply = response
                            elif action == "done_event":
                                saved = value(Reader(journal.read_bytes()))
                                receipt = saved["receipts"][0]
                                check(request["done_events"] == [42] and receipt["state"] == "ack_pending",
                                      "acknowledgment preceded durable result")
                                check("secret" not in str(receipt["task_result"]), "private fields retained")
                                reply = {}
                            else:
                                raise AssertionError("unexpected action " + action)
                            tls.sendall(wire(reply))
            except Exception as error:
                errors.append(repr(error))
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            process = subprocess.run([driver, str(listener.getsockname()[1]), str(cert),
                                      str(journal), str(result_id)], capture_output=True, text=True, timeout=15)
            check(process.returncode == int(failure), f"{process.stderr}; {errors}; {actions}")
        finally:
            stopped.set()
            worker.join(6)
    check(not errors and not worker.is_alive(), str(errors))
    saved = value(Reader(journal.read_bytes()))
    check(actions.count("done_event") == int(not failure), "failed lookup acknowledged")
    check(bool(saved["receipts"]) == failure, "wrong retained receipt state")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("driver")
    parser.add_argument("openssl")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="opensabba-task-result-") as directory:
        root = Path(directory)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
                        "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
        driver = str(Path(args.driver).resolve())
        for result_id, response, failure in (
                (0, {}, False),
                (0, {"running_task_result": {"job_action": "unknown"}}, False),
                (112, {"backup_result": {"last_success_time": 99, "last_backup_status": "complete",
                                        "secret": "private"},
                       "running_task_result": {"task_id": 2, "result_id": 112, "job_action": "backup",
                                               "status": "incomplete", "secret": "private"}}, False),
                (112, {"error": {"code": 4106}}, True)):
            run(driver, cert, key, root, result_id, response, failure)


if __name__ == "__main__":
    main()
