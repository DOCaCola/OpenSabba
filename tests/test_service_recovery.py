"""Restart durable service phases against an independent mock NAS."""
import argparse
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
from pstream_peer import value
from test_probe import check, wire


def run(driver, cert, key, root, mode, env=None):
    journal = root / (mode + ".pstream")
    subprocess.run([driver, "1", str(cert), str(journal), mode, "seed"], check=True,
                   capture_output=True, text=True)
    errors, actions, details = [], [], []
    stopped = threading.Event()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(.2)

        def serve():
            operation_done = False
            try:
                while not stopped.is_set():
                    try:
                        peer, _ = listener.accept()
                    except socket.timeout:
                        continue
                    try:
                        with peer:
                            peer.settimeout(10)
                            check(value(peer)["action"] == "encrypt_channel", "TLS upgrade missing")
                            peer.sendall(wire({}))
                            with context.wrap_socket(peer, server_side=True) as tls:
                                req = value(tls)
                                action = req.get("subaction", req["action"])
                                actions.append(action)
                                if action == "query_server_info":
                                    reply = dict(ds_id="test-nas")
                                elif action == "get_running_task":
                                    if req.get("check_backup_exist") or ((mode == "operation-error" or mode.startswith("read-")) and not operation_done):
                                        job = dict(id=27, task_id=2, type=0, version_id=9, result_id=112,
                                            status=1, is_backing_up=int(mode == "active"),
                                            backup_task=dict(data_format=2 if mode == "app-aware-format2" else 1, error_code=0,
                                                resume_info="{}" if mode == "metadata-resume" else ""))
                                        reply = dict(running_task_list=[] if mode == "missing" else [job])
                                    else:
                                        reply = dict(running_task_list=[dict(id=28, task_id=2, type=0,
                                            status=0, version_id=0, result_id=0)])
                                elif action == "update_device_spec":
                                    check(req["running_task_id"] == 27 and req["resume"] == int(mode == "metadata-resume") and
                                          req["snapshot_info"] == b"{}", "metadata recovery changed snapshot")
                                    check(req["enable_app_aware"] == int(mode == "app-aware"),
                                          "retained task application-aware policy or format-2 exclusion lost")
                                    reply = {}
                                elif action == "get_running_task_result":
                                    check(req["result_id"] == 112, "wrong terminal result")
                                    reply = dict(running_task_result=dict(task_id=2, result_id=112,
                                        job_action="backup", status="complete" if mode == "finish-terminal"
                                        else "incomplete"))
                                elif action == "check_complete":
                                    check(req["status"] == ("cancel" if mode == "timeout" else
                                          "error" if mode in ("source-missing", "operation-error") or
                                          (mode.startswith("read-") and mode != "read-eio-skip") else "complete") and req["running_task_id"] == 27 and
                                          req["result_id"] == 112, "wrong repeated completion")
                                    operation_done = True
                                    reply = dict(status=req["status"])
                                elif action == "result_detail":
                                    check(len(req["logs"]) == 1 and not operation_done, "activity must precede completion")
                                    log = req["logs"][0]
                                    if mode == "source-missing":
                                        check(log["log_type"] == 7021, "wrong missing-snapshot detail")
                                    else:
                                        check(log["running_task_id"] == 27 and isinstance(log["log_time"],int),
                                              "source activity envelope changed")
                                        params = json.loads(log["other_params"])
                                        expected = dict(id=27,running_task_id=27,task_id=2,result_id=112,
                                                        task_uuid="test-task-uuid")
                                        if log["log_type"] == 7044:
                                            expected.update(volume_name="/dev/source",interval_start="0x200",interval_end="0x3ff")
                                        elif log["log_type"] == 7084:
                                            expected.update(error_code="ffffffffffffffe5" if mode == "read-cow" else "fffffffffffffffb")
                                        else:
                                            check(log["log_type"] == 7020, "wrong source read activity")
                                            expected.update(error_code="61" if mode == "read-enodata" else "5")
                                        check(params == expected, f"wrong source activity content: {params}")
                                        details.append(log["log_type"])
                                    reply = {}
                                else:
                                    raise AssertionError(f"unexpected action {action}")
                                tls.sendall(wire(reply))
                    except (EOFError, ConnectionResetError, BrokenPipeError, ssl.SSLEOFError,
                            ssl.SSLZeroReturnError):
                        # run_service_backup cancels its concurrent observer after
                        # the injected operation error; keep serving its final result.
                        if mode != "operation-error" and not mode.startswith("read-"):
                            raise
            except Exception as error:
                errors.append(repr(error))
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            process = subprocess.run([driver, str(listener.getsockname()[1]), str(cert), str(journal),
                mode, "recover"], capture_output=True, text=True, timeout=50,env=env)
            check(process.returncode == 0, f"{mode}: {process.stderr}; {errors}; {actions}")
        finally:
            stopped.set()
            worker.join(12)
    check(not errors and not worker.is_alive(), f"{mode}: {errors}")
    check(actions.count("update_device_spec") == int(mode in ("prepare", "prepared", "metadata", "metadata-resume",
          "app-aware", "app-aware-format2")),
          f"{mode}: metadata replay count {actions}")
    check(actions.count("check_complete") == int(mode in ("finish-incomplete", "timeout", "source-missing", "operation-error") or mode.startswith("read-")),
          f"{mode}: completion replay count {actions}")
    if mode.startswith("read-"):
        check(details == ([7044] if mode == "read-eio-skip" else [7020] if mode == "read-enodata" else [7084,7020]),
              f"source activity ordering changed: {details}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("driver")
    parser.add_argument("openssl")
    parser.add_argument("--source-reads",action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="opensabba-service-recovery-") as directory:
        root = Path(directory)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
            "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
            "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
        modes = ("read-enodata","read-eio-skip","read-eio-fatal","read-cow") if args.source_reads else ("prepare", "prepared", "metadata", "metadata-resume", "app-aware", "app-aware-format2",
                     "finish-terminal", "finish-incomplete",
                     "active", "missing", "timeout", "source-missing", "operation-error")
        for mode in modes:
            run(str(Path(args.driver).resolve()), cert, key, root, mode)
            print(mode + ": passed")


if __name__ == "__main__":
    main()
