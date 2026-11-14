"""Loopback TLS fixture for single-image unused full/incremental restart."""
from pstream_peer import upload_value

import argparse
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading

from test_probe import check, exact, wire


def value(peer, tag=None):
    tag = exact(peer, 1)[0] if tag is None else tag
    if tag == 1:
        return int.from_bytes(exact(peer, exact(peer, 1)[0]), "big")
    if tag == 16:
        return exact(peer, int.from_bytes(exact(peer, 2), "big")).decode("ascii")
    if tag == 32:
        return exact(peer, int.from_bytes(exact(peer, 4), "big"))
    if tag == 66:
        result = {}
        while (tag := exact(peer, 1)[0]) != 64:
            key = value(peer, tag)
            result[key] = value(peer)
        return result
    raise AssertionError(f"unexpected request tag {tag}")


def run(driver, cert, key, incremental, allocation=False, prepared=False):
    mib = 1024*1024
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    errors, actions, uploads, skipped, preparations = [], [], 0, 0, 0
    stop = threading.Event()
    connections = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(.1)

        def handle(peer):
            nonlocal uploads, skipped, preparations
            try:
                with peer:
                    peer.settimeout(5)
                    check(value(peer)["action"] == "encrypt_channel", "missing TLS upgrade")
                    peer.sendall(wire({}))
                    with context.wrap_socket(peer, server_side=True) as tls:
                        request = value(tls)
                        action = request["action"]
                        actions.append(action)
                        if action == "query_server_info":
                            reply = dict(ds_id="test-nas")
                        elif action == "client_trigger":
                            if request["subaction"] == "get_base_version":
                                check(incremental, "full upload requested a base")
                                reply = dict(base_version_id=8)
                            else:
                                preparations += 1
                                check(preparations == 1, "capture handshake was repeated by image transfer")
                                check(request["subaction"] == "update_backup_task" and
                                      request["running_task_id"] == 27, "wrong prepare")
                                check(request.get("is_cbt", 0) == int(incremental), "wrong CBT prepare")
                                reply = dict(running_task_id=27, version_id=9, result_id=112, data_format=1)
                        elif action == "get_running_task_result":
                            reply = dict(running_task_result=dict(task_id=2, result_id=112,
                                         job_action="backup", status="incomplete"))
                        elif action == "get_running_task":
                            reply = dict(running_task_list=[dict(id=27, type=0, task_id=2,
                                version_id=9, result_id=112, status=2, detail_status=6,
                                is_backing_up=0, backup_task=dict(error_code=0,
                                is_cbt=int(incremental), base_version_id=8 if incremental else 0,
                                resume_info=json.dumps({"single-disk": dict(current=str(2*mib+512),
                                                       transfer_current=str(mib))})))])
                        else:
                            check(action == "backup", f"unexpected action {action}")
                            op = request["subaction"]
                            if op == "update_device_spec":
                                check(request["snapshot_info"] == b"{}", "wrong metadata")
                                reply = {}
                            elif op == "upload_block":
                                uploads += 1
                                check(request["resume"] == int(uploads == 2), "wrong resume flag")
                                tls.sendall(wire(dict(success=1)))
                                at = 0 if uploads == 1 else 2*mib+512
                                while at < 5*mib:
                                    block = upload_value(tls)
                                    length = block["length"]
                                    check(block["image_name"] == "single-disk" and
                                          block["offset"] == at and 0 < length <= mib and
                                          block["is_interval_cbt"] == int(incremental),
                                          "wrong image/offset/CBT block")
                                    unused = mib <= at < 3*mib
                                    check(at+length <= (mib if at < mib else 3*mib if unused else
                                                       4*mib if at < 4*mib else 5*mib),
                                          "block crosses excluded boundary")
                                    if unused:
                                        check(block["used"] == 0 and block["changed"] == int(not allocation) and
                                              block["changed_length"] == 0 and "buffer" not in block,
                                              "excluded partition uploaded used data")
                                        skipped += 1
                                    elif incremental and 3*mib <= at < 4*mib:
                                        check(block["used"] == 1 and block["changed"] == 0 and
                                              block["changed_length"] == 0 and "buffer" not in block,
                                              "inherited interval changed")
                                    else:
                                        check(block["used"] == 1 and block["changed"] == 1 and
                                              block["buffer"] == bytes([0xa5])*length,
                                              "used data differs")
                                    at += length
                                    if uploads == 1 and at == 2*mib:
                                        return  # Restart inside the excluded partition.
                                check(upload_value(tls) == dict(close=1), "upload did not close")
                                reply = dict(close=1)
                            else:
                                check(op == "check_complete" and request["status"] == "complete" and
                                      request.get("is_cbt", 0) == int(incremental) and uploads == 2,
                                      "finish lost CBT mode or preceded resume")
                                reply = dict(status="complete")
                        tls.sendall(wire(reply))
            except Exception as error:
                errors.append(repr(error))

        def serve():
            while not stop.is_set():
                try:
                    peer, _ = listener.accept()
                except socket.timeout:
                    continue
                worker = threading.Thread(target=handle, args=(peer,))
                connections.append(worker)
                worker.start()

        server = threading.Thread(target=serve)
        server.start()
        try:
            mode = ("single-unused-prepared" if prepared else "single-unused-allocation" if allocation else
                    "single-unused-incremental" if incremental else "single-unused-full")
            result = subprocess.run([driver, str(listener.getsockname()[1]), str(cert), mode],
                                    capture_output=True, text=True, timeout=30)
            check(result.returncode == 0,
                  f"{mode}: {result.stdout} {result.stderr}; actions={actions}; errors={errors}")
        finally:
            stop.set()
            server.join(2)
            for connection in connections:
                connection.join(6)
        check(not errors and uploads == 2 and (skipped > 2 if allocation else skipped == 2),
              f"unused restart failed: {errors}")


def base_selection(driver, cert, key):
    """official agent asInt32 zero semantics over the actual TLS response parser."""
    replies = [{}, {"base_version_id": None}, {"base_version_id": "103"},
               {"base_version_id": b"103"}, {"base_version_id": 0}, {"base_version_id": 103},
               {"base_version_id": 0x100000067}, {"base_version_id": 0xffffffff}]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    errors = []
    stop = threading.Event()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(.1)
        def serve():
            try:
                while not stop.is_set():
                    try:
                        peer, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with peer:
                        peer.settimeout(5)
                        check(value(peer)["action"] == "encrypt_channel", "base query TLS upgrade missing")
                        peer.sendall(wire({}))
                        with context.wrap_socket(peer, server_side=True) as tls:
                            request = value(tls)
                            if request["action"] == "query_server_info":
                                reply = {"ds_id": "test-nas"}
                            else:
                                check(request["action"] == "client_trigger" and
                                      request["subaction"] == "get_base_version" and request["task_id"] == 2,
                                      "unexpected base-selection request")
                                reply = replies.pop(0)
                            tls.sendall(wire(reply))
            except Exception as error:
                errors.append(repr(error))
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            result = subprocess.run([driver, str(listener.getsockname()[1]), str(cert), "base-selection"],
                                    capture_output=True, text=True, timeout=20)
            check(result.returncode == 0, f"base selection failed: {result.stderr}; {errors}")
        finally:
            stop.set()
            worker.join(6)
        check(not worker.is_alive() and not errors and not replies, f"base response coverage failed: {errors}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("driver")
    parser.add_argument("openssl")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="opensabba-single-unused-") as directory:
        cert, key = Path(directory)/"cert.pem", Path(directory)/"key.pem"
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
                        "-days", "1", "-keyout", str(key), "-out", str(cert),
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"],
                       capture_output=True, check=True)
        base_selection(str(Path(args.driver).resolve()), cert, key)
        for incremental in (False, True):
            run(str(Path(args.driver).resolve()), cert, key, incremental)
        run(str(Path(args.driver).resolve()), cert, key, True, allocation=True)
        run(str(Path(args.driver).resolve()), cert, key, False, prepared=True)
    print("PASS unused full/incremental allocation journals and resumed independent used/changed flags")


if __name__ == "__main__":
    main()
