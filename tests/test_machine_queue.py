"""Loopback TLS only: queue cancellation while a simulated capture is running."""
from pstream_peer import upload_value
from upload_timing import record_timing

import argparse
import ctypes
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from test_probe import check, exact, wire
from test_login import value as protocol_value


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


def run(driver, cert, key, mode):
    driver_mode = mode
    mode = mode.removeprefix("direct-")
    errors, actions = [], []
    performance = {}
    stop = threading.Event()
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(cert, key)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(.1)

        polls = 0
        upload_attempts = 0
        checkpoint_queries = 0
        received = {"disk-0": b"", "disk-1": b""}
        mib = 1024*1024
        incremental_base = {"disk-0": bytes([0xa5])*(4*mib),
                            "disk-1": bytes([0x5a])*(4*mib)}
        incremental_current = {name: bytearray(data) for name, data in incremental_base.items()}
        incremental_current["disk-0"][mib+4096] = 0x13
        incremental_current["disk-1"][2*mib+8192] = 0x27
        incremental_target = {name: bytearray(data) for name, data in incremental_base.items()}
        inherited = set()
        lz4 = ctypes.CDLL("liblz4.so.1")
        lz4.LZ4_decompress_safe.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
        lz4.LZ4_decompress_safe.restype = ctypes.c_int
        def apply_incremental(block):
            name, at, length = block["image_name"], block["offset"], block["length"]
            check(name in incremental_target and at+length <= 4*mib and length,
                  "incremental block has wrong image or geometry")
            check(block["is_interval_cbt"] == 1 and block["used"] == 1,
                  "incremental upload did not mark its image interval")
            expected = bytes(incremental_current[name][at:at+length])
            if block["changed"]:
                data = block["buffer"]
                if mode.endswith("lz4"):
                    output = ctypes.create_string_buffer(length)
                    count = lz4.LZ4_decompress_safe(data, output, len(data), length)
                    check(block.get("compressed") == 1 and count == length, "invalid LZ4 changed block")
                    data = output.raw
                else:
                    check("compressed" not in block, "raw block marked compressed")
                check(data == expected, "incremental changed bytes differ")
                incremental_target[name][at:at+length] = data
            else:
                check("buffer" not in block and block["changed_length"] == 0 and
                      bytes(incremental_base[name][at:at+length]) == expected,
                      "incremental inherited range differs from base")
                inherited.add(name)
        connections = []
        def handle(peer):
            nonlocal polls, upload_attempts, checkpoint_queries
            try:
                with peer:
                    peer.settimeout(10)
                    check(value(peer)["action"] == "encrypt_channel", "upgrade missing")
                    peer.sendall(wire({}))
                    with tls_context.wrap_socket(peer, server_side=True) as tls:
                        request = protocol_value(tls)
                        action = request["action"]
                        actions.append(action)
                        if action == "query_server_info":
                            reply = {"ds_id": "test-nas"}
                        elif mode.startswith("bandwidth") and action == "backup":
                            check(request["subaction"] == "upload_block", "wrong upload action")
                            init = dict(success=1)
                            if mode != "bandwidth-absent":
                                init["backup_bandwidth"] = ("invalid" if mode == "bandwidth-invalid" else
                                                            0 if mode == "bandwidth-zero" else 512)
                            tls.sendall(wire(init))
                            if mode == "bandwidth-invalid":
                                return
                            block = dict(image_name="rate-test", offset=0, length=4096,
                                used=1, changed=1, is_interval_cbt=0, buffer=bytes([0xa5])*4096)
                            expected = wire(block)
                            started = time.monotonic()
                            check(exact(tls, len(expected)) == expected, "paced stream changed data")
                            elapsed = time.monotonic()-started
                            if mode == "bandwidth-zero":
                                check(elapsed < 2, "explicit handshake zero did not remove prior policy")
                            else:
                                arrival = record_timing(block,512)["arrival_us"]/1000000
                                check(max(len(expected)/512*.95,arrival-.25) <= elapsed < arrival+4,
                                      "handshake limit was discarded or exceeded")
                            check(upload_value(tls, performance) == {"close": 1}, "missing upload close")
                            reply = {"close": 1}
                        elif mode in ("multi-upload", "multi-job") and action == "backup" and request["subaction"] == "upload_block":
                            check(request["subaction"] == "upload_block" and request["resume"] == 0,
                                  "wrong multi-image initialization")
                            tls.sendall(wire(dict(success=1)))
                            for name, byte in (("disk-0",0xa5),("disk-1",0x5a)):
                                expected = wire(dict(image_name=name, offset=0, length=4096,
                                    used=1, changed=1, is_interval_cbt=0, buffer=bytes([byte])*4096))
                                check(wire(upload_value(tls, performance)) == expected,
                                      f"multi-image block changed: {name}")
                            check(upload_value(tls, performance) == {"close": 1}, "missing shared upload close")
                            check(set(performance) == ({"read_disk", "send", "snapshot"} if mode == "multi-job"
                                                       else {"read_disk", "send"}), "missing multi-image components")
                            check(performance["read_disk"]["size"] == performance["send"]["size"] == 8192,
                                  "multi-image counters were cumulative or counted framing")
                            check(performance["send"]["messages"] == 2, "first and final drains missing")
                            if mode == "multi-job":
                                check(performance["snapshot"] == {"time":123456789,"size":0,"messages":1},
                                      "snapshot timing repeated or changed")
                            reply = {"close": 1}
                        elif mode == "multi-job" and action == "client_trigger":
                            check(request["subaction"] == "update_backup_task" and
                                  request["running_task_id"] == 27, "wrong multi-image preparation")
                            reply = dict(running_task_id=27, version_id=1, result_id=112, data_format=1)
                        elif mode == "multi-job" and action == "backup":
                            if request["subaction"] == "update_device_spec":
                                check(request["snapshot_info"] == b"{}", "multi-image metadata changed")
                                reply = {}
                            else:
                                check(request["subaction"] == "check_complete" and
                                      request["status"] == "complete", "wrong multi-image completion")
                                reply = {"status": "complete"}
                        elif mode == "multi-resume" and action == "get_running_task_result":
                            reply = {"running_task_result": dict(task_id=2,result_id=112,
                                job_action="backup",status="incomplete")}
                        elif mode == "multi-resume" and action == "get_running_task":
                            reply = {"running_task_list":[dict(id=27,type=0,task_id=2,
                                version_id=1,result_id=112,status=2,detail_status=6,
                                is_backing_up=0,backup_task=dict(error_code=0,
                                resume_info=json.dumps({"disk-0":dict(current="4096",
                                    transfer_current="5000"),"disk-1":dict(current="2048",
                                    transfer_current="2100")})))]}
                        elif mode == "multi-resume" and action == "backup":
                            if request["subaction"] == "upload_block":
                                check(request["resume"] == 1,"multi-image resume flag missing")
                                tls.sendall(wire(dict(success=1)))
                                expected = wire(dict(image_name="disk-1",offset=2048,length=2048,
                                    used=1,changed=1,is_interval_cbt=0,buffer=bytes([0x5a])*2048))
                                check(wire(upload_value(tls, performance)) == expected,
                                      "multi-image resumed the wrong range")
                                check(upload_value(tls, performance) == {"close":1},"multi-image resume close missing")
                                check(set(performance) == {"read_disk","send"} and all(
                                    item["size"] == 2048 for item in performance.values()),
                                    "resume counted already committed bytes")
                                reply = {"close":1}
                            else:
                                check(request["subaction"] == "check_complete" and
                                      request["status"] == "complete","multi-image resume completion wrong")
                                reply = {"status":"complete"}
                        elif mode == "multi-interrupt-resume" and action == "client_trigger":
                            check(request["subaction"] == "update_backup_task", "wrong interrupted job preparation")
                            reply = dict(running_task_id=27, version_id=1, result_id=112, data_format=1)
                        elif mode == "multi-interrupt-resume" and action == "get_running_task_result":
                            reply = {"running_task_result": dict(task_id=2,result_id=112,
                                job_action="backup",status="incomplete")}
                        elif mode == "multi-interrupt-resume" and action == "get_running_task":
                            checkpoint_queries += 1
                            checkpoints = {"foreign-disk": dict(current="4096",transfer_current="4096")} \
                                if checkpoint_queries == 1 else {
                                    "disk-0": dict(current="4096",transfer_current="4096"),
                                    "disk-1": dict(current=str(1024*1024),transfer_current=str(1024*1024))}
                            reply = {"running_task_list":[dict(id=27,type=0,task_id=2,
                                version_id=1,result_id=112,status=2,detail_status=6,
                                is_backing_up=0,backup_task=dict(error_code=0,
                                resume_info=json.dumps(checkpoints)))]}
                        elif mode == "multi-interrupt-resume" and action == "backup":
                            if request["subaction"] == "update_device_spec":
                                check(request["snapshot_info"] == b"{}", "interrupted job metadata changed")
                                reply = {}
                            elif request["subaction"] == "upload_block":
                                upload_attempts += 1
                                check(request["resume"] == (upload_attempts == 2),
                                      "interrupted upload has wrong resume flag")
                                tls.sendall(wire(dict(success=1)))
                                if upload_attempts == 1:
                                    for name, offset, data in (("disk-0",0,bytes([0xa5])*4096),
                                                               ("disk-1",0,bytes([0x5a])*(1024*1024))):
                                        expected = wire(dict(image_name=name,offset=offset,length=len(data),
                                            used=1,changed=1,is_interval_cbt=0,buffer=data))
                                        check(wire(upload_value(tls, performance)) == expected,
                                              f"interrupted upload changed {name}")
                                        received[name] += data
                                    return  # Drop the channel during the second image.
                                check(upload_attempts == 2, "unexpected upload replay")
                                data = bytes([0x5a])*(1024*1024)
                                expected = wire(dict(image_name="disk-1",offset=1024*1024,length=len(data),
                                    used=1,changed=1,is_interval_cbt=0,buffer=data))
                                check(wire(upload_value(tls, performance)) == expected,
                                      "second-image resume did not continue from NAS offset")
                                received["disk-1"] += data
                                check(upload_value(tls, performance) == {"close":1}, "resumed upload did not close")
                                reply = {"close":1}
                            else:
                                check(request["subaction"] == "check_complete" and
                                      request["status"] == "complete", "wrong interrupted job finish")
                                check(upload_attempts == 2 and checkpoint_queries == 2 and
                                      received["disk-0"] == bytes([0xa5])*4096 and
                                      received["disk-1"] == bytes([0x5a])*(2*1024*1024),
                                      "NAS finalized before both exact images arrived")
                                reply = {"status":"complete"}
                        elif mode.startswith("multi-incremental") and action == "client_trigger":
                            if request["subaction"] == "get_base_version":
                                check(request["task_id"] == 2, "incremental base selected for wrong task")
                                reply = {"base_version_id":8}
                            else:
                                check(request["subaction"] == "update_backup_task" and
                                      request["base_version_id"] == 8 and request["is_cbt"] == 1,
                                      "multi-incremental preparation lost its NAS base")
                                reply = dict(running_task_id=27,version_id=9,result_id=112,data_format=1)
                        elif mode.startswith("multi-incremental") and action == "get_running_task_result":
                            reply = {"running_task_result":dict(task_id=2,result_id=112,
                                job_action="backup",status="incomplete")}
                        elif mode.startswith("multi-incremental") and action == "get_running_task":
                            checkpoint_queries += 1
                            reply = {"running_task_list":[dict(id=27,type=0,task_id=2,
                                version_id=9,result_id=112,status=2,detail_status=6,
                                is_backing_up=0,backup_task=dict(is_cbt=1,
                                base_version_id=7 if checkpoint_queries == 1 else 8,error_code=0,
                                resume_info=json.dumps({"disk-0":dict(current=str(4*mib),
                                    transfer_current=str(4*mib)),
                                    "disk-1":dict(current=str(mib+mib//2),
                                    transfer_current=str(mib+mib//2))})))]}
                        elif mode.startswith("multi-incremental") and action == "backup":
                            if request["subaction"] == "update_device_spec":
                                check(request["snapshot_info"] == b"{}", "incremental metadata changed")
                                reply = {}
                            elif request["subaction"] == "upload_block":
                                upload_attempts += 1
                                check(request["resume"] == int(upload_attempts == 2),
                                      "incremental resume flag changed")
                                tls.sendall(wire(dict(success=1)))
                                position = {"disk-0":0 if upload_attempts == 1 else 4*mib,
                                            "disk-1":0 if upload_attempts == 1 else mib+mib//2}
                                while True:
                                    block = upload_value(tls, performance)
                                    if "close" in block:
                                        check(upload_attempts == 2 and inherited == {"disk-0","disk-1"},
                                              "inherited intervals missing")
                                        check(all(incremental_target[name] == incremental_current[name]
                                                  for name in incremental_target),
                                              "two-disk incremental reconstruction differs")
                                        reply = {"close":1}
                                        break
                                    name, at, length = block["image_name"], block["offset"], block["length"]
                                    check(at == position[name], "incremental image checkpoint ignored")
                                    apply_incremental(block)
                                    position[name] = at+length
                                    if upload_attempts == 1 and name == "disk-1" and position[name] == 2*mib:
                                        return  # Break in the second image after an inherited interval.
                            else:
                                check(request["subaction"] == "check_complete" and
                                      request["status"] == "complete" and request["is_cbt"] == 1 and
                                      upload_attempts == 2 and checkpoint_queries == 2,
                                      "multi-incremental finalized with wrong base or before resume")
                                check(all(incremental_target[name] == incremental_current[name]
                                          for name in incremental_target),
                                      "NAS incremental reconstruction incomplete")
                                reply = {"status":"complete"}
                        elif mode == "task-policy" and action == "get_task":
                            reply = {"task_list": [dict(id=2, name="Policy fixture", compression=1, source_type=1,
                                pre_script_enabled=0, pre_post_script_setting=dict(
                                    pre_script_enabled=1, post_script_enabled=0,
                                    script_exec_mode=0, pre_script_content="SECRET"))]}
                        else:
                            check(action == "get_running_task", f"unexpected NAS mutation: {action}")
                            check(request["token"] == "test-token", "wrong test credential")
                            polls += 1
                            job = dict(id=27, task_id=2, type=0, status=0)
                            jobs = [job]
                            if mode == "absent-initial" or (polls > 1 and mode == "absent"):
                                jobs = []
                            elif polls > 1 and mode in ("cancel", "cancel-after-ready", "cleanup-after-cancel", "cancel-then-next"):
                                job["status"] = 3
                                if mode == "cancel-then-next" and polls > 2:
                                    job.update(id=28, status=0)
                            elif polls > 1 and mode == "foreign":
                                job["task_id"] = 99
                            elif polls > 1 and mode == "duplicate":
                                jobs.append(dict(job))
                            reply = {"running_task_list": jobs}
                            if polls > 1 and mode == "control-error":
                                reply = {"error": {"code": 8193}}
                        tls.sendall(wire(reply))
            except (EOFError, ssl.SSLEOFError, ConnectionResetError, BrokenPipeError):
                pass  # Observer shutdown cancels its in-flight socket.
            except Exception as error:
                errors.append(repr(error))

        def serve():
            while not stop.is_set():
                try:
                    peer, _ = listener.accept()
                except socket.timeout:
                    continue
                connection = threading.Thread(target=handle, args=(peer,))
                connections.append(connection)
                connection.start()

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            # Both positive-policy cases have4206 encoded bytes at512B/s:
            # 8s last-byte arrival,8.214843s through final sleep. The15s
            # child budget leaves6.785157s for TLS/scheduling/close. Other
            # cases have zero pacing; incremental retries retain their30s IO budget.
            timeout = 30 if mode.startswith("multi-incremental") else 15
            result = subprocess.run([driver, str(listener.getsockname()[1]), str(cert), driver_mode],
                                    capture_output=True, text=True, timeout=timeout)
            check(result.returncode == 0,
                  f"{mode}: driver returncode={result.returncode}; stdout={result.stdout!r}; "
                  f"stderr={result.stderr!r}; actions={actions!r}; server errors={errors!r}")
        except subprocess.TimeoutExpired as error:
            raise AssertionError(f"{mode}: driver timed out; actions={actions}; server errors={errors}") from error
        finally:
            stop.set()
            worker.join(4)
            for connection in connections:
                connection.join(11)
        check(not worker.is_alive() and all(not c.is_alive() for c in connections) and not errors, f"{mode}: {errors}")
        if mode.startswith("bandwidth"):
            check("get_backup_bandwidth" not in actions, "upload invented a periodic policy query")
        check(("backup" if mode.startswith("bandwidth") or mode.startswith("multi-") else
               "get_task" if mode == "task-policy" else "get_running_task") in actions,
              "no task observation")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("driver")
    parser.add_argument("openssl")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="opensabba-queue-") as directory:
        root = Path(directory)
        cert, key = root/"cert.pem", root/"key.pem"
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
                        "-days", "1", "-keyout", str(key), "-out", str(cert),
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"],
                       capture_output=True, check=True)
        for mode in ("bandwidth", "bandwidth-absent", "bandwidth-zero", "bandwidth-invalid", "multi-upload", "multi-job", "multi-resume",
                     "multi-incremental-raw", "multi-incremental-lz4",
                     "direct-multi-incremental-raw", "direct-multi-incremental-lz4",
                     "multi-interrupt-resume", "task-policy", "complete", "absent-initial", "absent", "cancel", "foreign",
                     "duplicate", "control-error", "cleanup-error", "shutdown",
                     "cancel-after-ready", "cleanup-after-cancel", "cancel-then-next"):
            run(str(Path(args.driver).resolve()), cert, key, mode)


if __name__ == "__main__":
    main()
