"""official agent script task buffers/result detail/output requests against loopback TLS."""
import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from pstream_peer import value
from test_probe import check, wire


def run(driver, cert, key, root, mode):
    errors, actions = [], []
    stop = threading.Event()
    prepared = completed = results = outputs = upload_errors = 0
    successful = mode.startswith("successful")
    captured_at = time.time()
    boundary = mode.startswith("boundary-")
    capture = mode.startswith("capture") or boundary
    refused = mode in ("capture-old", "capture-release",
                       "capture-observer", "capture-shutdown")
    capture_logs, activities = [], []
    activity_rows = []
    activity_attempts = []
    failed_activity_sends = 0
    queue_queries = 0
    observer_cancel_ready = False
    observer_disconnects = 0
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(.2)

        def serve():
            nonlocal prepared, completed, results, outputs, upload_errors, queue_queries
            nonlocal failed_activity_sends, observer_cancel_ready, observer_disconnects
            while not stop.is_set():
                try:
                    peer, _ = listener.accept()
                except socket.timeout:
                    continue
                cancel_observer = False
                try:
                    with peer:
                        peer.settimeout(10)
                        check(value(peer)["action"] == "encrypt_channel", "missing TLS upgrade")
                        if (mode.startswith("activity-") and mode.endswith("send-failed") and
                                not failed_activity_sends and (root/(mode+".pstream")).exists()):
                            # Fail the activity channel itself. Connection identity
                            # is discovered once, independently of each request.
                            failed_activity_sends += 1
                            continue
                        if mode == "capture-cancel-upgrade" and queue_queries == 1 and not observer_cancel_ready:
                            cancel_observer = True
                            observer_cancel_ready = True
                            (root/(mode+"-observer-ready")).touch()
                            check(peer.recv(1, socket.MSG_PEEK) == b"",
                                  "observer sent data before the TLS upgrade acknowledgment")
                        peer.sendall(wire({}))
                        with context.wrap_socket(peer, server_side=True) as tls:
                            request = value(tls)
                            action = request["action"]
                            actions.append(action)
                            if action == "query_server_info":
                                reply = {"ds_id": "test-nas"}
                            else:
                                check(request["token"] == "test-token", "wrong auth token")
                                if action == "get_task":
                                    failed = mode.startswith("failed") or mode in ("prepare-lost", "finish-lost")
                                    reply = {"task_list": [dict(id=2, name="Scripts", task_uuid="task-uuid",
                                        compression=0, encryption=1, source_type=1,
                                        pre_post_script_setting=dict(pre_script_enabled=1,
                                            post_script_enabled=int(capture or (successful and "scripts" in mode)), pre_script_extension=".py",
                                            post_script_extension=".sh", post_script_error=0,
                                            pre_script_error=7054 if failed else 0,
                                            script_exec_mode=int(failed or (boundary and "-continue" not in mode))),
                                        pre_script_content=b"exit 0\n", post_script_content=b"exit 0\n")]}
                                elif action == "client_trigger":
                                    check(request["subaction"] == "update_backup_task" and
                                          request["running_task_id"] == 27, "wrong failed backup preparation")
                                    check(request["base_version_id"] == 0 and request["is_cbt"] == 0 and
                                          request["is_cache"] == 0 and request["check_point_backup"] == 0,
                                          "failed preparation changed official agent flags")
                                    prepared += 1
                                    if mode == "prepare-lost":
                                        continue
                                    reply = dict(running_task_id=27, version_id=9, result_id=112, data_format=1)
                                elif action == "get_running_task":
                                    queue_queries += 1
                                    if request.get("check_backup_exist"):
                                        check(mode == "prepare-lost", "unexpected preparation recovery")
                                        tls.sendall(wire({"running_task_list": [dict(id=27, type=0, task_id=2,
                                            version_id=9, result_id=112, status=1, is_backing_up=0,
                                            backup_task=dict(data_format=1, error_code=0, resume_info=""))]}))
                                        continue
                                    if mode == "capture-observer" and queue_queries > 1:
                                        tls.sendall(wire({"error": {"code": 8193}}))
                                        continue
                                    reply = {"running_task_list": [dict(id=28 if completed else 27,
                                        type=0, task_id=2, status=0, version_id=0, result_id=0,
                                        detail_status=0, is_backing_up=0)]}
                                elif action == "backup":
                                    check(request["subaction"] == "check_complete" and
                                          request["status"] == "error" and
                                          request["running_task_id"] == 27, "wrong failed script result")
                                    completed += 1
                                    if mode in ("finish-lost", "capture-finish-lost", "boundary-post-stop-lost"):
                                        continue
                                    reply = {"status": "error"}
                                elif action == "get_running_task_result":
                                    check(mode in ("finish-lost", "capture-finish-lost", "boundary-post-stop-lost"), "unexpected result reconciliation")
                                    reply = {"running_task_result": dict(task_id=2, result_id=112,
                                        job_action="backup", status="failure")}
                                else:
                                    check(action == "log_report" and len(request["logs"]) == 1,
                                          f"unexpected script action {request}")
                                    record = request["logs"][0]
                                    kind = request["subaction"]
                                    if boundary:
                                        if kind == "result_detail":
                                            params = json.loads(record["other_params"])
                                            check(record["running_task_id"] == 27 and params["result_id"] == 112,
                                                  "boundary result belongs to another event")
                                            activities.append(record["log_type"])
                                            if record["log_type"] in (7046, 7047, 7050, 7051):
                                                check(params["exit_code"] == 37 and params["version_id"] == 9,
                                                      "boundary failure lost script exit/version")
                                        else:
                                            check(kind == "script_log", "unexpected boundary output")
                                            check(record["output"] == b"script output", "boundary output changed")
                                            outputs += 1
                                        tls.sendall(wire({}))
                                        continue
                                    if mode.startswith("activity-"):
                                        check(kind == "result_detail", "wrong activity transport")
                                        params = json.loads(record["other_params"])
                                        check(record["running_task_id"] == 27 and record["log_time"] == 1700000000 and
                                              record["log_type"] == (7001 if "capture" in mode else 7045) and
                                              params["id"] == 27 and params["running_task_id"] == 27 and
                                              params["result_id"] == 112, "wrong retained backup activity")
                                        activity_attempts.append(record)
                                        activity_rows.append(record)
                                        if mode.endswith("lost-reply") and len(activity_rows) == 1:
                                            continue
                                        tls.sendall(wire({}))
                                        continue
                                    if kind == "result_detail":
                                        activities.append(record["log_type"])
                                        if successful:
                                            check(prepared == 1, "activity sent before NAS result binding")
                                            params = json.loads(record["other_params"])
                                            check(params["id"] == 27 and params["running_task_id"] == 27 and
                                                  params["task_id"] == 2 and params["task_uuid"] == "task-uuid" and
                                                  params["result_id"] == 112, "wrong bound capture identity")
                                            check(captured_at + 300 < record["log_time"] < captured_at + 350,
                                                  "capture timestamp was not retained across restart")
                                            kind = record["log_type"]
                                            if kind == 7096:
                                                check(params == dict(id=27, running_task_id=27, task_id=2,
                                                    task_uuid="task-uuid", result_id=112,
                                                    mount_path="/missing-b, /missing-a"), "wrong custom warning parameters")
                                            elif kind in (7002, 7003):
                                                check(params["volume_name"] == "/", "wrong captured mount")
                                            elif kind == 7001:
                                                check(set(params) == {"id", "running_task_id", "task_id",
                                                    "task_uuid", "result_id"}, "unexpected 7001 parameters")
                                            else:
                                                check(kind in (7045, 7049) and params["exit_code"] == 0 and
                                                      params["version_id"] == 9, "wrong boundary script activity")
                                            tls.sendall(wire({}))
                                            continue
                                        if (capture or mode.startswith("partial")) and record["log_type"] in (7001, 7002, 7003, 7004, 7083, 7096):
                                            params = json.loads(record["other_params"])
                                            check(params["running_task_id"] == 27 and params["task_id"] == 2 and
                                                  params["result_id"] == 112, "wrong capture log identity")
                                            check(record["log_time"] == 1700000000, "capture log time changed")
                                            if record["log_type"] == 7096:
                                                check(params["mount_path"] == "/missing-b, /missing-a",
                                                      "wrong missing-volume warning")
                                            if record["log_type"] == 7004:
                                                check(params["error_code"] == "ffffffffffffffe4" and
                                                      params["volume_name"] == "/", "wrong snapshot errno/volume")
                                            capture_logs.append(record["log_type"])
                                            tls.sendall(wire({}))
                                            continue
                                        results += 1
                                        failed = mode.startswith("failed") or mode in ("prepare-lost", "finish-lost")
                                        check(record["running_task_id"] == 27 and
                                              record["log_type"] == (7049 if capture and results == 2 else
                                                  7054 if failed else 7045), "wrong log type/run")
                                        params = json.loads(record["other_params"])
                                        check(params["task_id"] == 2 and params["task_uuid"] == "task-uuid" and
                                              params["version_id"] == 9 and params["result_id"] == 112 and
                                              params["exit_code"] == (-1 if failed else 0), "wrong log detail")
                                    elif kind == "script_log":
                                        outputs += 1
                                        check(record == dict(task_id=2, version_id=9,
                                            output_source="post" if capture and outputs == 2 else "pre",
                                            output=(b"post output" if outputs == 2 else b"pre output") if capture else
                                                b"" if mode == "empty" else b"hello\0stderr\n"),
                                            "output wire fields/bytes changed")
                                        if mode == "output-lost" and outputs == 1:
                                            continue
                                        if mode == "output-error" and outputs == 1:
                                            tls.sendall(wire({"error": {"code": 8193}}))
                                            continue
                                    else:
                                        check(kind == "activity_log" and record["log_type"] == 7067,
                                              "wrong script upload failure activity")
                                        upload_errors += 1
                                    reply = {}
                            tls.sendall(wire(reply))
                except (ConnectionError, ssl.SSLEOFError, ssl.SSLZeroReturnError, EOFError) as error:
                    # A completed capture cancels its concurrent queue observer
                    # at any transport stage. The next connection still owns
                    # the capture's failure publication and must be served.
                    if capture:
                        observer_disconnects += int(cancel_observer)
                    else:
                        errors.append(str(error))
                except Exception as error:
                    errors.append(str(error))

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            phases = (mode+"-acquire", mode+"-publish", mode+"-publish") if successful else (mode,)
            for phase in phases:
                process = subprocess.run([driver, str(listener.getsockname()[1]), str(cert), str(root), phase],
                                         capture_output=True, text=True, timeout=25)
                check(process.returncode == 0,
                      f"{phase}: {process.stderr}; server={errors}; actions={actions}")
                if phase.endswith("-acquire"):
                    check(not activities and prepared == 0, "capture sent activity before binding")
        finally:
            stop.set()
            worker.join(12)
        check(not worker.is_alive() and not errors, f"{mode}: {errors}")
        if boundary:
            failed_pre = "-pre-" in mode
            abort = mode.endswith("-abort")
            terminal = "-stop" in mode
            expected = ([7047] if terminal and failed_pre else
                [7046 if failed_pre else 7045, 7001, 7002, 7003]+
                ([] if abort else [7051 if terminal else 7049 if failed_pre else 7050]))
            check(activities == expected, f"boundary activities changed: {activities}")
            check(prepared == completed == int(terminal), "terminal script failure did not stop its event")
            check(outputs == (1 if abort or (terminal and failed_pre) else 2),
                  "boundary output was omitted or aborted output was published")
            check("upload_block" not in actions and "update_device_spec" not in actions,
                  "terminal boundary entered real image transfer")
            return
        if mode.startswith("activity-"):
            rows = 2 if mode.endswith("lost-reply") else 1
            check(len(activity_rows) == rows and activity_rows == [activity_rows[0]] * rows,
                  "backup NAS rows do not match official agent retry semantics")
            check(failed_activity_sends == int(mode.endswith("send-failed")) and
                  len(activity_attempts) == rows, "failed send reached the activity handler")
            check(prepared == completed == outputs == 0, "activity retry repeated backup work")
            return
        if successful:
            expected = ([7045] if "scripts" in mode else []) + [7001] + (
                [7096] if "missing" in mode else []) + [7002, 7003] + ([7049] if "scripts" in mode else [])
            check(activities == expected, f"successful capture activities changed/replayed: {activities}")
            check(prepared == 1 and completed == 0, "successful capture rebound its result")
            if os.name != "nt":
                starts = [json.loads(line.split("activity=", 1)[1]) for line in
                          (root/"log/log.txt").read_text().splitlines() if "activity=" in line]
                starts = [entry for entry in starts if entry["parameters"]["task_name"] == mode]
                expected = [] if "start-cache" in mode else [1115 if "start-event" in mode else 1101]
                check([entry["log_type"] for entry in starts] == expected,
                      "capture start omitted or repeated by reuse/publication")
                check(all(entry["parameters"] == dict(task_name=mode,
                          trigger_type=3 if "start-event" in mode else 1, trigger_event=9)
                          for entry in starts), "start activity parameters changed")
                check(all(captured_at + 320 <= entry["log_time"] <= time.time() + 322
                          for entry in starts), "start activity lost NAS-adjusted boundary time")
            return
        if mode.startswith("partial"):
            check((prepared, completed, results, outputs) == (0, 0, 0, 0),
                  "partial capture entered failure completion or replayed scripts")
            check(capture_logs == [7001] + ([7096] if "missing" in mode else []) +
                  [7002, 7004, 7002, 7003], "partial capture logs replayed or omitted")
            return
        if capture:
            if mode.startswith("capture-cancel-"):
                check(observer_cancel_ready and observer_disconnects == 1,
                      "capture observer was not cancelled at the selected transport stage")
            expected = (0, 0, 0, 0) if refused else (1, 1, 0, 0) if mode.startswith("capture-no-scripts") else (1, 1, 2, 2)
            check((prepared, completed, results, outputs) == expected,
                  f"capture failure was replayed/omitted: {(prepared, completed, results, outputs)}")
            check(capture_logs == ([] if refused or mode == "capture-old" else
                  [7001] + ([7096] if "missing" in mode else []) + [7002, 7004, 7083]), "wrong capture logs")
            expected_activities = [] if refused else ([7001, 7002, 7004, 7083] if mode.startswith("capture-no-scripts") else
                [7045, 7001, 7002, 7004, 7083, 7049])
            if "missing" in mode:
                expected_activities.insert(expected_activities.index(7001)+1, 7096)
            check(activities == expected_activities, f"failed capture order changed: {activities}")
            return
        check(results == 1, "result log replayed or omitted")
        check(outputs == (2 if mode in ("output-lost", "output-error") else
                          0 if mode.startswith("failed") or mode in ("prepare-lost", "finish-lost") else 1),
              "script output retry count differs")
        check(upload_errors == int(mode == "output-error"), "missing upload failure activity")
        check(prepared == int(mode.startswith("failed") or mode in ("prepare-lost", "finish-lost")) and
              completed == int(mode.startswith("failed") or mode in ("prepare-lost", "finish-lost")),
              "uncertain failed-backup mutation was replayed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("driver")
    parser.add_argument("openssl")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="opensabba-script-wire-") as directory:
        root = Path(directory)
        cert, key = root/"cert.pem", root/"key.pem"
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
            "-days", "1", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
            "-addext", "subjectAltName=IP:127.0.0.1"], capture_output=True, check=True)
        for mode in ("boundary-pre-continue", "boundary-pre-stop",
                     "boundary-post-continue", "boundary-post-stop", "boundary-post-stop-lost",
                     "boundary-post-abort", "successful", "successful-missing", "successful-scripts", "successful-scripts-missing",
                     "successful-start-event", "successful-start-cache",
                     "activity-script-lost-reply", "activity-script-send-failed",
                     "activity-capture-lost-reply", "activity-capture-send-failed",
                     "normal", "empty", "output-lost", "output-error", "partial", "partial-missing",
                     "failed", "prepare-lost", "finish-lost", "capture", "capture-restart",
                     "capture-old", "capture-uncertain", "capture-release", "capture-cleanup", "capture-observer",
                     "capture-shutdown", "capture-cancel-upgrade",
                     "capture-finish-lost", "capture-no-scripts",
                     "capture-missing", "capture-no-scripts-missing"):
            run(str(Path(args.driver).resolve()), cert, key, root, mode)
            print(f"{mode}: passed")


if __name__ == "__main__":
    main()
