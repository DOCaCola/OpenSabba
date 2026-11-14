"""Durable event handling through the real service and an independent TLS server."""
import argparse
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile

from test_probe import check, wire
from test_login import terminal, value
from test_registration import Nas
from test_service import wait_for


class Reader(io.BytesIO):
    recv = io.BytesIO.read


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    parser.add_argument('openssl')
    args = parser.parse_args()
    executable = str(Path(args.executable).resolve())
    with tempfile.TemporaryDirectory(prefix='opensabba-events-') as directory:
        root = Path(directory)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, capture_output=True)
        env = dict(os.environ, XDG_CONFIG_HOME=str(root / 'config'), TZ='CET-1')
        journal = root / 'config' / 'opensabba' / 'events.pstream'
        nas = Nas(cert, key)
        nas.allow_client_disconnect = True
        process = None
        def cli(*args):
            return subprocess.run([executable, *args], env=env, capture_output=True,
                                  text=True, timeout=10)
        def start():
            return subprocess.Popen([executable, 'service', 'run'], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def requests(action):
            if action == 'get_running_task_result':
                return nas.task_result_queries
            return [r for r in nas.requests if r['action'] == action]
        def read_journal():
            return value(Reader(journal.read_bytes()))
        try:
            code, output = terminal([executable, '--connect', '--address', '127.0.0.1', '--username', 'test-user',
                                     '--port', str(nas.port), '--ca-file', str(cert)], env)
            check(code == 0, output)
            nas.events = [
                {'id': 1, 'action': 'change_task', 'task_id': 7},
                {'id': 2, 'action': 'act_client', 'webapi_task': {'secret': 'PRIVATE-PAYLOAD'}},
                {'id': 3, 'action': 'update_running_task'},
                {'id': 4, 'action': 'future_action', 'opaque': ['preserve', 19]},
            ]
            def before_done(ids):
                check(bool(ids) and set(ids) <= {1, 3}, f'unsupported event completed: {ids}')
                saved = read_journal()
                ready = [r for r in saved['receipts'] if r['state'] == 'ack_pending']
                check([r['payload']['id'] for r in ready] == ids, 'ack preceded durable completion')
                if 3 in ids:
                    jobs = saved['running_task_snapshot']
                    check(len(jobs) == 1 and jobs[0]['id'] == 12 and jobs[0]['task_id'] == 7,
                          'running-task ACK preceded its durable NAS refresh')
                check(saved['task_snapshot'][0]['id'] == 7, 'task snapshot not persisted')
            nas.before_done = before_done
            nas.done_mode = 'lost_once'
            process = start()
            wait_for(lambda: len(requests('done_event')) >= 2 and len(requests('long_poll')) >= 1 and
                     [r['payload']['id'] for r in read_journal()['receipts']] == [2, 4],
                     'lost task ACK or supported running-task ACK missing')
            acknowledgments = [r['done_events'] for r in requests('done_event')]
            check(acknowledgments in ([[1], [1], [3]], [[1], [1, 3]], [[1, 3], [1, 3]]),
                  f'wrong task/running-task receipt or lost-ACK replay: {acknowledgments}')
            acknowledged_count = len(acknowledgments)
            process.kill()  # Retained unsupported receipts must survive an unclean process exit.
            out, err = process.communicate(timeout=3)
            process = None
            saved = read_journal()
            check([r['payload']['id'] for r in saved['receipts']] == [2, 4], 'wrong retained events')
            check(saved['receipts'][0]['payload']['webapi_task']['secret'] == 'PRIVATE-PAYLOAD',
                  'opaque payload lost')
            check(stat.S_IMODE(journal.stat().st_mode) == 0o600, 'inbox permissions')
            result = cli('events', '--json')
            check(result.returncode == 0 and len(json.loads(result.stdout)['events']) == 2, 'event listing')
            check('PRIVATE-PAYLOAD' not in out + err + result.stdout, 'payload logged')
            count = len(requests('pull_event'))
            process = start()
            wait_for(lambda: len(requests('pull_event')) > count, 'restart failed')
            check(requests('pull_event')[-1]['event_list'] == [2, 4], 'retained IDs not excluded')
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=3)
            check(process.returncode == 0, f'restart shutdown: {out} {err}')
            process = None
            check(len(requests('done_event')) == acknowledged_count, 'unsupported events acknowledged after restart')

            # Reject a foreign journal before authentication or any event request.
            foreign = read_journal()
            foreign['ds_id'] = 'different-nas'
            journal.write_bytes(wire(foreign))
            count = len(nas.requests)
            result = cli('service', 'run')
            check(result.returncode == 1 and len(nas.requests) == count, 'foreign inbox used')
            journal.unlink()

            # Fail atomic rename after delivery; no acknowledgment is allowed.
            nas.events = [{'id': 5, 'action': 'change_task'}]
            def block_inbox_commit():
                # Initialization already persisted a fresh inbox. Replace it at
                # delivery so the subsequent atomic rename fails as intended.
                journal.unlink()
                journal.mkdir()
            nas.before_pull = block_inbox_commit
            result = cli('service', 'run')
            check(result.returncode == 1 and len(requests('done_event')) == acknowledged_count, 'write failure acknowledged')
            journal.rmdir()
            nas.before_pull = lambda: None
            nas.before_done = lambda ids: check(ids == [5], 'wrong recovered ID')
            process = start()
            wait_for(lambda: len(requests('done_event')) == acknowledged_count+1, 'delivery not recovered after failed write')
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=3)
            check(process.returncode == 0, f'recovery shutdown: {out} {err}')
            process = None
            for event_id, response in ((6, {"backup_bandwidth": 1024}),
                                       (7, {"backup_bandwidth": 0}), (8, {})):
                nas.events = [{"id": event_id, "action": "update_backup_bandwidth"}]
                nas.bandwidth_response = response
                def bandwidth_done(ids):
                    saved = read_journal()
                    check(ids == [event_id] and saved["format"] == 3, "wrong bandwidth ack")
                    check(saved["bandwidth_snapshot"] == response, "bandwidth result not durable")
                    check(any(r["payload"]["id"] == event_id and r["state"] == "ack_pending"
                              for r in saved["receipts"]), "bandwidth ack preceded persistence")
                nas.before_done = bandwidth_done
                nas.done_mode = "lost_once"
                before = len(requests("done_event"))
                queries = len(requests("get_backup_bandwidth"))
                process = start()
                wait_for(lambda: len(requests("done_event")) >= before+2 and
                         not read_journal()["receipts"], "bandwidth ack recovery failed")
                process.send_signal(signal.SIGTERM)
                out, err = process.communicate(timeout=3)
                check(process.returncode == 0, f'bandwidth shutdown: {out} {err}')
                check(len(requests("get_backup_bandwidth")) == queries+1,
                      "lost acknowledgment re-executed bandwidth query")
                process = None
            nas.events = [{"id": 9, "action": "update_backup_bandwidth"}]
            nas.bandwidth_response = {"backup_bandwidth": "invalid"}
            before = len(requests("done_event"))
            result = cli("service", "run")
            check(result.returncode == 1 and len(requests("done_event")) == before,
                  "invalid bandwidth acknowledged")
            check(read_journal()["receipts"][0]["state"] == "pending", "failed refresh lost receipt")
            journal.unlink()
            nas.events = [{"id": 10, "action": "act_client",
                           "webapi_task": {"subaction": "list_nodes", "event_id": 10,
                                           "node_path": "", "dir_only": 1}}]
            def before_nodes(message):
                saved = read_journal()
                check(saved["receipts"][0]["state"] == "pending" and
                      saved["receipts"][0]["node_result"]["node_list"] == message["node_list"],
                      "volume-list result was sent before durable intent")
                nodes = message["node_list"]
                check(message["event_id"] == 10 and message["error_code"] == 0 and
                      any(n["path"] == "/" and n["is_system_drive"] == 1 for n in nodes) and
                      all(set(n) == {"name", "path", "is_dir", "file_system",
                                     "is_dynamic_volume", "is_system_drive",
                                     "volume_name", "total_size", "used_size", "free_size"}
                          for n in nodes),
                      "invalid official agent mounted-volume response")
                if Path("/mnt/opensabba-lvm-selected").is_mount():
                    check(any(n["path"] == "/mnt/opensabba-lvm-selected" and
                              n["file_system"] == "ext4" and n["volume_name"] and
                              n["is_dynamic_volume"] == 0 for n in nodes),
                          "mounted LVM logical volume missing from official agent inventory")
            nas.before_node_result = before_nodes
            def done_nodes(ids):
                check(ids == [10] and len(nas.node_results) == 1 and
                      read_journal()["receipts"][0]["state"] == "ack_pending",
                      "done_event preceded the durable volume-list result")
            nas.before_done = done_nodes
            process = start()
            wait_for(lambda: len(nas.node_results) == 1 and not read_journal()["receipts"],
                     "volume-list response was not completed")
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=3)
            check(process.returncode == 0, f"volume-list shutdown: {out} {err}")
            process = None
            # Destination navigation is a child list, distinct from the empty
            # path's mounted-volume inventory. Empty/error results omit node_list.
            destination = root / "destination-tree"
            destination.mkdir()
            (destination / "nested").mkdir()
            (destination / "ordinary").write_text("file")
            (destination / "directory-link").symlink_to("nested")
            (destination / "file-link").symlink_to("ordinary")
            (destination / "dangling-link").symlink_to("missing")
            def node_event(event_id, path, dir_only):
                return {"id": event_id, "action": "act_client",
                        "webapi_task": {"subaction": "list_nodes", "event_id": event_id,
                                        "node_path": str(path), "dir_only": dir_only}}
            def run_nodes(event_id, path, dir_only, verify):
                nonlocal process
                nas.events = [node_event(event_id,path,dir_only)]
                before = len(nas.node_results)
                def before_result(message):
                    receipt = read_journal()["receipts"][0]
                    response = {key: message[key] for key in ("event_id", "error_code", "node_list")
                                if key in message}
                    check(receipt["state"] == "pending" and receipt["node_result"] == response,
                          "directory result was sent before durable intent")
                    verify(response)
                nas.before_node_result = before_result
                nas.before_done = lambda ids: check(ids == [event_id] and
                    read_journal()["receipts"][0]["state"] == "ack_pending",
                    "directory event acknowledged before durable result")
                process = start()
                wait_for(lambda: len(nas.node_results) == before+1 and not read_journal()["receipts"],
                         "directory listing was not completed")
                process.send_signal(signal.SIGTERM)
                out, err = process.communicate(timeout=3)
                check(process.returncode == 0, f"directory-list shutdown: {out} {err}")
                process = None
            def verify_children(response, include_file):
                nodes = response["node_list"]
                expected = {"nested", "directory-link", "file-link", "dangling-link"}
                if include_file:
                    expected.add("ordinary")
                check(response["error_code"] == 0 and
                      {n["name"] for n in nodes} == expected and
                      all(set(n) == {"name", "path", "is_dir"} and
                          n["path"] == str(destination) + "/" + n["name"] and
                          n["is_dir"] == int(n["name"] != "ordinary") for n in nodes),
                      "directory fields or symlink filtering differ from official agent")
            run_nodes(19,"/",1,lambda response:
                      check(response["error_code"] == 0 and response["node_list"] and
                            all(set(n) == {"name", "path", "is_dir"} and n["is_dir"] == 1 and
                                n["path"] == "/" + n["name"] for n in response["node_list"]),
                            "root directory was confused with volume inventory"))
            run_nodes(20,destination,1,lambda response: verify_children(response,False))
            run_nodes(21,destination,0,lambda response: verify_children(response,True))
            run_nodes(22,destination/"nested",1,lambda response:
                      check(response == {"event_id": 22, "error_code": 0},
                            "empty directory did not omit node_list"))
            run_nodes(23,destination/"missing",1,lambda response:
                      check(response == {"event_id": 23, "error_code": (1 << 64)-2},
                            "missing directory errno was not sign-extended"))
            # Lose the result reply, stop the service, and change the directory.
            # Recovery must replay the original list before done_event.
            nas.events = [node_event(24,destination,1)]
            before = len(nas.node_results)
            nas.node_result_mode = "lost_once"
            nas.before_done = lambda ids: check(ids == [24], "wrong directory replay ack")
            original = []
            def replay_result(message):
                response = {key: message[key] for key in ("event_id", "error_code", "node_list")}
                if not original:
                    original.append(response)
                check(response == original[0] and
                      read_journal()["receipts"][0]["node_result"] == original[0],
                      "directory reply changed across retry")
            nas.before_node_result = replay_result
            process = start()
            wait_for(lambda: len(nas.node_results) == before+1, "lost directory reply not observed")
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=3)
            process = None
            (destination/"created-after-result").mkdir()
            process = start()
            wait_for(lambda: len(nas.node_results) == before+2 and not read_journal()["receipts"],
                     "saved directory result not replayed after restart")
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=3)
            check(process.returncode == 0, f"directory replay shutdown: {out} {err}")
            process = None
            for event_id, response in ((11, {}), (12, {
                    "backup_result": {"last_success_time": 1234, "last_backup_status": "complete"},
                    "running_task_result": {"job_action": "unknown"}})):
                nas.events = [{"id": event_id, "action": "get_running_task_result",
                               "task_id": 7, "version_id": 42}]
                nas.task_result_response = response
                def done_result(ids):
                    saved = read_journal()
                    check(ids == [event_id] and saved["receipts"][0]["state"] == "ack_pending" and
                          saved["receipts"][0]["task_result"] == response,
                          "task-result acknowledgment preceded durable response")
                    check("result_id" not in requests("get_running_task_result")[-1],
                          "result ID invented without matching local history")
                nas.before_done = done_result
                nas.done_mode = "lost_once"
                before = len(requests("done_event"))
                queries = len(requests("get_running_task_result"))
                process = start()
                wait_for(lambda: len(requests("done_event")) >= before+2 and
                         not read_journal()["receipts"], "task-result receipt not completed")
                process.send_signal(signal.SIGTERM)
                out, err = process.communicate(timeout=3)
                check(process.returncode == 0, f"task-result shutdown: {out} {err}")
                check(len(requests("get_running_task_result")) == queries+1,
                      "lost acknowledgment repeated task-result query")
                process = None
            nas.events = [{"id": 13, "action": "get_running_task_result",
                           "task_id": 7, "version_id": 42}]
            nas.task_result_response = {"error": {"code": 4106}}
            before = len(requests("done_event"))
            queries = len(requests("get_running_task_result"))
            polls = len(requests("long_poll"))
            process = start()
            wait_for(lambda: len(requests("get_running_task_result")) > queries and
                     len(requests("long_poll")) > polls, "failed handler stopped observation")
            check(process.poll() is None and len(requests("done_event")) == before and
                  read_journal()["receipts"][0]["state"] == "pending",
                  "failed task-result query exited or acknowledged")
            nas.task_result_response = {}
            nas.before_done = lambda ids: check(ids == [13], "wrong retried event")
            edited = subprocess.run([executable,"--reload","-q"],env=env,capture_output=True,text=True,timeout=10)
            check(edited.returncode == 0,edited.stdout+edited.stderr)
            wait_for(lambda: not read_journal()["receipts"], "failed handler was not retried")
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=3)
            check(process.returncode == 0, f"handler retry shutdown: {out} {err}")
            process = None
            # Reproduce the live collision: a backup and several image restores
            # refer to the same source version, alongside archived backups.
            # official agent's process-local history starts empty after daemon restart.
            backup_journal = journal.parent / "backup-job.pstream"
            session = value(Reader((journal.parent / "session.pstream").read_bytes()))
            backup = dict(schema=1, ds_id=session["ds_id"], device_uuid=session["device_uuid"],
                username=session["username"], phase="upload", running_task_id=27, task_id=7,
                version_id=42, result_id=112, data_format=1, image_name="disk", image_size=512,
                image_sha256="a"*64, snapshot_info=b"{}", requested_outcome="complete")
            backup_journal.write_bytes(wire(backup))
            backup_journal.chmod(0o600)
            for name, result_id in (("backup-job-25-110.pstream", 110),
                                    ("restore-job-28.pstream", 113),
                                    ("restore-job-29.pstream", 114),
                                    ("restore-job.pstream", 115)):
                archived = dict(backup, phase="complete", result_id=result_id)
                path = journal.parent / name
                path.write_bytes(wire(archived))
                path.chmod(0o600)
            nas.events = [{"id": event_id, "action": "get_running_task_result",
                           "task_id": 7, "version_id": 42} for event_id in (14, 15)]
            nas.task_result_response = {"running_task_result": {
                "task_id": 7, "result_id": 112, "job_action": "backup", "status": "incomplete"}}
            def done_history(ids):
                saved = value(Reader(backup_journal.read_bytes()))
                check(saved["phase"] == "upload" and "result_history_retired" not in saved and
                      "resolution" not in saved, "incomplete result changed the backup outcome")
                query = requests("get_running_task_result")[-1]
                check("result_id" not in query, "archived history supplied a running result")
            nas.before_done = done_history
            before = len(requests("done_event"))
            process = start()
            wait_for(lambda: len(requests("done_event")) >= before+2 and
                     not read_journal()["receipts"], "running-result history not consumed")
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=3)
            check(process.returncode == 0, f"history shutdown: {out} {err}")
            process = None
            # Crash after saving the query, before receipt
            # completion: replay the saved reply, including its exact query ID.
            recovered = read_journal()
            event = {"id": 16, "action": "get_running_task_result", "task_id": 7, "version_id": 42}
            recovered["receipts"] = [{"payload": event, "state": "pending",
                "task_result_id": 112, "task_result": nas.task_result_response}]
            journal.write_bytes(wire(recovered))
            nas.events = [event]
            queries = len(requests("get_running_task_result"))
            nas.before_done = lambda ids: check(
                ids == [16] and len(requests("get_running_task_result")) == queries,
                "crash replay repeated a consumed result lookup")
            process = start()
            wait_for(lambda: not read_journal()["receipts"], "saved task-result reply not replayed")
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=3)
            check(process.returncode == 0, f"result replay shutdown: {out} {err}")
            process = None
            nas.events = [{"id": event_id, "action": "get_running_task_result",
                           "task_id": 7, "version_id": 43} for event_id in (17, 18)]
            nas.task_result_response = {"running_task_result": {
                "task_id": 7, "result_id": 113, "job_action": "restore", "status": "complete"}}
            def done_file_history(ids):
                check("result_id" not in requests("get_running_task_result")[-1],
                      "previous-process file restore supplied result ID")
            nas.before_done = done_file_history
            before = len(requests("done_event"))
            process = start()
            wait_for(lambda: len(requests("done_event")) >= before+2 and
                     not read_journal()["receipts"], "file restore result events not completed")
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=3)
            check(process.returncode == 0, f"file restore history shutdown: {out} {err}")
            process = None
            print('events: durable ordering, lost ack, crash/restart, private retention, identity, write failure passed')
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()
            nas.close()


if __name__ == '__main__':
    main()
