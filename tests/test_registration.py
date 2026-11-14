"""Independent Linux CLI registration/token lifecycle regression tests."""
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

from test_probe import check, wire
from pstream_peer import value
from pstream_peer import Reader


class Nas:
    def __init__(self, cert, key, port=0):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", port))
        self.listener.listen()
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.stopped = threading.Event()
        self.errors, self.requests = [], []
        self.clients = []
        self.connections = 0
        self.alive = 0
        self.allow_client_disconnect = False
        self.allowed_driver_status = {"disable"}
        self.poll_mode = "pending"
        self.events = []
        self.done_mode = "normal"
        self.before_done = lambda ids: None
        self.before_pull = lambda: None
        self.before_tasks = lambda: None
        self.before_auth = lambda: None
        self.before_portal = lambda: None
        self.bandwidth_response = {"backup_bandwidth": 1024}
        self.task_result_response = {}
        self.initial_result_response = {}
        self.initial_result_pending = False
        self.task_result_queries = []
        self.initial_result_queries = []
        self.before_node_result = lambda message: None
        self.node_results = []
        self.node_result_mode = "normal"
        self.admin_mode = "normal"
        self.mode = "normal"
        self.timezone = 3600
        self.time_difference = 1000
        self.time_error = False
        self.token = "registration-test-token"
        self.ds_id = "registration-test-nas"
        self.tasks = [{"id": 7, "name": "Linux backup", "task_uuid": "task-uuid",
                       "backup_type": 3, "source_type": 1, "custom_volume": None,
                       "custom_volume_alias": ["/"], "sched_content": '{"run_hour":3}',
                       "compression": 1, "encryption": 1, "is_paused": 0,
                       "pre_script_content": "SCRIPT-SECRET", "token": "TASK-SECRET"}]
        self.jobs = [{"id": 12, "task_id": 7, "type": 0, "status": 2,
                      "detail_status": 0,
                      "backup_task": {"task_name": "Linux backup", "total_size": 1024,
                                      "current_size": 512, "resume_info": "RESUME-SECRET"}}]
        self.discovery_mode = "normal"
        self.template = {"id": 27, "template_name": "Test Linux", "share_name": "backups",
                         "sched_content": '{"run_hour":3}', "source_type": 1,
                         "password": "MUST-NOT-PERSIST"}
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                peer, _ = self.listener.accept()
            except socket.timeout:
                continue
            client = threading.Thread(target=self.handle, args=(peer,), daemon=True)
            self.clients.append(client)
            client.start()

    def handle(self, peer):
        self.connections += 1
        try:
            with peer:
                peer.settimeout(30 if self.alive else 5)
                upgrade = value(peer)
                check(set(upgrade) == {"action", "agent"} and
                      upgrade["action"] == "encrypt_channel", "secret in plaintext")
                peer.sendall(wire({}))
                with self.context.wrap_socket(peer, server_side=True) as secured:
                    while not self.stopped.is_set():
                        self.handle_request(secured)
                        if not self.alive:
                            return
        except (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError,
                ssl.SSLZeroReturnError, EOFError) as exc:
            if not self.allow_client_disconnect:
                self.errors.append(exc)
        except Exception as exc:
            self.errors.append(exc)

    def handle_request(self, secured):
        if self.alive:
            peer = secured
            nas = self
            class PersistentReply:
                recv = peer.recv
                def sendall(self, data):
                    reply = value(Reader(data))
                    reply['alive'] = nas.alive
                    peer.sendall(wire(reply))
            secured = PersistentReply()
        message = value(secured)
        self.requests.append(message)
        action = message["action"]
        check(message["agent"]["version"]["build"] == "5059", "wrong wire version")
        if action == "query_server_info":
            secured.sendall(wire({"ds_id": self.ds_id}))
            return
        if action == "auth" and "password" in message:
            secured.sendall(wire({
                "token": self.token, "auth_type": 1,
                "temp_device": {"backup_type": 2, "password": "MUST-NOT-PERSIST"},
                "task_template": self.template,
                "password": "MUST-NOT-PERSIST"}))
            return
        check(message["token"] == self.token and message["ds_id"] == self.ds_id,
              "incorrect saved identity/token")
        if action == "auth_admin":
            check(set(message) == {"action", "agent", "token", "ds_id", "username", "password", "otp"},
                  "unexpected admin request fields")
            check(message["username"] == "test-admin" and message["password"] == "admin-password-837",
                  "incorrect admin credentials")
            if self.admin_mode == "reject":
                reply = {"error": {"code": 4096}}
            elif self.admin_mode == "otp" and message["otp"] != "654321":
                reply = {"error": {"code": 4101}}
            else:
                reply = {}
            secured.sendall(wire(reply))
            return
        check("password" not in message and "otp" not in message,
              "credentials in token operation")
        if action == "pull_event":
            self.before_pull()
            check(set(message) == {"action", "agent", "token", "ds_id", "event_list"},
                  "unexpected event pull fields")
            held = message["event_list"]
            secured.sendall(wire({"event_list": [
                event for event in self.events if event["id"] not in held]}))
            return
        if action == "done_event":
            ids = message["done_events"]
            self.before_done(ids)
            self.events = [event for event in self.events if event["id"] not in ids]
            if self.done_mode == "lost_once":
                self.done_mode = "normal"
                return
            secured.sendall(wire({}))
            return
        if action == "act_client_result":
            check(set(message) - {"node_list"} == {"action", "agent", "token", "ds_id",
                                                   "event_id", "error_code"},
                  "unexpected node-list response fields")
            self.before_node_result(message)
            self.node_results.append(message)
            if self.node_result_mode == "lost_once":
                self.node_result_mode = "normal"
                return
            secured.sendall(wire({}))
            return
        if action == "get_backup_bandwidth":
            check(set(message) == {"action", "agent", "token", "ds_id"},
                  "unexpected bandwidth request fields")
            secured.sendall(wire(self.bandwidth_response))
            return
        if action == "get_running_task_result":
            check(set(message) <= {"action", "agent", "token", "ds_id", "result_id"},
                  "unexpected task-result request fields")
            if self.initial_result_pending:
                check("result_id" not in message, "initial result invented running history")
                self.initial_result_queries.append(message)
                reply = self.initial_result_response
                self.initial_result_pending = "error" in reply
            else:
                self.task_result_queries.append(message)
                reply = self.task_result_response
            secured.sendall(wire(reply))
            return
        if action in ("get_task", "get_running_task"):
            check(set(message) == {"action", "agent", "token", "ds_id"},
                  "unexpected task request fields")
            if self.discovery_mode == "reject":
                reply = {"error": {"code": 4106}}
            elif action == "get_task":
                self.before_tasks()
                reply = {"task_list": self.tasks} if self.tasks else {}
            else:
                reply = {"running_task_list": self.jobs}
            secured.sendall(wire(reply))
            return
        if action == "unlink_connection":
            check(set(message) == {"action", "agent", "token", "ds_id"},
                  "unexpected unlink request fields")
            if self.mode == "unlink-lost":
                return
            secured.sendall(wire({"error": {"code": 4106}} if
                                self.mode == "unlink-reject" else {}))
            return
        if action == "long_poll":
            check(message["timeout"] == 400 and message["last_event_id"] >= 0,
                  "invalid long poll cursor")
            if self.poll_mode == "stall":
                self.stopped.wait(15)
                return
            if self.poll_mode == "disconnect":
                return
            if self.poll_mode == "events":
                while not self.stopped.is_set() and not any(
                        event['id'] > message['last_event_id'] for event in self.events):
                    self.stopped.wait(.05)
                if self.stopped.is_set():
                    return
                secured.sendall(wire({'has_event': 1}))
                return
            secured.sendall(wire({"has_event": int(self.poll_mode == "pending")}))
            return
        if action == "get_timezone":
            check(set(message) == {"action", "agent", "token", "ds_id"},
                  "unexpected timezone fields")
            secured.sendall(wire({"error": {"code": 8193, "message": "denied"}} if self.time_error else
                                {"timezone": str(self.timezone),
                                 "epoch": str(int(time.time()) + self.time_difference)}))
            return
        if action == "get_portal_link":
            self.before_portal()
            check(message["address"] == "127.0.0.1", "wrong portal address")
            secured.sendall(wire({"url": "https://fixture.invalid/recovery"}))
            return
        check(message["driver_status"] in self.allowed_driver_status and "drvier_status" not in message,
              "driver status typo or false capability")
        if action in ("auth", "confirm_auth"):
            check(message["time_zone"] == self.timezone % (1 << 64),
                  "timezone not sign-extended")
        if action == "confirm_auth":
            check(message["template_id"] == (self.template or {}).get("id", 0),
                  "template selection mismatch")
            check(message["backup_type"] == 2 and message["kernel_version"],
                  "device metadata absent")
            check(message["connect_type"] in ("backup", "restore"), "wrong mode")
            if self.mode == "lost":
                return
            if self.mode == "reject":
                secured.sendall(wire({"error": {"code": 4106}}))
            else:
                secured.sendall(wire({}))
        elif action == "auth":
            self.before_auth()
            # init=1 identifies a fresh process; an already
            # authenticated service reconnects with init=0.
            check(message["init"] in (0, 1) and message["device_uuid"] and
                  message["username"] == "test-user", "wrong reconnect fields")
            if self.mode == "reject-token":
                secured.sendall(wire({"error": {"code": 4106}}))
            elif self.mode == "missing-token":
                secured.sendall(wire({"ds_id": self.ds_id}))
            elif self.mode == "wrong-response-id":
                secured.sendall(wire({"token": self.token, "ds_id": "unexpected-nas"}))
            else:
                self.initial_result_pending = True
                self.token += "-rotated"
                reply = {"token": self.token, "ds_id": self.ds_id}
                if self.mode == "auth-type":
                    reply["auth_type"] = 1
                secured.sendall(wire(reply))
        elif action == "heart_beat":
            secured.sendall(wire({}))
        else:
            raise AssertionError(f"unexpected action {action}")

    def close(self):
        self.stopped.set()
        self.worker.join(6)
        self.listener.close()
        for client in self.clients:
            client.join(6)
        check(not self.worker.is_alive() and not self.errors, f"mock errors: {self.errors}")


def main():
    from test_login import terminal
    parser = argparse.ArgumentParser()
    parser.add_argument("executable")
    parser.add_argument("openssl")
    parser.add_argument("restore_driver")
    args = parser.parse_args()
    executable = str(Path(args.executable).resolve())
    with tempfile.TemporaryDirectory(prefix="opensabba-registration-") as directory:
        root = Path(directory)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
                        "-days", "1", "-keyout", str(key), "-out", str(cert),
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"],
                       check=True, capture_output=True)
        env = dict(os.environ, XDG_CONFIG_HOME=str(root / "config"), TZ="CET-1")
        nas = Nas(cert, key)
        session = root / "config" / "opensabba" / "session.pstream"

        def cli(*arguments, expected=0):
            if arguments and arguments[0] == "--logout":
                arguments += ("--quiet", "--username", "test-admin", "--password", "admin-password-837")
            result = subprocess.run([executable, *arguments], env=env, capture_output=True,
                                    text=True, timeout=10)
            check(result.returncode == expected, f"{arguments}: {result.stdout} {result.stderr}")
            check(nas.token not in result.stdout + result.stderr, "token leaked")
            return result

        def login(approval="", expected=0):
            code, output = terminal([executable, "--connect", "--address", "127.0.0.1", "--username", "test-user",
                                     "--port", str(nas.port), "--ca-file", str(cert)], env, approval=approval)
            check(code == expected, output)
            if session.exists():
                check(b"MUST-NOT-PERSIST" not in session.read_bytes(), "extra auth fields persisted")
            return output

        try:
            for approval in ("n", "NO", "invalid\nn"):
                count = len(nas.requests)
                output = login(approval)
                requests = nas.requests[count:]
                check("Cancel login" in output and not session.exists(), "cancel retained connection")
                check(sum(r["action"] == "unlink_connection" for r in requests) == 1 and
                      not any(r["action"] == "confirm_auth" for r in requests), "cancel did not unlink temporary auth")
                if approval.startswith("invalid"):
                    check("Enter [y/n](default: y):" in output, "invalid answer did not reprompt")
            for mode in ("unlink-lost", "unlink-reject"):
                nas.mode = mode
                login("n")
                check(not session.exists(), "failed temporary unlink retained connection")
            nas.mode = "normal"
            count = len(nas.requests)
            login("__interrupt__", expected=-2)
            check(value(Reader(session.read_bytes()))["registration_state"] == "pending" and
                  not any(r["action"] in ("confirm_auth", "unlink_connection") for r in nas.requests[count:]),
                  "Ctrl-C submitted a confirmation or cancellation")
            output = login("__eof__")
            check("Test Linux" in output and value(Reader(session.read_bytes()))["registration_state"] == "confirmed",
                  "EOF did not choose official agent default yes")
            output = login("YES")
            check("Confirm authentication? [y/n](default: y):" in output, "missing official agent prompt")
            count = len(nas.requests)
            cli("registration", "show", expected=1)
            cli("registration", "confirm", "--yes", expected=1)
            cli("--connect", "--yes", expected=1)
            check(len(nas.requests) == count, "removed surface contacted NAS")
            result = cli("--connect", "--quiet", "--address", "127.0.0.1", "--username", "test-user",
                         "--password", "test-password-742", "--port", str(nas.port), "--ca-file", str(cert))
            check(not result.stdout and value(Reader(session.read_bytes()))["registration_state"] == "confirmed",
                  "quiet connect did not confirm without prompting")
            cli("reconnect")
            check(nas.token.encode() in session.read_bytes(), "rotated token not persisted")
            time_state = session.parent / "server-time.pstream"
            saved_time = value(Reader(time_state.read_bytes()))
            check(saved_time["server_timezone"] == "3600" and
                  998 <= int(saved_time["server_timediff"]) <= 1002 and
                  int(saved_time["server_timeoffset"]) == int(saved_time["server_timediff"]) + 3600,
                  "timezone or epoch correction not persisted")
            retained_time = time_state.read_bytes()
            modified = time_state.stat().st_mtime_ns
            nas.tasks[0]["last_backup_success_time"] = 5000
            nas.jobs[0].update(create_time=6000, start_time=6001)
            display = json.loads(cli("--status", "--online", "--json").stdout)
            check(display["task_list"][0]["last_backup_success_time"] ==
                  5000 - int(saved_time["server_timediff"]),
                  "new CLI process did not load the persisted correction")
            check(display["running_task_list"][0]["create_time"] == 6000 and
                  display["running_task_list"][0]["start_time"] == 6001,
                  "running-job timestamps received an unsupported official agent conversion")
            nas.time_error = True
            check("get timezone failed (8193: 'denied')" in cli("reconnect").stderr,
                  "timezone rejection did not retain official agent error details")
            check(time_state.read_bytes() == retained_time and time_state.stat().st_mtime_ns == modified,
                  "failed refresh changed persisted time")
            nas.time_error = False
            nas.time_difference = 0
            cli("reconnect")
            check(value(Reader(time_state.read_bytes())) ==
                  {"server_timezone": "3600", "server_timediff": "0", "server_timeoffset": "3600"},
                  "nearby clock was not normalized to zero")
            modified = time_state.stat().st_mtime_ns
            cli("reconnect")
            check(time_state.stat().st_mtime_ns == modified, "unchanged server time was rewritten")
            before = session.read_bytes()
            result = json.loads(cli("tasks", "--json").stdout)
            check(result["task_list"][0]["custom_volume"] == [], "null volumes not normalized")
            check("SECRET" not in json.dumps(result), "sensitive task fields exposed")
            result = json.loads(cli("--status", "--online", "--json").stdout)
            check(result["running_task_list"][0]["backup_task"]["current_size"] == 512,
                  "job progress missing")
            check("SECRET" not in json.dumps(result), "sensitive job fields exposed")
            output = cli("--status", "--online").stdout
            check("Linux backup" in output and "NAS-reported current jobs: 1" in output,
                  "live summary missing")
            count = len(nas.requests)
            cli("--status", "--json", expected=1)
            cli("tasks", "--online", expected=1)
            check(len(nas.requests) == count, "invalid arguments contacted NAS")
            saved_tasks, saved_jobs = nas.tasks, nas.jobs
            nas.tasks, nas.jobs = [], []
            check(json.loads(cli("--status", "--online", "--json").stdout) ==
                  {"task_list": [], "running_task_list": []}, "empty task handling")
            nas.tasks = "invalid"
            cli("tasks", expected=1)
            nas.tasks = [{"id": 7, "name": "bad", "custom_volume": [9]}]
            cli("tasks", expected=1)
            nas.tasks = [{"id": 7, "name": "bad", "compression": "enabled"}]
            cli("tasks", expected=1)
            nas.tasks, nas.jobs = saved_tasks, "invalid"
            cli("--status", "--online", expected=1)
            nas.jobs = saved_jobs
            nas.discovery_mode = "reject"
            check("4106" in cli("tasks", expected=1).stderr, "server error missing")
            nas.discovery_mode = "normal"
            nas.ds_id += "-changed"
            count = len(nas.requests)
            cli("tasks", expected=1)
            check(all(r["action"] == "query_server_info" for r in nas.requests[count:]),
                  "task credentials sent to different NAS")
            nas.ds_id = nas.ds_id.removesuffix("-changed")
            check(session.read_bytes() == before, "read-only discovery mutated saved state")
            cli("heartbeat")
            before = session.read_bytes()
            nas.mode = "reject-token"
            cli("reconnect", expected=1)
            check(session.read_bytes() == before, "rejected reconnect changed session")
            for mode in ("missing-token", "wrong-response-id"):
                nas.mode = mode
                cli("reconnect", expected=1)
                check(session.read_bytes() == before, "invalid reconnect changed session")
            nas.mode = "auth-type"
            cli("reconnect")
            check(nas.token.encode() in session.read_bytes(),
                  "non-5 auth_type prevented valid token rotation")
            nas.mode = "normal"
            nas.ds_id = "different-nas"
            count = len(nas.requests)
            cli("reconnect", expected=1)
            check(len(nas.requests) == count + 1 and nas.requests[-1]["action"] == "query_server_info",
                  "token sent to changed NAS")
            nas.ds_id = "registration-test-nas"
            before = session.read_bytes()
            retained_time = time_state.read_bytes()
            for mode in ("unlink-reject", "unlink-lost"):
                nas.mode = mode
                cli("--logout")
                check(not session.exists(), "official agent logout retained credentials after failed unlink")
                session.write_bytes(before)
                session.chmod(0o600)
                time_state.write_bytes(retained_time)
            nas.mode = "normal"
            nas.ds_id = "different-nas"
            count = len(nas.requests)
            cli("--logout", expected=1)
            check(all(r["action"] == "query_server_info" for r in nas.requests[count:]),
                  "unlink sent credentials to another NAS")
            check(session.read_bytes() == before, "identity mismatch erased credentials")
            nas.ds_id = "registration-test-nas"
            pending = session.parent / "service-machine-pending.pstream"
            pending.write_bytes(wire({}))
            pending.chmod(0o600)
            count = len(nas.requests)
            result = cli("--logout", expected=1)
            check("saved record missing task_owner" in result.stderr, result.stderr)
            check("task_owner" not in value(Reader(session.read_bytes())),
                  "connection invented a task assignment")
            check(session.read_bytes() == before and not any(
                  req["action"] == "unlink_connection" for req in nas.requests[count:]),
                  "invalid pending capture logout erased recovery credentials")
            pending.unlink()
            retained = {p.name: p.read_bytes() for p in session.parent.iterdir()
                        if p not in (session, time_state) and p.is_file()}
            result = cli("--logout")
            check(not result.stdout and not session.exists(),
                  "successful unlink did not remove local token")
            check(all((session.parent / name).read_bytes() == data for name, data in retained.items()),
                  "logout changed retained identity or state")
            check(value(Reader(time_state.read_bytes())) ==
                  {"server_timezone": "3600", "server_timediff": "0", "server_timeoffset": ""},
                  "logout did not reset clock correction and retain timezone")
            count = len(nas.requests)
            cli("--logout", expected=5)
            check(len(nas.requests) == count, "logout without a session contacted NAS")
            print("registration, metadata filtering, token rotation, and identity checks: passed")

            nas.mode = "lost"
            login(expected=3)
            check(value(Reader(session.read_bytes()))["registration_state"] == "uncertain", "lost reply marked successful")
            count = len(nas.requests)
            cli("registration", "confirm", "--yes", expected=1)
            check(len(nas.requests) == count, "removed command retried uncertain confirmation")
            nas.mode = "normal"
            cli("reconnect")
            check(value(Reader(session.read_bytes()))["registration_state"] == "confirmed", "token auth did not reconcile")
            nas.mode = "reject"
            login(expected=3)
            check(value(Reader(session.read_bytes()))["registration_state"] == "uncertain", "rejection assumed rollback")
            print("interrupted/rejected confirmation and reconciliation: passed")

            nas.mode = "normal"
            nas.template = None
            env["TZ"] = "EST5"
            nas.timezone = -18000
            login()
            # official agent abb-cli does not expose a restore connect-type flag; the
            # recovery protocol remains covered by a typed, test-only driver.
            result = subprocess.run([args.restore_driver,str(session)],capture_output=True,text=True,timeout=10)
            check(result.returncode == 0,result.stderr)
            check(nas.requests[-1]["connect_type"] == "restore", "typed recovery selection was lost")
            cli("reconnect")
            auth_request = next(r for r in reversed(nas.requests) if r["action"] == "auth")
            check(auth_request["time_zone"] == (1 << 64) - 18000, "negative timezone")
            print("default template, typed restore connection, and negative timezone: passed")
        finally:
            nas.close()


if __name__ == "__main__":
    main()
