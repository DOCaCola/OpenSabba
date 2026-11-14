"""Persistent service lifecycle against an independent concurrent TLS NAS mock."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time

from test_probe import check, wire
from test_login import terminal
from test_registration import Nas


def wait_for(predicate, message, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.05)
    raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    parser.add_argument('openssl')
    args = parser.parse_args()
    executable = str(Path(args.executable).resolve())
    with tempfile.TemporaryDirectory(prefix='opensabba-service-') as directory:
        root = Path(directory)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, capture_output=True)
        env = dict(os.environ, XDG_CONFIG_HOME=str(root / 'config'), TZ='CET-1')
        nas = Nas(cert, key)
        nas.allow_client_disconnect = True
        process = None
        def cli(*args):
            if args and args[0] == "--logout":
                args += ("--quiet", "--username", "test-admin", "--password", "admin-password-837")
            return subprocess.run([executable, *args], env=env, capture_output=True,
                                  text=True, timeout=10)
        def start():
            return subprocess.Popen([executable, 'service', 'run'], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def count(action):
            return sum(r['action'] == action for r in nas.requests)
        try:
            code, output = terminal([executable, '--connect', '--address', '127.0.0.1', '--username', 'test-user',
                                     '--port', str(nas.port), '--ca-file', str(cert)], env)
            check(code == 0, output)
            requests = len(nas.requests)
            ready = cli('service', 'check')
            check(ready.returncode == 0 and json.loads(ready.stdout)['state'] == 'resume-required',
                  f'local machine preflight failed: {ready.stdout} {ready.stderr}')
            check(len(nas.requests) == requests, 'preflight contacted NAS')
            # Removed source formats never enter the machine consumer or NAS.
            source_path = root/'config/opensabba/service-source.pstream'
            for old_format in (1, 2):
                source_path.write_bytes(wire(dict(format=old_format)))
                source_path.chmod(0o600)
                rejected = cli('service', 'check')
                check(rejected.returncode != 0 and 'invalid format' in rejected.stderr,
                      'obsolete source format was accepted')
                check(len(nas.requests) == requests, 'obsolete source format contacted NAS')
                source_path.unlink()
            nas.poll_mode = 'stall'
            nas.initial_result_response = dict(backup_result=dict(
                last_success_time=7200, last_backup_status='complete'))
            nas.tasks[0]['last_backup_success_time'] = 1234
            process = start()
            wait_for(lambda: count('long_poll') == 1, 'service did not poll')
            check(count('get_timezone') == 1, 'service token authentication omitted routine time refresh')
            def idle_status(epoch, detail):
                status = cli('--status', '--skip-portal')
                expected = time.strftime('%Y-%m-%d %H:%M',
                                         time.gmtime(epoch - nas.time_difference + 3600))
                check(status.returncode == 0 and not status.stderr and
                      f'Last backup time: {expected} \t\t Next backup time: ' in status.stdout and
                      f'Service Status: Idle - {detail}\n\nRecovery portal:  - \n\n' in status.stdout,
                      f'fresh connection lost NAS result summary: {status.stdout} {status.stderr}')
            idle_status(7200, 'Completed')
            actions = [r['action'] for r in nas.requests if r['action'] not in (
                'query_server_info', 'heart_beat', 'get_timezone')]
            initial = actions.index('get_running_task_result')
            check('result_id' not in next(r for r in nas.requests if
                  r['action'] == 'get_running_task_result') and
                  actions[initial:initial+3] == ['get_running_task_result', 'get_task', 'get_running_task'],
                  'local initialization query order differs from official agent')
            check(cli('tasks').returncode == 0, 'service blocks task reads')
            check(cli('--connect', '-q', '-a', '127.0.0.1', '-u', 'test-user', '-p', 'test').returncode != 0, 'connect changed active service credentials')
            check(cli('service', 'run').returncode == 1, 'duplicate service accepted')
            wait_for(lambda: count('heart_beat') >= 2, 'heartbeat blocked behind long poll')
            # A NAS-only outage may hold token authentication for its full
            # transport timeout. Local status must not acquire that lock.
            auth_entered, auth_release = threading.Event(), threading.Event()
            def hold_auth():
                auth_entered.set()
                check(auth_release.wait(8), 'test did not release reconnect')
            nas.before_auth = hold_auth
            check(cli('--reload', '-q').returncode == 0, 'status reconnect setup failed')
            try:
                wait_for(auth_entered.is_set, 'reconnect did not reach held NAS request')
                before = time.monotonic()
                check(cli('--status', '--skip-portal').returncode == 0,
                      'local status unavailable during blocked NAS reconnect')
                check(time.monotonic() - before < 2, 'status waited for NAS authentication')
            finally:
                nas.before_auth = lambda: None
                auth_release.set()
            wait_for(lambda: count('long_poll') >= 2, 'held reconnect did not finish')
            # Default status also returns successfully when portal I/O times
            # out; its 10-second official agent budget fits inside the IPC wait.
            portal_entered, portal_release = threading.Event(), threading.Event()
            def hold_portal():
                portal_entered.set()
                portal_release.wait(20)
            nas.before_portal = hold_portal
            try:
                portal = subprocess.Popen([executable, '--status'], env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                wait_for(portal_entered.is_set, 'status did not request portal')
                out, err = portal.communicate(timeout=14)
                check(portal.returncode == 0 and not err and
                      'Retrieved service status successfully' in out,
                      f'portal outage became local IPC failure: {out} {err}')
            finally:
                nas.before_portal = lambda: None
                portal_release.set()
            old_auth, old_tasks, old_time = count('auth'), count('get_task'), count('get_timezone')
            old_results = count('get_running_task_result')
            nas.initial_result_response = dict(backup_result=dict(
                last_success_time=10800, last_backup_status='partial_success'))
            reload = cli('--reload', '-q')
            check(reload.returncode == 0 and not reload.stdout,
                  f'CLI reload failed: {reload.stdout} {reload.stderr}')
            wait_for(lambda: count('auth') > old_auth and count('get_task') > old_tasks,
                     'reload did not reconnect and refresh tasks')
            check(count('get_timezone') > old_time, 'reload omitted token-runner time refresh')
            check(process.poll() is None, 'reload terminated service')
            check(cli('--connect', '-q', '-a', '127.0.0.1', '-u', 'test-user', '-p', 'test').returncode != 0, 'reload released credential ownership')
            wait_for(lambda: count('long_poll') >= 2, 'reload did not resume observation')
            idle_status(10800, 'Partially complete')
            check(count('get_running_task_result') == old_results + 1,
                  'reconnect omitted or repeated local last-result initialization')
            actions = [r['action'] for r in nas.requests if r['action'] not in (
                'query_server_info', 'heart_beat', 'get_timezone', 'get_connection_info')]
            start_at = len(actions) - 1 - actions[::-1].index('get_running_task_result')
            check(actions[start_at:start_at+3] == ['get_running_task_result', 'get_task', 'get_running_task'],
                  'reconnect initialization query order differs from official agent')
            old_auth = count('auth')
            # Unknown packets cannot request a reload or terminate the listener.
            st = (root/'config/opensabba').stat()
            address = f'\0opensabba-{os.getuid()}-{st.st_dev}-{st.st_ino}'
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
                peer.settimeout(2)
                peer.connect(address)
                peer.sendall(b'reload-invalid')
                check(peer.recv(32) == b'', 'malformed reload was acknowledged')
            # official agent's local producer must be dispatched without turning an
            # observer or a disabled NAS task into a cache-capable provider.
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
                peer.settimeout(10)
                peer.connect(address)
                peer.sendall(b'generate_event:' + wire(dict(
                    task_id=2, task_uuid='test-task', event_type='cache_write')))
                check(peer.recv(1024) == b'error:no assigned backup cache policy',
                      'local cache event bypassed provider ownership')
            check(not (root/'config/opensabba/service-cache-event-task-2.pstream').exists(),
                  'rejected manual cache request created a durable event')
            other = root/'other-config/opensabba'
            other.mkdir(parents=True, mode=0o700)
            wrong = subprocess.run([executable, '--reload'],
                                   env=dict(env, XDG_CONFIG_HOME=str(other.parent)),
                                   capture_output=True, text=True, timeout=3)
            check(wrong.returncode == 5, 'reload crossed session boundaries')
            check(count('auth') == old_auth, 'rejected control request reloaded service')
            check(cli('--reload').returncode == 0, 'top-level reload failed')
            wait_for(lambda: count('auth') > old_auth, 'CLI alias reload was lost')
            old_auth = count('auth')
            check(cli('--reload', '-q').returncode == 0, 'second edit failed')
            wait_for(lambda: count('auth') > old_auth, 'second edit was lost')
            before = time.monotonic()
            process.send_signal(signal.SIGHUP)
            out, err = process.communicate(timeout=3)
            check(process.returncode == 0 and 'Service stopped.' in out and 'Service reload:' in out,
                  f'unclean shutdown: {out} {err}')
            check(time.monotonic() - before < 3, 'poll cancellation too slow')
            check(nas.token not in out + err, 'service leaked token')
            process = None
            stopped_reload = cli('service', 'reload')
            check(stopped_reload.returncode == 1 and 'usage:' in stopped_reload.stderr,
                  'reload claimed success without a running service')
            # A rejected local initialization handler stays independent of
            # task observation and is never turned into a NAS event receipt.
            nas.initial_result_response = dict(error=dict(code=8193))
            old_polls = count('long_poll')
            process = start()
            wait_for(lambda: count('long_poll') > old_polls,
                     'rejected initial result stopped task observation')
            check(process.poll() is None and not nas.task_result_queries,
                  'local initialization used the event-result path')
            nas.initial_result_response = dict(backup_result=dict(
                last_success_time=14400, last_backup_status='complete'))
            old_polls = count('long_poll')
            check(cli('--reload', '-q').returncode == 0, 'initial result retry reload failed')
            wait_for(lambda: count('long_poll') > old_polls, 'initial result did not refresh after reconnect')
            idle_status(14400, 'Completed')
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=3)
            check(process.returncode == 0 and 'Initial task-result lookup failed:' in err,
                  'failed initialization was not reported independently')
            process = None
            nas.poll_mode = 'disconnect'
            old_auth = count('auth')
            process = start()
            wait_for(lambda: count('auth') >= old_auth + 2, 'disconnect did not reconnect')
            process.send_signal(signal.SIGINT)
            out, err = process.communicate(timeout=3)
            check(process.returncode == 0 and 'reconnecting in' in err, 'retry path failed')
            process = None
            # The packaged unit stops only its main process with SIGQUIT.
            nas.poll_mode = 'stall'
            old_polls = count('long_poll')
            process = start()
            wait_for(lambda: count('long_poll') > old_polls, 'QUIT fixture did not start polling')
            process.send_signal(signal.SIGQUIT)
            out, err = process.communicate(timeout=3)
            check(process.returncode == 0 and 'Service stopped.' in out,
                  f'QUIT did not stop workers cleanly: {out} {err}')
            process = None
            nas.mode = 'reject-token'
            old_auth = count('auth')
            process = start()
            out, err = process.communicate(timeout=5)
            check(process.returncode == 1 and '4106' in err, 'auth error not fatal')
            check(count('auth') == old_auth + 1, 'rejected token was retried')
            check(not any(r['action'] == 'done_event' for r in nas.requests), 'empty inbox acknowledged')
            check(cli('--logout').returncode == 0, 'service failed to release session lock')
            process = None
            nas.mode = 'normal'
            nas.poll_mode = 'stall'
            code, output = terminal([executable, '--connect', '--address', '127.0.0.1', '--username', 'test-user',
                                     '--port', str(nas.port), '--ca-file', str(cert)], env)
            check(code == 0, output)
            # Logout leaves a valid empty offset; password login retains it.
            # A failed first refresh must keep the service alive and postpone
            # calendar initialization rather than treating the empty text as UTC.
            nas.tasks[0]['sched_content'] = json.dumps(dict(
                repeat_type='Weekly', schedule_setting_type=1, run_hour=23,
                run_min=59, run_weekday=[0,1,2,3,4,5,6], repeat_hour=0,
                enable_backup_window=False))
            nas.time_error = True
            old_polls = count('long_poll')
            process = start()
            wait_for(lambda: count('long_poll') > old_polls, 'unset-offset service did not poll')
            status = cli('--status', '--skip-portal')
            check(status.returncode == 0 and 'Next backup time:  - ' in status.stdout,
                  'unset NAS offset invented a scheduled time: ' + status.stdout + status.stderr)
            # Let the independent one-second scheduler observe the unset state.
            time.sleep(1.1)
            check(process.poll() is None, 'unset NAS offset terminated schedule worker')
            nas.time_error = False
            old_polls = count('long_poll')
            check(cli('--reload', '-q').returncode == 0, 'clock refresh reload failed')
            wait_for(lambda: count('long_poll') > old_polls, 'clock refresh did not resume observation')
            status = cli('--status', '--skip-portal')
            check(status.returncode == 0 and 'Next backup time:  - ' not in status.stdout,
                  'successful NAS refresh did not initialize calendar: ' + status.stdout + status.stderr)
            result = cli('--logout')
            out, err = process.communicate(timeout=3)
            check(result.returncode == 0 and not result.stdout,
                  result.stdout + result.stderr)
            check(process.returncode == 0 and 'Service stopped.' in out, out + err)
            check(count('unlink_connection') == 2, 'logout did not notify NAS exactly once')
            check(cli('--status').returncode == 2, 'logout retained session')
            check(cli('--logout').returncode == 5, 'missing connection did not return official agent code 5')
            process = None
            print('service: concurrent heartbeats, read access, ownership, cancellation, retry, fatal auth passed')
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()
            nas.close()


if __name__ == '__main__':
    main()
