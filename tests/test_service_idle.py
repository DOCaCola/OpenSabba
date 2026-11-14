"""official agent idle request budget, real native event worker, and service Linux gate."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

from test_probe import check
from test_registration import Nas


def wait_for(test, detail, timeout=12):
    until = time.monotonic() + timeout
    while not test():
        check(time.monotonic() < until, detail)
        time.sleep(.05)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    parser.add_argument('openssl')
    parser.add_argument('--service', action='store_true')
    parser.add_argument('--alive', type=int, default=30)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='opensabba-idle-') as directory:
        root = Path(directory)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, capture_output=True)
        nas = Nas(cert, key)
        nas.tasks, nas.jobs = [], []
        nas.alive = args.alive
        nas.poll_mode = 'events'
        nas.allow_client_disconnect = True
        process = None
        def count(action):
            return sum(r['action'] == action for r in nas.requests)
        try:
            executable = str(Path(args.executable).resolve())
            if args.service:
                from test_login import terminal
                env = dict(os.environ, XDG_CONFIG_HOME=str(root/'config'), TZ='CET-1')
                code, output = terminal([executable, '--connect', '--address', '127.0.0.1',
                                         '--username', 'test-user', '--port', str(nas.port),
                                         '--ca-file', str(cert)], env)
                check(code == 0, output)
                nas.requests.clear()
                nas.connections = 0
                process = subprocess.Popen([executable, 'service', 'run'], env=env,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            else:
                process = subprocess.Popen([executable, str(nas.port), str(cert), '18' if args.alive == 1 else '13'],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            beats = 3 if args.alive == 1 else 2
            wait_for(lambda: count('heart_beat') >= beats, 'heartbeat blocked behind idle poll', timeout=16)
            check(process.poll() is None, 'service exited during idle interval')
            for action, expected in [('get_task', 1), ('get_running_task', 1),
                                     ('get_running_task_result', 1), ('pull_event', 0),
                                     ('long_poll', 1), ('auth', 1), ('query_server_info', 1)]:
                check(count(action) == expected, f'idle budget: {action}={count(action)}, expected {expected}')
            expected_connections = len(nas.requests) if not args.alive else 3 if args.alive == 1 else 2
            check(nas.connections == expected_connections,
                  f'idle opened {nas.connections} connections, expected {expected_connections}')
            nas.tasks = [dict(id=7, name='updated', task_uuid='task-uuid', backup_type=3,
                              source_type=1, is_paused=1,
                              pre_post_script_setting=dict(pre_script_enabled=1, post_script_enabled=0,
                                  pre_script_extension='.sh', pre_script_error=0),
                              pre_script_content=b'PRIVATE-SCRIPT-BODY')]
            nas.jobs = [dict(id=12, task_id=7, type=0, status=2, detail_status=0)]
            nas.events = [dict(id=1, action='change_task'), dict(id=2, action='update_running_task'),
                          dict(id=3, action='future_action')]
            wait_for(lambda: count('done_event') >= 1 and count('long_poll') == 2,
                     'events did not refresh/dispatch and resume long poll')
            expected = dict(get_task=3, get_running_task=2, pull_event=1, long_poll=2)
            time.sleep(1.2)
            for action, total in expected.items():
                check(count(action) == total, f'event budget: {action}={count(action)}, expected {total}')
            check([r['last_event_id'] for r in nas.requests if r['action'] == 'long_poll'] == [0, 3],
                  'delivered unsupported event repeatedly woke long poll')
            expected_connections = len(nas.requests) if not args.alive else expected_connections
            check(nas.connections == expected_connections, 'event handlers violated channel lease')
            if args.service:
                process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=10)
            check(process.returncode == 0, f'worker failed: {out} {err}')
            if not args.service:
                check('tasks=1 runs=1 dispatches=1' in out, f'fresh snapshots not dispatched: {out}')
            process = None
        finally:
            if process is not None:
                process.kill()
                process.communicate(timeout=3)
            nas.close()
    print('official agent idle request and channel budget passed')


if __name__ == '__main__':
    main()
