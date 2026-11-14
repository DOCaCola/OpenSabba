"""Production private store, heartbeat and fixed-image CLI against an independent NAS."""
import argparse
import fcntl
import io
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time

from test_image import receive_blocks
from test_login import value
from test_probe import check, wire
from test_snapshot import filesystem, disk, check_spec
from test_service import wait_for


class Reader(io.BytesIO):
    recv = io.BytesIO.read


class Server:
    def __init__(self, root, cert, key, image, mode):
        self.root, self.image = root, image
        self.create = mode.startswith('create-')
        self.mode = mode.removeprefix('create-')
        self.run_id = 27
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(cert, key)
        self.stopped = threading.Event()
        self.release = threading.Event()
        self.errors, self.requests, self.clients = [], [], []
        self.worker = threading.Thread(target=self.run)
        self.worker.start()

    def record(self):
        path = self.root / 'opensabba' / 'backup-job.pstream'
        check(stat.S_IMODE(path.stat().st_mode) == 0o600, 'public journal')
        record = value(Reader(path.read_bytes()))
        check(b'test-token' not in path.read_bytes() and 'token' not in record, 'journal secret')
        return record

    def run(self):
        while not self.stopped.is_set():
            try:
                peer, _ = self.listener.accept()
            except socket.timeout:
                continue
            client = threading.Thread(target=self.handle, args=(peer,))
            self.clients.append(client)
            client.start()

    def handle(self, peer):
        try:
            with peer:
                peer.settimeout(15)
                check(value(peer)['action'] == 'encrypt_channel', 'plaintext request')
                peer.sendall(wire({}))
                with self.tls.wrap_socket(peer, server_side=True) as tls:
                    request = value(tls)
                    action = request['action']
                    operation = request.get('subaction', action)
                    self.requests.append(operation)
                    if action == 'query_server_info':
                        tls.sendall(wire({'ds_id': 'test-nas'}))
                        return
                    check(request['token'] == 'test-token' and request['ds_id'] == 'test-nas', 'auth')
                    if action == 'get_running_task_result':
                        tls.sendall(wire({'error': {'code': 8193}}))
                        return
                    if action == 'auth_admin':
                        tls.sendall(wire({}))
                        return
                    if action == 'get_task':
                        task = {'id': 2, 'name': 'Disposable test',
                                'compression': 1 if self.mode == 'compressed' else 0, 'encryption': 1}
                        if self.mode.startswith('app-aware'):
                            task['app_aware_bkp'] = 1
                        if self.mode == 'bad-compression':
                            task['compression'] = 2
                        if self.mode == 'missing-compression':
                            del task['compression']
                        tls.sendall(wire({'task_list': [] if self.mode == 'unassigned' else
                                         [task]}))
                    elif action == 'get_running_task':
                        jobs = [{'id': self.run_id, 'type': 0, 'task_id': 99 if self.mode == 'wrong-task' else 2}]
                        tls.sendall(wire({'running_task_list': [] if self.create and self.mode != 'already-running'
                                         else jobs}))
                    elif action == 'heart_beat':
                        tls.sendall(wire({'error': {'code': 8193}} if self.mode == 'heartbeat-failed' and
                                         self.requests.count('heart_beat') >= 2 else {}))
                    else:
                        record = self.record()
                        check(record['schema'] == 2 and
                              record['compression'] == ('lz4' if self.mode == 'compressed' else 'none'),
                              'compression policy was not saved before mutation')
                        phase = {'update_backup_task': 'prepare', 'add_backup_task': 'prepare', 'update_device_spec': 'metadata',
                                 'upload_block': 'upload', 'check_complete': 'finish'}[operation]
                        check(record['phase'] == phase and record['task_id'] == 2 and
                              record['running_task_id'] == (0 if operation == 'add_backup_task' else self.run_id),
                              'request preceded durable intent')
                        if operation in ('update_backup_task', 'add_backup_task'):
                            if self.create:
                                check(operation == 'add_backup_task' and record['create_task_id'] == 2,
                                      'creation intent missing')
                                check(set(request) == {'action', 'subaction', 'agent', 'token', 'ds_id',
                                                       'task_id', 'trigger_type', 'base_version_id',
                                                       'is_cbt', 'is_cache', 'check_point_backup'}, 'creation keys')
                                check(request['task_id'] == 2 and request['trigger_type'] == 1 and
                                      all(request[k] == 0 for k in ('base_version_id', 'is_cbt',
                                                                   'is_cache', 'check_point_backup')), 'creation flags')
                            if self.mode == 'lost-prepare':
                                return
                            reply = {'running_task_id': self.run_id, 'version_id': 9,
                                     'result_id': 14,
                                     'data_format': 1 if self.create or self.mode == 'app-aware' else 2}
                            if self.mode == 'zero-run':
                                reply['running_task_id'] = 0
                            if self.mode == 'missing-version':
                                del reply['version_id']
                            tls.sendall(wire(reply))
                        elif operation == 'update_device_spec':
                            check(record['snapshot_info'] == request['snapshot_info'], 'metadata journal mismatch')
                            check(request['enable_app_aware'] ==
                                  int(self.mode.startswith('app-aware') and record['data_format'] != 2),
                                  'task application-aware metadata differs from official agent policy')
                            check(record.get('app_aware_bkp', 0) == int(self.mode.startswith('app-aware')),
                                  'task application-aware policy was not retained')
                            check_spec(json.loads(request['snapshot_info']), self.image.stat().st_size)
                            if self.mode == 'lost-metadata':
                                return
                            if self.mode in ('cancel', 'slow', 'heartbeat-failed'):
                                self.release.wait(12)
                                if self.mode in ('cancel', 'heartbeat-failed'):
                                    return
                            tls.sendall(wire({}))
                        elif operation == 'upload_block':
                            tls.sendall(wire({'success': 1}))
                            receive_blocks(tls, self.image, self.root / 'restored.img',
                                           compressed=self.mode == 'compressed')
                            if self.mode == 'lost-close':
                                return
                            tls.sendall(wire({'close': 1}))
                        else:
                            if self.mode == 'lost-finish':
                                return
                            check(request['status'] == 'complete', 'wrong requested outcome')
                            tls.sendall(wire({'status': 'partial' if self.mode == 'partial' else 'complete'}))
        except Exception as error:
            self.errors.append(error)

    def close(self):
        self.release.set()
        self.stopped.set()
        self.worker.join(3)
        for client in self.clients:
            client.join(15)
        self.listener.close()
        check(not any(t.is_alive() for t in self.clients) and not self.errors, str(self.errors))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    parser.add_argument('openssl')
    args = parser.parse_args()
    exe = str(Path(args.executable).resolve())
    with tempfile.TemporaryDirectory(prefix='opensabba-cli-job-') as directory:
        root = Path(directory)
        image = root / 'fixed.img'
        image.write_bytes(disk(filesystem(root)))
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, capture_output=True)
        for case in ('success', 'partial', 'lost-prepare', 'lost-metadata', 'lost-close',
                     'lost-finish', 'unassigned', 'wrong-task', 'locked', 'cancel', 'slow', 'heartbeat-failed',
                     'create-success', 'create-lost-prepare', 'create-lost-metadata', 'create-lost-finish',
                     'create-already-running', 'create-zero-run', 'create-missing-version',
                     'compressed', 'create-compressed', 'bad-compression', 'missing-compression',
                     'app-aware', 'app-aware-format2', 'create-app-aware'):
            mode = case.removeprefix('create-')
            config = root / case
            private = config / 'opensabba'
            private.mkdir(parents=True, mode=0o700)
            server = Server(config, cert, key, image, case)
            env = dict(os.environ, XDG_CONFIG_HOME=str(config))
            session = dict(format=2, host='127.0.0.1', port=server.port, ca_file=str(cert),
                           username='test-user', device_uuid='test-device', token='test-token',
                           ds_id='test-nas', registration_state='confirmed')
            session_path = private / 'session.pstream'
            session_path.write_bytes(wire(session))
            session_path.chmod(0o600)

            def cli(*arguments):
                if arguments and arguments[0] == "--logout":
                    arguments += ("--quiet", "--username", "test-admin", "--password", "admin-password-837")
                return subprocess.run([exe, *arguments], env=env, capture_output=True, text=True, timeout=25)

            command = ['backup', 'image', str(image), '--task', '2', '--running-task',
                       '27', '--sector-size', '512', '--image-name', 'test-image']
            if server.create:
                del command[5:7]
            lock = None
            process = None
            try:
                check(json.loads(cli('backup', 'status', '--json').stdout) is None, 'initial status')
                if mode == 'locked':
                    lock = os.open(private, os.O_RDONLY)
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if mode in ('cancel', 'slow', 'heartbeat-failed'):
                    process = subprocess.Popen([exe, *command], env=env, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, text=True)
                    wait_for(lambda: 'update_device_spec' in server.requests, 'no metadata request')
                    # Atomic readers must work while the writer owns the store.
                    check(json.loads(cli('backup', 'status', '--json').stdout)['phase'] == 'metadata',
                          'concurrent private status failed')
                    if mode == 'cancel':
                        process.send_signal(signal.SIGTERM)
                    else:
                        wait_for(lambda: server.requests.count('heart_beat') >= 2, 'heartbeat stopped during backup')
                    server.release.set()
                    out, err = process.communicate(timeout=20)
                    result = subprocess.CompletedProcess(command, process.returncode, out, err)
                    process = None
                else:
                    result = cli(*command)
                check((result.returncode == 0) == (mode in ('success', 'slow', 'compressed',
                      'app-aware', 'app-aware-format2')), result.stdout + result.stderr)
                check('test-token' not in result.stdout + result.stderr, 'output secret')
                if mode in ('unassigned', 'wrong-task', 'locked', 'already-running', 'bad-compression', 'missing-compression'):
                    check(not (private / 'backup-job.pstream').exists(), 'invalid selection created a job')
                    check('update_backup_task' not in server.requests and 'add_backup_task' not in server.requests,
                          'invalid selection mutated NAS')
                    continue
                record = server.record()
                expected = {'success': 'complete', 'compressed': 'complete', 'slow': 'complete', 'partial': 'partial',
                            'app-aware': 'complete', 'app-aware-format2': 'complete',
                            'lost-prepare': 'prepare', 'lost-metadata': 'metadata', 'cancel': 'metadata',
                            'heartbeat-failed': 'metadata',
                            'zero-run': 'prepare', 'missing-version': 'prepare',
                            'lost-close': 'upload', 'lost-finish': 'finish'}[mode]
                check(record['phase'] == expected, f'{mode}: unexpected saved phase')
                summary = json.loads(cli('backup', 'status', '--json').stdout)
                check('snapshot_info' not in summary and 'token' not in summary and
                      summary['terminal'] == int(mode in ('success', 'slow', 'partial', 'compressed',
                          'app-aware', 'app-aware-format2')), 'unsafe status')
                count = len(server.requests)
                if not summary['terminal']:
                    saved_session = session_path.read_bytes()
                    # Manual image jobs belong to the noninstalled lab tool.
                    # Their explicit reconciliation must preserve uncertainty;
                    # official agent logout has no blanket unfinished-job refusal.
                    reconcile = cli('backup', 'reconcile')
                    check(reconcile.returncode != 0, 'failed NAS result lookup was accepted')
                    check(session_path.read_bytes() == saved_session and not any(
                          op == 'unlink_connection' for op in server.requests[count:]),
                          'failed reconciliation erased credentials or unlinked NAS')
                count = len(server.requests)
                if not server.create or mode not in ('success', 'compressed', 'app-aware'):
                    check(cli(*command).returncode != 0 and len(server.requests) == count, 'job replayed')
                if mode in ('success', 'compressed', 'app-aware'):
                    # A later distinct run preserves the previous terminal record.
                    server.run_id = 28
                    if not server.create:
                        command[command.index('--running-task')+1] = '28'
                    check(cli(*command).returncode == 0, 'next job rejected')
                    check((private / 'backup-job-27-14.pstream').exists(), 'terminal history lost')
                    restored = config / 'restored.img'
                    part = config / 'restored.ext4'
                    with restored.open('rb') as stream:
                        stream.seek(1024*1024)
                        part.write_bytes(stream.read(16*1024*1024))
                    subprocess.run(['/usr/sbin/e2fsck', '-fn', str(part)], check=True, capture_output=True)
                    restored_text = subprocess.run(['/usr/sbin/debugfs', '-R', 'cat /restore-check.txt', str(part)],
                                                   check=True, capture_output=True, text=True).stdout
                    check(restored_text == 'OpenSabba independent restore specimen\n', 'restored file content')
                    journal = private / 'backup-job.pstream'
                    original = journal.read_bytes()
                    # The production reader uses backup limits, not the 128 KiB session limit.
                    larger = server.record()
                    larger['snapshot_info'] = b' ' * (256*1024)
                    journal.write_bytes(wire(larger))
                    check(cli('backup', 'status').returncode == 0, 'backup record limited to session size')
                    journal.write_bytes(original)
                    journal.chmod(0o644)
                    check(cli('backup', 'status').returncode != 0, 'public journal accepted')
                    journal.chmod(0o600)
                    journal.write_bytes(original[:-1])
                    check(cli('backup', 'status').returncode != 0, 'truncated journal accepted')
                    journal.unlink()
                    journal.symlink_to(session_path)
                    check(cli('backup', 'status').returncode != 0, 'journal symlink followed')
                    journal.unlink()
                    journal.write_bytes(original)
                    journal.chmod(0o600)
                if mode == 'heartbeat-failed':
                    check('8193' in result.stderr, 'heartbeat failure hidden behind cancellation')
                # A changed account cannot inspect another account's journal.
                session['username'] = 'foreign-user'
                session_path.write_bytes(wire(session))
                check(cli('backup', 'status').returncode != 0, 'foreign journal accepted')
            finally:
                if process:
                    process.kill()
                    process.communicate()
                if lock is not None:
                    os.close(lock)
                server.close()
    print('23 production CLI lifecycle/store cases and independent ext4 reconstruction passed')


if __name__ == '__main__':
    main()
