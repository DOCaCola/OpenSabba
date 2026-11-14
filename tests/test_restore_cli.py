"""Independent TLS range server exercising the real Linux CLI and private store."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import stat
import subprocess
import tempfile

from test_backup_cli import Server as BaseServer, Reader
from test_login import value
from test_probe import check, wire
from test_service import wait_for


class Server(BaseServer):
    def record(self):
        path = self.root / 'opensabba' / 'restore-job.pstream'
        check(stat.S_IMODE(path.stat().st_mode) == 0o600, 'public restore journal')
        raw = path.read_bytes()
        check(b'test-token' not in raw and b'server-secret' not in raw, 'secret in journal')
        return value(Reader(raw))

    def handle(self, peer):
        try:
            with peer:
                peer.settimeout(15)
                check(value(peer)['action'] == 'encrypt_channel', 'plaintext auth')
                peer.sendall(wire({}))
                with self.tls.wrap_socket(peer, server_side=True) as tls:
                    request = value(tls)
                    action = request['action']
                    self.requests.append(request.get('subaction', action))
                    if action == 'query_server_info':
                        tls.sendall(wire({'ds_id': 'foreign' if self.mode == 'foreign-nas' else 'test-nas'}))
                        return
                    check(request['token'] == 'test-token' and request['ds_id'] == 'test-nas', 'bad auth')
                    if action == 'auth_admin':
                        tls.sendall(wire({}))
                        return
                    if action == 'list_device_task':
                        task = {'task_id': 2, 'device_info': {
                            'device_id': 7, 'device_uuid': 'foreign' if self.mode == 'foreign-device' else 'test-device',
                            'agent_token': 'server-secret', 'login_password': 'server-secret'}}
                        tls.sendall(wire({'tasks': [] if self.mode == 'no-task' else [task], 'total': 1}))
                        return
                    if action == 'get_running_task':
                        job = dict(id=self.run_id, task_id=2, device_id=7, version_id=1, type=2,
                                   result_id=getattr(self, 'result_id', 112),
                                   status=getattr(self, 'run_status', 1), detail_status=getattr(self, 'detail_status', 0))
                        if self.mode == 'missing-result':
                            del job['result_id']
                        if self.mode == 'wrong-run-type':
                            job['type'] = 1
                        tls.sendall(wire({'running_task_list': [job]}))
                        return
                    if action == 'get_running_task_result':
                        if getattr(self, 'logout_recovery', False):
                            tls.sendall(wire({'error': {'code': 8193}}))
                            return
                        check(request['result_id'] == 112, 'wrong restore result lookup')
                        tls.sendall(wire({'running_task_result': dict(task_id=2, result_id=112,
                            job_action='restore', status=getattr(self, 'result_status',
                                'complete' if self.mode == 'lost-finish' else 'incomplete'))}))
                        return
                    check(action == 'image_restore', 'unexpected action')
                    record = self.record()
                    sub = request.get('subaction')
                    if sub is None:
                        check(record['phase'] == 'create' and record['running_task_id'] == 0, 'no create intent')
                        check(request['task_id'] == 2 and request['device_id'] == 7 and
                              request['version_id'] == 1 and request['restore_mode'] == 1 and
                              request['device_uuid'] == 'test-device', 'wrong restore selection')
                        if self.mode == 'lost-create':
                            return
                        tls.sendall(wire({'running_task_id': 0 if self.mode == 'zero-run' else self.run_id}))
                    elif sub == 'read_image_requests':
                        check(record['phase'] == 'download' and request['running_task_id'] == self.run_id,
                              'no download intent')
                        check(record['result_id'] == 112, 'result identity not persisted before download')
                        tls.sendall(wire({'success': 1}))
                        at = getattr(self, 'range_start', 0)
                        while at < len(self.image):
                            req = value(tls)
                            count = min(1024*1024, len(self.image)-at)
                            check(req == {'image_name': getattr(self, 'image_name', 'test-image'),
                                          'offset': at, 'length': count},
                                  'unbounded or incorrect range')
                            self.requests.append('range')
                            if self.mode == 'resume-drop' and at >= 5*1024*1024:
                                return
                            if self.mode == 'checkpoint-failed' and at == 3*1024*1024:
                                (self.root/'opensabba').chmod(0o500)
                                tls.sendall(wire({'buffer': self.image[at:at+count]}))
                                return
                            if self.mode == 'cancel':
                                self.release.wait(10)
                                return
                            if self.mode == 'lost-range':
                                return
                            block = self.image[at:at+count]
                            if self.mode == 'short':
                                block = block[:-1]
                            if self.mode == 'long':
                                block += b'\0'
                            if self.mode == 'corrupt':
                                block = bytes([block[0] ^ 1]) + block[1:]
                            if self.mode == 'early-close':
                                tls.sendall(wire({'close': 1, 'status': 'complete'}))
                                return
                            if getattr(self, 'change_during_range', '') == 'cancel':
                                self.run_status = 3
                            if getattr(self, 'change_during_range', '') == 'result':
                                self.result_id = 113
                            tls.sendall(wire({'buffer': block, 'running_task_status': 3 if self.mode == 'nas-cancel' else (2 if getattr(self, 'change_during_range', '') else getattr(self, 'run_status', 1))}))
                            if getattr(self, 'change_during_range', ''):
                                check(tls.recv(1) == b'', 'changed job accepted during resume')
                                return
                            if self.mode in ('short', 'long', 'nas-cancel'):
                                return
                            at += count
                        if self.mode == 'corrupt':
                            check(tls.recv(1) == b'', 'corruption reported as success')
                            return
                        progress = value(tls)
                        check(progress == {'progress': {'current_size': len(self.image), 'total_size': len(self.image)}},
                              'wrong progress')
                        check(self.record()['phase'] == 'verified', 'progress before verification')
                        check(value(tls) == {'close': 1}, 'missing channel close')
                        if self.mode == 'lost-close':
                            return
                        tls.sendall(wire({'close': 1, 'status': 'error' if self.mode == 'close-error' else 'running'}))
                    elif sub == 'check_complete':
                        check(record['phase'] == 'finish' and request['status'] == 'complete', 'no finish intent')
                        check(Path(record['destination']).read_bytes() == self.image, 'finish before file verification')
                        if self.mode == 'lost-finish':
                            return
                        tls.sendall(wire({'status': 'cancel' if self.mode == 'finish-cancel' else 'complete'}))
                    else:
                        raise AssertionError('unknown restore subaction')
        except Exception as error:
            self.errors.append(repr(error))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    parser.add_argument('openssl')
    args = parser.parse_args()
    exe = str(Path(args.executable).resolve())
    image = bytes(range(256)) * (8192+2)  # Exercises multiple ranges and a short final range.
    with tempfile.TemporaryDirectory(prefix='opensabba-restore-') as temporary:
        root = Path(temporary)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, capture_output=True)
        cases = ('success', 'lost-create', 'zero-run', 'lost-range', 'short', 'long', 'corrupt',
                 'early-close', 'nas-cancel', 'lost-close', 'close-error', 'lost-finish', 'finish-cancel',
                 'foreign-nas', 'foreign-device', 'no-task', 'existing', 'symlink', 'cancel', 'foreign-journal',
                 'missing-result', 'wrong-run-type')
        for mode in cases:
            config = root/mode
            private = config/'opensabba'
            private.mkdir(parents=True, mode=0o700)
            server = Server(config, cert, key, image, mode)
            env = dict(os.environ, XDG_CONFIG_HOME=str(config))
            session = dict(format=2, host='127.0.0.1', port=server.port, ca_file=str(cert),
                           username='test-user', device_uuid='test-device', token='test-token',
                           ds_id='test-nas', registration_state='confirmed')
            backup = dict(schema=1, ds_id='test-nas', username='test-user', device_uuid='test-device',
                          phase='complete', running_task_id=64, task_id=2, version_id=1, result_id=112,
                          data_format=1, image_name='test-image', image_size=len(image),
                          image_sha256=hashlib.sha256(image).hexdigest(),
                          snapshot_info=b'{}', requested_outcome='complete')
            if mode == 'foreign-journal':
                backup['device_uuid'] = 'foreign'
            for name, record in [('session', session), ('backup-job', backup)]:
                path = private/(name+'.pstream')
                path.write_bytes(wire(record))
                path.chmod(0o600)
            original = (private/'backup-job.pstream').read_bytes()
            destination = config/'restored.img'
            if mode == 'existing':
                destination.write_bytes(b'keep this')
            if mode == 'symlink':
                destination.symlink_to(private/'session.pstream')
            def cli(*arguments):
                if arguments and arguments[0] == "--logout":
                    arguments += ("--quiet", "--username", "test-admin", "--password", "admin-password-837")
                return subprocess.run([exe, *arguments], env=env, capture_output=True, text=True, timeout=20)
            process = None
            try:
                check(json.loads(cli('restore', 'status', '--json').stdout) is None, 'initial status')
                command = ['restore', 'image', str(destination)]
                if mode == 'cancel':
                    process = subprocess.Popen([exe, *command], env=env, text=True,
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    wait_for(lambda: 'range' in server.requests, 'no download')
                    check(json.loads(cli('restore', 'status', '--json').stdout)['phase'] == 'download',
                          'concurrent journal reader failed')
                    process.send_signal(signal.SIGTERM)
                    out, err = process.communicate(timeout=10)
                    result = subprocess.CompletedProcess(command, process.returncode, out, err)
                    process = None
                else:
                    result = cli(*command)
                check((result.returncode == 0) == (mode == 'success'), result.stdout+result.stderr)
                check('server-secret' not in result.stdout+result.stderr and
                      'test-token' not in result.stdout+result.stderr, 'leaked credentials')
                check((private/'backup-job.pstream').read_bytes() == original, 'backup journal modified')
                if mode in ('foreign-nas', 'foreign-device', 'no-task', 'existing', 'symlink', 'foreign-journal'):
                    check('image_restore' not in server.requests, 'invalid selection created restore')
                    check(not (private/'restore-job.pstream').exists(), 'invalid job saved')
                    if mode == 'existing':
                        check(destination.read_bytes() == b'keep this', 'existing file overwritten')
                    if mode == 'symlink':
                        check(destination.is_symlink() and value(Reader(destination.read_bytes())) == session,
                              'symlink target overwritten')
                    continue
                expected = {'success': 'complete', 'lost-create': 'create', 'zero-run': 'create',
                            'lost-close': 'verified', 'close-error': 'verified', 'lost-finish': 'finish',
                            'missing-result': 'created', 'wrong-run-type': 'created',
                            'finish-cancel': 'cancel'}.get(mode, 'download')
                summary = json.loads(cli('restore', 'status', '--json').stdout)
                check(summary['phase'] == expected, f'{mode}: wrong journal phase {summary}')
                check(stat.S_IMODE(destination.stat().st_mode) == 0o600, 'public restore output')
                if mode not in ('success', 'finish-cancel'):
                    count = len(server.requests)
                    saved_session = (private/'session.pstream').read_bytes()
                    server.logout_recovery = True
                    # A manual image restore has no official agent CLI counterpart.
                    # Exercise its explicit lab reconciliation rather than an
                    # invented official agent logout prohibition.
                    reconcile = cli('restore', 'reconcile')
                    check(reconcile.returncode != 0, 'failed NAS restore result lookup was accepted')
                    check((private/'session.pstream').read_bytes() == saved_session and
                          not any(op == 'unlink_connection' for op in server.requests[count:]),
                          'failed reconciliation erased credentials or unlinked NAS')
                    server.logout_recovery = False
                    count = len(server.requests)
                    check(cli(*command).returncode != 0 and len(server.requests) == count, 'uncertain job replayed')
                if mode == 'success':
                    check(destination.read_bytes() == image, 'restored bytes differ')
                    server.run_id += 1
                    check(cli('restore', 'image', str(config/'second.img')).returncode == 0, 'second restore failed')
                    check((private/'restore-job-27.pstream').exists(), 'history lost')
                if mode == 'lost-finish':
                    check(cli('restore', 'reconcile').returncode == 0, 'lost finish reply not reconciled')
                    summary = json.loads(cli('restore', 'status', '--json').stdout)
                    check(summary['phase'] == 'complete' and summary['verified'] == 1 and
                          summary['result_id'] == 112, 'reconciled restore lost evidence')
            finally:
                if process:
                    process.kill()
                    process.communicate()
                server.close()

        named_cases = ('secondary-full', 'direct-machine', 'lv-incremental', 'primary-explicit',
                       'unknown-name', 'path-name', 'duplicate-option', 'duplicate-journal-name',
                       'bad-secondary-size', 'bad-secondary-digest', 'bad-primary-binding',
                       'wrong-content', 'incomplete-backup', 'single-image-unknown')
        primary = b'P' * (3*1024*1024)
        secondary = b'S' * (4*1024*1024)
        for mode in named_cases:
            config = root/mode
            private = config/'opensabba'
            private.mkdir(parents=True, mode=0o700)
            selected = 'VG=LV.img' if mode == 'lv-incremental' else (
                'test-image' if mode == 'primary-explicit' else 'physical-second.img')
            expected_image = primary if mode == 'primary-explicit' else secondary
            server = Server(config, cert, key, expected_image,
                            'corrupt' if mode == 'wrong-content' else 'success')
            server.image_name = selected
            env = dict(os.environ, XDG_CONFIG_HOME=str(config))
            session = dict(format=2, host='127.0.0.1', port=server.port, ca_file=str(cert),
                           username='test-user', device_uuid='test-device', token='test-token',
                           ds_id='test-nas', registration_state='confirmed')
            secondary_name = 'VG=LV.img' if mode == 'lv-incremental' else 'physical-second.img'
            backup = dict(schema=5 if mode == 'lv-incremental' else 4,
                          ds_id='test-nas', username='test-user', device_uuid='test-device',
                          phase='complete', running_task_id=64, task_id=2, version_id=1,
                          result_id=112, data_format=1, compression='none',
                          image_name='test-image', image_size=len(primary),
                          image_sha256=hashlib.sha256(primary).hexdigest(),
                          snapshot_info=b'{}', requested_outcome='complete',
                          images=[dict(name='test-image', size=len(primary),
                                       sha256=hashlib.sha256(primary).hexdigest()),
                                  dict(name=secondary_name, size=len(secondary),
                                       sha256=hashlib.sha256(secondary).hexdigest())])
            if mode == 'direct-machine':
                backup['direct_intervals'] = 1
                backup['image_sha256'] = ''
                for item in backup['images']:
                    item['sha256'] = ''
                backup['source_capture'] = dict(schema=5, id='c'*32,
                    boot_id='00000000-0000-0000-0000-000000000001', phase='ready', failure='',
                    failure_disposition='', logs=[], plan={}, reservation={},
                    snapshot=dict(owned=1), artifact=dict(direct=1))
            if mode == 'lv-incremental':
                backup['incremental'] = dict(base_version_id=1, base_result_id=110,
                                             base_running_task_id=62, base_snapshot_id='a'*32)
                for item in backup['images']:
                    item.update(base_sha256='b'*64,
                                ranges=[dict(offset=0, length=item['size'], changed=1)])
            if mode == 'duplicate-journal-name':
                backup['images'][1]['name'] = 'test-image'
            if mode == 'bad-secondary-size':
                backup['images'][1]['size'] += 1
            if mode == 'bad-secondary-digest':
                backup['images'][1]['sha256'] = 'Z'*64
            if mode == 'bad-primary-binding':
                backup['image_sha256'] = '0'*64
            if mode == 'incomplete-backup':
                backup['phase'] = 'error'
            if mode == 'single-image-unknown':
                backup['schema'] = 1
                del backup['compression'], backup['images']
            for name, record in [('session', session), ('backup-job', backup)]:
                path = private/(name+'.pstream')
                path.write_bytes(wire(record))
                path.chmod(0o600)
            original = (private/'backup-job.pstream').read_bytes()
            destination = config/'restored.img'
            try:
                name_arg = ('missing.img' if mode in ('unknown-name', 'single-image-unknown') else
                            'subdir/image' if mode == 'path-name' else selected)
                command = ['restore', 'image', str(destination), '--image-name', name_arg]
                if mode == 'duplicate-option':
                    command += ['--image-name', selected]
                result = subprocess.run([exe, *command], env=env, capture_output=True,
                                        text=True, timeout=20)
                good = mode in ('secondary-full', 'direct-machine', 'lv-incremental', 'primary-explicit')
                check((result.returncode == 0) == good, f'{mode}: {result.stdout}{result.stderr}')
                check((private/'backup-job.pstream').read_bytes() == original,
                      'named restore modified backup journal')
                if good:
                    check(destination.read_bytes() == expected_image, 'wrong named image bytes')
                    summary = json.loads(subprocess.run(
                        [exe, 'restore', 'status', '--json'], env=env, capture_output=True,
                        text=True, check=True).stdout)
                    check(summary['phase'] == 'complete' and summary['image_name'] == selected and
                          summary['image_size'] == len(expected_image) and
                          summary['image_sha256'] == ('' if mode == 'direct-machine' else hashlib.sha256(expected_image).hexdigest()),
                          'named restore identity or digest differs from backup')
                elif mode == 'wrong-content':
                    check(destination.exists() and
                          value(Reader((private/'restore-job.pstream').read_bytes()))['image_name'] == selected,
                          'failed named digest did not retain exact selected identity')
                    check('check_complete' not in server.requests, 'bad digest completed NAS restore')
                else:
                    check(not destination.exists() and not (private/'restore-job.pstream').exists(),
                          'bad named selection created output or restore journal')
                    check(not server.requests, 'bad named selection contacted NAS')
            finally:
                server.close()
                check(not server.errors, f'{mode}: {server.errors}')
        print(f'{len(cases) + len(named_cases)} restore CLI cases passed')


if __name__ == '__main__':
    main()
