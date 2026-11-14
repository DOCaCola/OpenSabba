"""Recovery uses exact NAS identities and durable cancellation intent."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from test_backup_cli import Server as BaseServer, Reader
from test_login import value
from test_probe import check, wire


class Server(BaseServer):
    def handle(self, peer):
        try:
            with peer:
                peer.settimeout(10)
                check(value(peer)['action'] == 'encrypt_channel', 'plaintext auth')
                peer.sendall(wire({}))
                with self.tls.wrap_socket(peer, server_side=True) as tls:
                    request = value(tls)
                    action = request['action']
                    self.requests.append(action)
                    if action == 'query_server_info':
                        tls.sendall(wire({'ds_id': 'test-nas'}))
                        return
                    check(request['token'] == 'test-token', 'wrong token')
                    if action == 'get_running_task_result':
                        check(request['result_id'] == 112, 'latest result substituted')
                        result = dict(task_id=2, result_id=112, job_action=self.kind, status='incomplete')
                        if self.mode in ('complete', 'partial_success', 'failure', 'cancel'):
                            result['status'] = self.mode
                        if self.mode == 'multi-incremental-complete':
                            result['status'] = 'complete'
                        if self.mode == 'unverified-complete':
                            result['status'] = 'complete'
                        if self.mode == 'bind-running':
                            result['status'] = 'cancel'
                        if self.mode == 'wrong-result':
                            result['result_id'] = 113
                        if self.mode == 'wrong-task':
                            result['task_id'] = 3
                        if self.mode == 'wrong-action':
                            result['job_action'] = 'restore' if self.kind == 'backup' else 'backup'
                        if self.mode == 'unknown':
                            result['status'] = 'new-status'
                        tls.sendall(wire({'running_task_result': result}))
                    elif action == 'get_running_task':
                        job = dict(id=27, task_id=2, version_id=1, result_id=112, device_id=7,
                                   type=2 if self.kind == 'restore' else 0)
                        if self.mode == 'wrong-running':
                            job['version_id'] = 2
                        if self.mode == 'wrong-device':
                            job['device_id'] = 8
                        if self.mode == 'wrong-type':
                            job['type'] = 1
                        if self.mode == 'persist-failed':
                            (self.root/'opensabba').chmod(0o500)
                        if self.mode == 'bind-wrong-type':
                            job['type'] = 1
                        if self.mode == 'bind-zero':
                            job['result_id'] = 0
                        jobs = [] if self.mode in ('absent', 'bind-absent') else [job]
                        if self.mode == 'bind-duplicate':
                            jobs.append(job)
                        tls.sendall(wire({'running_task_list': jobs}))
                    elif action in ('backup', 'image_restore'):
                        check(request['subaction'] == 'check_complete' and request['status'] == 'cancel' and
                              request['running_task_id'] == 27, 'invalid cancellation')
                        if self.mode == 'multi-incremental':
                            check(request['is_cbt'] == 1, 'multi-disk incremental cancellation lost CBT flag')
                        record = value(Reader((self.root/'opensabba'/
                            ('backup-job.pstream' if action == 'backup' else 'restore-job.pstream')).read_bytes()))
                        check(record['resolution'] == {'state': 'cancel-pending', 'outcome': 'cancel'},
                              'no durable cancellation intent')
                        if self.mode == 'lost':
                            return
                        tls.sendall(wire({'status': 'complete' if self.mode == 'unexpected-complete' else 'cancel'}))
                    else:
                        raise AssertionError('unexpected operation')
        except EOFError as error:
            # The client establishes TLS, then persists intent before sending
            # the authenticated mutation. Failed persistence closes it unused.
            if self.mode != 'persist-failed':
                self.errors.append(repr(error))
        except Exception as error:
            self.errors.append(repr(error))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    parser.add_argument('openssl')
    args = parser.parse_args()
    exe = str(Path(args.executable).resolve())
    cases = [('backup', 'reconcile', mode) for mode in
             ('complete', 'partial_success', 'failure', 'cancel', 'incomplete',
              'wrong-result', 'wrong-task', 'wrong-action', 'unknown', 'unknown-run')]
    cases += [(kind, 'cancel', mode) for kind in ('backup', 'restore') for mode in
              ('success', 'lost', 'unexpected-complete', 'absent', 'wrong-running',
               'persist-failed', 'pending', 'foreign-journal', 'wrong-type')]
    cases += [('restore', 'cancel', 'wrong-device'), ('backup', 'cancel', 'complete')]
    cases += [('backup', 'cancel', 'multi-incremental'),
              ('backup', 'reconcile', 'multi-incremental-complete')]
    cases += [('restore', 'reconcile', mode) for mode in
              ('complete', 'partial_success', 'failure', 'cancel', 'incomplete', 'wrong-result',
               'wrong-task', 'wrong-action', 'unknown', 'unknown-run', 'unverified-complete',
               'bind-running', 'bind-absent', 'bind-wrong-type', 'bind-zero', 'bind-duplicate')]
    with tempfile.TemporaryDirectory(prefix='opensabba-recovery-') as temporary:
        root = Path(temporary)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, capture_output=True)
        for index, (kind, operation, mode) in enumerate(cases):
            config = root/str(index)
            private = config/'opensabba'
            private.mkdir(parents=True, mode=0o700)
            server = Server(config, cert, key, b'', mode)
            server.kind = kind
            env = dict(os.environ, XDG_CONFIG_HOME=str(config))
            session = dict(format=2, host='127.0.0.1', port=server.port, ca_file=str(cert),
                           username='test-user', device_uuid='test-device', token='test-token',
                           ds_id='test-nas', registration_state='confirmed')
            record = dict(schema=1, ds_id='test-nas', username='test-user', device_uuid='test-device',
                          phase='upload' if kind == 'backup' else 'download',
                          running_task_id=27, task_id=2, version_id=1,
                          image_name='test-image', image_size=512, image_sha256=hashlib.sha256(b'x'*512).hexdigest())
            if kind == 'backup':
                record.update(result_id=112, data_format=1, snapshot_info=b'{}', requested_outcome='complete')
                if mode.startswith('multi-incremental'):
                    size = 4*1024*1024
                    ranges = [dict(offset=0,length=1024*1024,changed=1),
                              dict(offset=1024*1024,length=2*1024*1024,changed=0),
                              dict(offset=3*1024*1024,length=1024*1024,changed=1)]
                    record.update(schema=5,compression='none',image_name='disk-0',
                                  image_size=size,image_sha256='a'*64,
                                  images=[dict(name='disk-0',size=size,sha256='a'*64,
                                               base_sha256='b'*64,ranges=ranges),
                                          dict(name='disk-1',size=size,sha256='c'*64,
                                               base_sha256='d'*64,ranges=ranges)],
                                  incremental=dict(base_version_id=8,base_result_id=13,
                                                   base_running_task_id=26,base_snapshot_id='e'*32))
            else:
                record.update(device_id=7, result_id=112, destination=str(config/'image.img'))
                if mode == 'complete':
                    record['phase'] = 'finish'
                if mode.startswith('bind-'):
                    del record['result_id']
            if mode == 'unknown-run':
                record.update(phase='prepare' if kind == 'backup' else 'create', running_task_id=0)
                if kind == 'backup':
                    record['create_task_id'] = 2
                    for key_name in ('version_id', 'data_format'):
                        del record[key_name]
                del record['result_id']
            if mode == 'foreign-journal':
                record['device_uuid'] = 'foreign'
            if mode == 'pending':
                record['resolution'] = dict(state='cancel-pending', outcome='cancel')
            for name, data in [('session', session), (kind+'-job', record)]:
                path = private/(name+'.pstream')
                path.write_bytes(wire(data))
                path.chmod(0o600)
            path = private/(kind+'-job.pstream')
            original = path.read_bytes()
            def cli(*arguments):
                return subprocess.run([exe, *arguments], env=env, capture_output=True, text=True, timeout=15)
            try:
                result = cli(kind, operation)
                good = mode in ('success', 'complete', 'partial_success', 'failure', 'cancel',
                                'bind-running', 'multi-incremental', 'multi-incremental-complete')
                check((result.returncode == 0) == good, f'{kind}/{operation}/{mode}: {result.stdout}{result.stderr}')
                check('test-token' not in result.stdout+result.stderr, 'token printed')
                private.chmod(0o700)
                saved = value(Reader(path.read_bytes()))
                if good:
                    status = json.loads(cli(kind, 'status', '--json').stdout)
                    expected = {'partial_success': 'partial', 'failure': 'error', 'success': 'cancel',
                                'bind-running': 'cancel', 'multi-incremental': 'cancel',
                                'multi-incremental-complete': 'complete'}.get(mode, mode)
                    check(status['phase'] == expected and status['terminal'] == 1, 'outcome not recorded')
                    check(status['transfer_phase'] == record['phase'], 'transfer evidence lost')
                    if kind == 'restore':
                        check(status['verified'] == int(mode == 'complete'), 'incorrect restore verification evidence')
                        check(status['result_id'] == 112, 'restore result binding missing')
                elif mode in ('lost', 'unexpected-complete'):
                    check(saved['resolution']['state'] == 'cancel-pending', 'uncertain cancel discarded')
                    count = server.requests.count('image_restore') + server.requests.count('backup')
                    check(cli(kind, 'cancel').returncode != 0, 'uncertain cancellation replayed')
                    check(server.requests.count('image_restore')+server.requests.count('backup') == count,
                          'cancellation sent twice')
                    server.mode = 'cancel'
                    check(cli(kind, 'reconcile').returncode == 0, 'lost cancel reply not reconciled')
                    status = json.loads(cli(kind, 'status', '--json').stdout)
                    check(status['phase'] == 'cancel' and status['terminal'] == 1,
                          'reconciled cancellation still unresolved')
                else:
                    check(path.read_bytes() == original, 'failed observation changed journal')
                    check('backup' not in server.requests and 'image_restore' not in server.requests,
                          'invalid cancellation sent')
            finally:
                private.chmod(0o700)
                server.close()
        print(f'{len(cases)} job recovery cases passed')


if __name__ == '__main__':
    main()
