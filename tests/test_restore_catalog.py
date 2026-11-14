"""Read-only version discovery through the real saved-session CLI and TLS protocol."""
import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading

from test_login import value
from test_probe import check, wire


class CatalogServer:
    def __init__(self, certificate, key, mode):
        self.mode = mode
        self.requests = []
        self.errors = []
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(certificate, key)
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self.run)
        self.worker.start()

    def run(self):
        while not self.stop.is_set():
            try:
                peer, _ = self.listener.accept()
            except socket.timeout:
                continue
            try:
                self.handle(peer)
            except Exception as error:
                self.errors.append(repr(error))

    def handle(self, peer):
        with peer:
            peer.settimeout(10)
            check(value(peer)['action'] == 'encrypt_channel', 'catalog request sent in clear')
            peer.sendall(wire({}))
            with self.tls.wrap_socket(peer, server_side=True) as tls:
                request = value(tls)
                action = request['action']
                self.requests.append(action)
                if action == 'query_server_info':
                    tls.sendall(wire({'ds_id': 'foreign' if self.mode == 'foreign-nas' else 'test-nas'}))
                    return
                check(request['token'] == 'test-token' and request['ds_id'] == 'test-nas',
                      'catalog authentication mismatch')
                if action == 'list_device_task':
                    task = {'task_id': 2, 'device_info': {
                        'device_id': 7,
                        'device_uuid': 'foreign' if self.mode == 'foreign-device' else 'test-device',
                        'agent_token': 'server-secret', 'login_password': 'server-secret'}}
                    tls.sendall(wire({'tasks': [] if self.mode == 'no-task' else [task]}))
                    return
                check(action == 'list_task_version', 'unexpected catalog action')
                check(request['task_id'] == 2 and request['device_id'] == 7 and
                      request['filter'] == {'offset': 1, 'limit': 2,
                                            'order_by': 'time_start', 'direction': 'DESC',
                                            'version_status': [3]},
                      'wrong catalog request or unbounded page')
                if self.mode in ('storage-error', 'middleware-error'):
                    # 20480 is shared by handler failures, middleware and exceptions.
                    reason = ('get storage status failed' if self.mode == 'storage-error'
                              else 'No rule to authenticate action, deny by default.')
                    tls.sendall(wire({'error': {'code': 20480, 'reason': reason,
                                               'message': 'server-secret'}}))
                    return
                versions = [
                    {'version_id': 20, 'time_start': 1720000000, 'time_end': 1720000300,
                     'status': 3, 'used_size': 1048576, 'full_backup': 1,
                     'other_spec': {'credentials': 'server-secret'},
                     'object_list': [{'path': 'server-secret'}]},
                    {'version_id': 21, 'time_start': 1720000100, 'time_end': 1720000400,
                     'status': 3, 'used_size': 2048, 'full_backup': 2,
                     'other_spec': {'nested': [1, {'password': 'server-secret'}]}}
                ]
                if self.mode == 'invalid-id':
                    versions[1]['version_id'] = '21'
                if self.mode == 'duplicate-id':
                    versions[1]['version_id'] = 20
                if self.mode == 'over-limit':
                    versions.append({'version_id': 22})
                if self.mode == 'missing-size':
                    del versions[1]['used_size']
                payload = 'bad list' if self.mode == 'invalid-list' else versions
                tls.sendall(wire({'versions': payload, 'total': 3,
                                  'device_specs': 'server-secret'}))

    def close(self):
        self.stop.set()
        self.worker.join(timeout=5)
        self.listener.close()
        check(not self.errors, repr(self.errors))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    parser.add_argument('openssl')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='opensabba-catalog-') as temp:
        root = Path(temp)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, capture_output=True)
        for mode in ('success', 'invalid-id', 'duplicate-id', 'over-limit',
                     'missing-size',
                     'storage-error', 'middleware-error', 'invalid-list',
                     'foreign-nas', 'foreign-device', 'no-task'):
            private = root/mode/'opensabba'
            private.mkdir(parents=True, mode=0o700)
            server = CatalogServer(cert, key, mode)
            try:
                session = dict(format=2, host='127.0.0.1', port=server.port, ca_file=str(cert),
                               username='test-user', device_uuid='test-device', token='test-token',
                               ds_id='test-nas', registration_state='confirmed')
                saved = private/'session.pstream'
                saved.write_bytes(wire(session))
                saved.chmod(0o600)
                env = dict(os.environ, XDG_CONFIG_HOME=str(private.parent))
                run = subprocess.run([args.executable, 'restore', 'versions', '--task', '2',
                                      '--offset', '1', '--limit', '2', '--json'],
                                     env=env, capture_output=True, text=True, timeout=15)
                combined = run.stdout + run.stderr
                check('server-secret' not in combined and 'test-token' not in combined,
                      'catalog leaked secret')
                check(saved.read_bytes() == wire(session), 'catalog modified session')
                check((run.returncode == 0) == (mode == 'success'), combined)
                if mode in ('storage-error', 'middleware-error'):
                    check('server rejected restore version catalog (code 20480)' in run.stderr,
                          'catalog rejection lost operation or numeric code')
                    check('storage status' not in run.stderr and 'No rule' not in run.stderr,
                          'catalog guessed failure cause or exposed raw NAS error text')
                if mode == 'success':
                    report = json.loads(run.stdout)
                    check(report == {'task_id': 2, 'device_id': 7, 'offset': 1,
                                     'limit': 2, 'total': 3,
                                     'versions': [
                                         {'version_id': 20, 'time_start': 1720000000,
                                          'time_end': 1720000300, 'status': 3,
                                          'used_size': 1048576, 'full_backup': 1},
                                         {'version_id': 21, 'time_start': 1720000100,
                                          'time_end': 1720000400, 'status': 3,
                                          'used_size': 2048, 'full_backup': 2}]},
                          'catalog output contains unexpected fields')
                    before = len(server.requests)
                    for arguments in (('--task', '0'), ('--task', '2', '--limit', '51'),
                                      ('--task', '2', '--offset', '2147483647')):
                        invalid = subprocess.run([args.executable, 'restore', 'versions', *arguments],
                                                 env=env, capture_output=True, text=True, timeout=10)
                        check(invalid.returncode != 0, 'invalid catalog option accepted')
                    check(len(server.requests) == before, 'invalid catalog option contacted NAS')
                if mode in ('foreign-nas', 'foreign-device', 'no-task'):
                    check('list_task_version' not in server.requests, 'foreign task catalog queried')
            finally:
                server.close()
        print('restore catalog read-only/security cases passed')


if __name__ == '__main__':
    main()
