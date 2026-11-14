"""Independent TLS transcript for preparation -> metadata -> blocks -> completion.

The metadata fixture is a protocol specimen, not a restorable disk layout.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading

from test_image import Reader, receive_blocks
from test_login import value
from test_probe import check, wire


class Server:
    def __init__(self, cert, key, mode, root, metadata, image):
        self.mode, self.root, self.metadata, self.image = mode, root, metadata, image
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.stop = threading.Event()
        self.requests, self.errors = [], []
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    def run(self):
        while not self.stop.is_set():
            try:
                peer, _ = self.listener.accept()
            except socket.timeout:
                continue
            try:
                with peer:
                    peer.settimeout(4)
                    upgrade = value(peer)
                    check(set(upgrade) == {'agent', 'action'} and
                          upgrade['action'] == 'encrypt_channel', 'plaintext secrets')
                    peer.sendall(wire({}))
                    with self.context.wrap_socket(peer, server_side=True) as tls:
                        try:
                            request = value(tls)
                        except (EOFError, ssl.SSLEOFError):
                            check(self.mode.startswith('persist-') or self.mode in
                                  ('mutate-after-prepare', 'replace-after-prepare'),
                                  'unexpected early disconnect')
                            continue
                        if request['action'] == 'query_server_info':
                            tls.sendall(wire({'ds_id': 'foreign' if self.mode == 'identity' else 'test-nas'}))
                            continue
                        check(request['agent']['version'] == {'major': 3, 'minor': 2, 'mini': 1, 'build': '5059'},
                              'wrong protocol version')
                        check(request['token'] == 'test-token' and request['ds_id'] == 'test-nas',
                              'wrong authentication')
                        self.handle(tls, request)
            except Exception as error:
                self.errors.append(error)

    def handle(self, tls, request):
        operation = request['subaction']
        self.requests.append(operation)
        common = {'action', 'subaction', 'token', 'ds_id', 'agent'}
        journal = (self.root / 'journal').read_text().splitlines()
        if operation == 'update_backup_task':
            check(journal == ['planned', 'prepare'], 'preparation sent before durable intent')
            check(set(request) == common | {'running_task_id', 'base_version_id', 'is_cbt',
                                           'is_cache', 'check_point_backup'}, 'handshake keys')
            check(request['action'] == 'client_trigger' and request['running_task_id'] == 27 and
                  all(request[k] == 0 for k in ('base_version_id', 'is_cbt', 'is_cache', 'check_point_backup')),
                  'wrong full-backup handshake')
            if self.mode == 'lost-prepare':
                return
            if self.mode == 'reject-prepare':
                tls.sendall(wire({'error': {'code': 8193}}))
                return
            response = {'running_task_id': 27, 'version_id': 9, 'result_id': 14, 'data_format': 2}
            if self.mode in ('missing-version_id', 'missing-result_id', 'missing-data_format'):
                del response[self.mode.removeprefix('missing-')]
            if self.mode == 'wrong-id':
                response['running_task_id'] = 28
            if self.mode == 'zero-result':
                response['result_id'] = 0
            tls.sendall(wire(response))
        elif operation == 'update_device_spec':
            check(journal[-2:] == ['prepared', 'metadata'], 'metadata sent before durable intent')
            check(set(request) == common | {'running_task_id', 'resume', 'enable_app_aware', 'snapshot_info'},
                  'metadata keys')
            check(request['action'] == 'backup' and request['running_task_id'] == 27 and
                  request['resume'] == 0 and request['enable_app_aware'] == 0, 'metadata context')
            check(isinstance(request['snapshot_info'], bytes) and request['snapshot_info'] == self.metadata,
                  'metadata not preserved as a PStream buffer')
            check(json.loads(request['snapshot_info'])['device_spec']['images'][0]['length'] ==
                  str(self.image.stat().st_size), 'fixture extent mismatch')
            if self.mode == 'lost-metadata':
                return
            tls.sendall(wire({'error': {'code': 20480}} if self.mode == 'reject-metadata' else {}))
        elif operation == 'upload_block':
            check(journal[-2:] == ['metadata-accepted', 'upload'], 'upload before metadata accepted/intent')
            tls.sendall(wire({'success': 1}))
            receive_blocks(tls, self.image, self.root / 'restored')
            if self.mode == 'lost-close':
                return
            tls.sendall(wire({'close': 1}))
        elif operation == 'check_complete':
            check(journal[-2:] == ['uploaded', 'finish'], 'completion before upload/durable intent')
            check(set(request) == common | {'running_task_id', 'result_id', 'is_cbt', 'status'},
                  'completion keys')
            check(request['action'] == 'backup' and request['running_task_id'] == 27 and
                  request['result_id'] == 14 and request['is_cbt'] == 0, 'completion context')
            expected = 'cancel' if self.mode == 'cancel' else 'error' if self.mode == 'report-error' else 'complete'
            check(request['status'] == expected, 'wrong requested outcome')
            if self.mode == 'lost-finish':
                return
            response = {'status': expected}
            if self.mode == 'incomplete':
                response = {'error': {'code': 28676}}
            elif self.mode == 'missing-status':
                response = {}
            elif self.mode == 'unknown-status':
                response = {'status': 'maybe'}
            elif self.mode == 'partial':
                response = {'status': 'partial'}
            tls.sendall(wire(response))
        else:
            raise AssertionError(f'unexpected operation {operation}')

    def close(self):
        self.stop.set()
        self.worker.join(5)
        self.listener.close()
        check(not self.worker.is_alive() and not self.errors, str(self.errors))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('driver')
    parser.add_argument('openssl')
    args = parser.parse_args()
    driver = str(Path(args.driver).resolve())
    with tempfile.TemporaryDirectory(prefix='opensabba-backup-control-') as directory:
        root = Path(directory)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, capture_output=True)
        image = root / 'source.img'
        image.write_bytes(bytes(range(256)) * 8192)
        metadata = json.dumps({'agent_version': '5059', 'device_spec': {
            'images': [{'image_name': 'test-image', 'length': str(image.stat().st_size)}]},
            'disk_images': []}).encode()
        modes = ('success', 'cancel', 'report-error', 'identity', 'reject-prepare', 'lost-prepare',
                 'missing-version_id', 'missing-result_id', 'missing-data_format', 'wrong-id', 'zero-result',
                 'reject-metadata', 'lost-metadata', 'lost-close', 'lost-finish', 'incomplete',
                 'missing-status', 'unknown-status', 'partial', 'persist-prepare', 'persist-metadata',
                 'persist-finish', 'empty-metadata', 'nul-metadata', 'persist-prepared',
                 'persist-metadata-accepted', 'persist-complete', 'mutate-after-prepare',
                 'replace-after-prepare')
        for mode in modes:
            case = root / mode
            case.mkdir()
            # Independent source per case because mutation tests modify it.
            source = case / 'source.img'
            source.write_bytes(image.read_bytes())
            spec = case / 'spec.json'
            spec.write_bytes(b'' if mode == 'empty-metadata' else metadata + b'\0' if mode == 'nul-metadata' else metadata)
            server = Server(cert, key, mode, case, metadata, source)
            try:
                result = subprocess.run([driver, str(server.port), str(cert), mode, str(spec),
                                         str(source), str(case / 'journal')],
                                        capture_output=True, text=True, timeout=15)
            finally:
                server.close()
            check(result.returncode == (0 if mode in ('success', 'cancel', 'report-error') else 1),
                  f'{mode}: {result.stderr}')
            check('test-token' not in result.stdout + result.stderr, 'token exposed')
            check(len(server.requests) == len(set(server.requests)), 'uncertain request automatically retried')
            journal = (case / 'journal').read_text().splitlines() if (case / 'journal').exists() else []
            if result.returncode:
                check('complete' not in journal, 'failure recorded as completed')
            state_path = case / 'journal.pstream'
            if state_path.exists():
                with state_path.open('rb') as stream:
                    state = value(Reader(stream))
                    check(stream.read() == b'', 'trailing state bytes')
                check(state['phase'] == journal[-1], 'persisted phase does not match audit')
                check(state['image_sha256'] == hashlib.sha256(image.read_bytes()).hexdigest(),
                      'source fingerprint mismatch')
                check(state['snapshot_info'] == metadata and 'token' not in state,
                      'descriptor changed or credentials persisted')
                if state['phase'] not in ('planned', 'prepare'):
                    check((state['version_id'], state['result_id'], state['data_format']) == (9, 14, 2),
                          'prepared identifiers not saved')
                if mode == 'lost-finish' or mode == 'persist-complete':
                    check(state['phase'] == 'finish', 'uncertain completion treated as terminal')
                if mode == 'lost-prepare' or mode == 'persist-prepared':
                    check(state['phase'] == 'prepare' and 'result_id' not in state,
                          'uncertain preparation treated as known')
            if mode in ('mutate-after-prepare', 'replace-after-prepare'):
                check(server.requests == ['update_backup_task'] and 'changed' in result.stderr,
                      'mutated source continued to metadata or upload')
            if mode in ('identity', 'persist-prepare'):
                check(not server.requests, 'credentials/mutation sent after identity/persistence failure')
            if mode == 'persist-metadata':
                check(server.requests == ['update_backup_task'], 'metadata sent after persistence failure')
            if mode == 'persist-finish':
                check('check_complete' not in server.requests, 'completion sent after persistence failure')
            if mode in ('empty-metadata', 'nul-metadata'):
                check('update_device_spec' not in server.requests, 'invalid buffer transmitted')
            if mode == 'incomplete':
                check('has not completed' in result.stderr, 'missing confirmed human-readable error')
            print(f'backup control {mode}: passed')


if __name__ == '__main__':
    main()
