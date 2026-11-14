"""Concurrent NAS cancellation while the real image writer is blocked in TLS."""
from pstream_peer import upload_value

import argparse
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading

from test_backup_cli import Server as BaseServer, Reader
from test_login import value
from test_probe import check, wire


class Server(BaseServer):
    def record(self):
        return value(Reader((self.root/'journal.pstream').read_bytes()))

    def handle(self, peer):
        try:
            with peer:
                peer.settimeout(20)
                check(value(peer)['action'] == 'encrypt_channel', 'plaintext authentication')
                peer.sendall(wire({}))
                with self.tls.wrap_socket(peer, server_side=True) as tls:
                    request = value(tls)
                    action = request['action']
                    op = request.get('subaction', action)
                    self.requests.append(op)
                    if action == 'query_server_info':
                        response = dict(ds_id='test-nas')
                    else:
                        check(request['token'] == 'test-token', 'wrong token')
                        if op == 'get_base_version':
                            response = dict(base_version_id=8)
                        elif op == 'update_backup_task':
                            if self.mode == 'lost-prepare':
                                return
                            response = dict(running_task_id=27, version_id=9, result_id=14, data_format=1)
                        elif op == 'update_device_spec':
                            response = {}
                        elif op == 'upload_block':
                            tls.sendall(wire(dict(success=1)))
                            block = upload_value(tls)
                            check(block['offset'] == 0 and block['length'] == 1048576, 'no first data block')
                            self.first_block.set()
                            # Stop consuming: the client must abort a blocked socket,
                            # not wait for the image to drain or a close acknowledgement.
                            self.release.wait(18)
                            return
                        elif action == 'get_running_task':
                            check(self.first_block.wait(10), 'control did not overlap transfer')
                            job = dict(id=27, type=0, task_id=2, version_id=9, result_id=14, status=3)
                            jobs = [job]
                            if self.mode.startswith('absent'):
                                jobs = []
                            elif self.mode.startswith('wrong-'):
                                job[self.mode.removeprefix('wrong-')] += 1
                            elif self.mode == 'duplicate':
                                jobs.append(dict(job))
                            elif self.mode == 'missing-field':
                                del job['result_id']
                            elif self.mode == 'control-error':
                                tls.sendall(wire({'error': {'code': 8193}}))
                                return
                            # An unrelated cancelling job must not change identity selection.
                            jobs.insert(0, dict(id=999, task_id=3, type=0, status=3))
                            response = dict(running_task_list=jobs)
                        elif action == 'get_running_task_result':
                            check(request['result_id'] == 14, 'wrong result queried')
                            response = dict(running_task_result=dict(task_id=2, result_id=14,
                                job_action='backup', status='cancel' if self.mode == 'absent-cancel' else
                                'complete' if self.mode == 'absent-complete' else 'incomplete'))
                        elif op == 'check_complete':
                            check(request['status'] == 'cancel' and request['running_task_id'] == 27 and
                                  request['is_cbt'] == int(self.mode == 'incremental'), 'invalid cancel mutation')
                            record = self.record()
                            check(record['nas_cancel_requested'] == 1 and record['phase'] == 'finish' and
                                  record['requested_outcome'] == 'cancel',
                                  'cancel before durable intent')
                            if self.mode == 'lost':
                                return
                            response = dict(status='cancel')
                        else:
                            raise AssertionError(f'unexpected request: {op}')
                    tls.sendall(wire(response))
        except (EOFError, ssl.SSLEOFError, ConnectionResetError, BrokenPipeError):
            # Concurrent monitor shutdown can close a newly opened TLS stream.
            pass
        except Exception as error:
            self.errors.append(repr(error))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('driver')
    parser.add_argument('openssl')
    args = parser.parse_args()
    driver = str(Path(args.driver).resolve())
    with tempfile.TemporaryDirectory(prefix='opensabba-service-cancel-') as directory:
        root = Path(directory)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=IP:127.0.0.1'], check=True, capture_output=True)
        image, metadata = root/'image', root/'metadata'
        image.write_bytes(os.urandom(16*1024*1024))
        metadata.write_text('{}')
        for mode in ('cancel', 'incremental', 'lost', 'lost-prepare', 'absent-cancel', 'absent-complete', 'absent-incomplete',
                     'wrong-task_id', 'wrong-type', 'wrong-version_id', 'wrong-result_id',
                     'duplicate', 'missing-field', 'control-error'):
            case = root/mode
            case.mkdir()
            server = Server(case, cert, key, image, mode)
            server.first_block = threading.Event()
            command = [driver, str(server.port), str(cert),
                       'service-incremental' if mode == 'incremental' else 'service-new', str(metadata), str(image),
                       str(case/'journal')]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=20)
                check((result.returncode == 0) == (mode in ('cancel', 'incremental', 'absent-cancel', 'absent-complete', 'absent-incomplete')),
                      f'{mode}: {result.stdout}{result.stderr}')
                check(server.first_block.is_set() == (mode != 'lost-prepare'), f'{mode}: upload state')
                record = server.record()
                check(record['phase'] == ('prepare' if mode == 'lost-prepare' else
                      'cancel' if mode in ('cancel', 'incremental') else 'finish' if mode == 'lost' else 'upload'),
                      f'{mode}: transfer phase lost')
                if mode in ('cancel', 'incremental', 'absent-cancel', 'absent-complete'):
                    expected = 'complete' if mode == 'absent-complete' else 'cancel'
                    check(record.get('resolution') == dict(state='resolved', outcome=expected) or
                          record['phase'] == expected, mode)
                elif mode == 'lost':
                    check(record['phase'] == 'finish' and record['requested_outcome'] == 'cancel', mode)
                    command[3] = 'service-restart'
                    restarted = subprocess.run(command, capture_output=True, text=True, timeout=20)
                    check(restarted.returncode != 0, 'lost repeat was declared terminal')
                    check(server.requests.count('check_complete') == 2, 'official agent cancellation was not retried')
                    server.mode = 'absent-cancel'
                    restarted = subprocess.run(command, capture_output=True, text=True, timeout=20)
                    check(server.record()['resolution'] == dict(state='resolved', outcome='cancel'),
                          'terminal reconciliation failed')
                    check(server.requests.count('check_complete') == 2, 'resolved cancel replayed')
                elif mode == 'absent-incomplete':
                    check(record['resolution'] == dict(state='retired', outcome='unknown'),
                          'absent event invented a NAS outcome')
                else:
                    check('resolution' not in record and 'nas_cancel_requested' not in record,
                          f'{mode}: fabricated cancellation')
                check(server.requests.count('check_complete') == (2 if mode == 'lost' else int(mode in ('cancel', 'incremental'))),
                      f'{mode}: unexpected mutation')
            finally:
                server.close()
        print('Service cancellation, identity rejection, absence, and lost-reply recovery passed.')


if __name__ == '__main__':
    main()
