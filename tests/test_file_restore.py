"""NAS-pushed file restore through the service API, using loopback TLS only."""
import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time

from lz4_receiver import literal_block
from pstream_peer import Reader, value, open_snapshot
from test_probe import check, wire


class Server:
    def __init__(self, root, cert, key, mode, metadata=False):
        self.root, self.mode, self.metadata = root, mode, metadata
        self.destination = root / 'destination'
        self.destination.mkdir()
        self.payload = bytes(range(256)) * 31 + b'end of restored file'
        self.running = dict(id=64, type=1, device_id=5, task_id=2, version_id=9,
                            result_id=112, status=1, detail_status=0,
                            file_restore_task=dict(running_task_id=64, device_name='fixture device',
                                source_device_id=5, task_name='file restore fixture', version_time=100,
                                target_path='/backup/version', source='/source',
                                destination=str(self.destination), selected_paths=['/nested'],
                                encryption=1, compression=int(mode not in ('raw', 'null-flags', 'omitted-flags')),
                                conflict_handle='skip' if mode == 'skip' else 'overwrite',
                                total_count=4, current_count=0, total_size=len(self.payload),
                                current_size=0, error_count=0, error_code=0))
        if mode == 'cross-device-source':
            self.running['file_restore_task']['source_device_id'] = 6
        self.expected, self.acknowledged, self.ack_attempts, self.requests = {}, {}, [], []
        self.downloads = []
        self.activity, self.log_attempts = [], []
        self.activity_rows = []
        self.reject_logs = mode in ('log-retry', 'log-send-failed')
        self.activity_fault = mode == 'log-lost-reply'
        self.block_activity_connection = False
        self.failed_activity_sends = 0
        self.activity_id = None
        self.errors, self.clients = [], []
        self.first_chunk = threading.Event()
        self.release = threading.Event()
        self.stop = threading.Event()
        self.cancel_observed = threading.Event()
        self.ack_started = threading.Event()
        self.ack_replayed = threading.Event()
        self.transfer_started = None
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(cert, key)
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.worker = threading.Thread(target=self.serve)
        self.worker.start()

    def record(self):
        with open_snapshot(self.root / 'journal.pstream') as snapshot:
            return value(Reader(snapshot.read()))

    def file(self, identifier, relative, kind=0, data=None, offset=0, size=None):
        fields = dict(id=identifier, path=str(self.destination / relative), file_type=kind)
        # NAS mutable skip lookups insert null when false. Reader lookups also
        # materialize null range members on directory/error records.
        if self.mode != 'omitted-flags':
            fields['skip'] = 0 if self.mode == 'explicit-flags' else None
        if kind == 0:
            fields.update(size=len(data) if size is None and data is not None else size or 0,
                          offset=offset, length=len(data) if data is not None else 0)
        else:
            fields.update(size=None, offset=None, length=None)
        if data is not None:
            compression = bool(self.running['file_restore_task']['compression'])
            fields['buffer'] = literal_block(data) if compression else data
            # The compression worker adds true only after compressing a buffer;
            # raw records carry no flag. Explicit null/zero are separate cases.
            if compression:
                fields['compression'] = 1
            elif self.mode == 'null-flags':
                fields['compression'] = None
        if kind == 1 or kind == 0 and offset + fields['length'] == fields['size']:
            fields.update(mode=0o750 if kind == 1 else 0o640, atime=1600000001, mtime=1600000002,
                          uid=os.getuid() if os.name != 'nt' else 0,
                          gid=os.getgid() if os.name != 'nt' else 0)
        self.expected[identifier] = 1 if kind == 2 else 2 if kind in (9998, 9999) else 0
        if kind == 2:
            fields['error_code'] = 13
        return fields

    def send_file(self, peer, fields):
        peer.sendall(wire(dict(has_more=1, file=fields)))

    def transfer(self, peer, request):
        attempt = len(self.downloads)
        self.downloads.append(request)
        if self.mode in ('restart-partial', 'restart-finish'):
            check('resume' not in request, 'fresh process recovered a partial-file offset')
            if attempt == 0 and self.mode == 'restart-partial':
                self.send_file(peer, self.file(41, 'partial.bin', data=self.payload[:3073],
                                               size=len(self.payload)))
                return
            if attempt == 0 or self.mode == 'restart-partial':
                self.send_file(peer, self.file(41, 'partial.bin', data=self.payload))
            # On the restarted finish attempt the NAS has no unfinished IDs.
        elif self.mode in ('ack-inflight', 'ack-server-error'):
            self.transfer_started = time.monotonic()
            # Two directory contents complete within one handler poll. Their
            # metadata remains deferred while get_file is deliberately open.
            self.send_file(peer, self.file(61, 'batch', 1))
            self.send_file(peer, self.file(62, 'batch/deeper', 1))
            check(self.ack_started.wait(8), '300 ms ACK did not run while receive blocked')
            self.send_file(peer, self.file(63, 'batch/third', data=b'third'))
            self.send_file(peer, self.file(64, 'batch/deeper/fourth', data=b'fourth'))
            check(self.ack_replayed.wait(8), 'writer/ACK failed to continue independently')
        elif self.mode == 'skip':
            (self.destination / 'exists.bin').write_bytes(b'preserve existing content')
            peer.sendall(wire(dict(precheck=1, destination=str(self.destination),
                                   paths=['/exists.bin', '/absent.bin'], skip_threshold=0x80000)))
            while True:
                reply = value(peer)
                if reply.get('alive') == 1:
                    continue
                check(reply == dict(paths=['/exists.bin']), f'wrong skip precheck: {reply}')
                break
            skipped = self.file(21, 'exists.bin', data=b'replacement')
            skipped = {key: skipped[key] for key in ('id', 'path', 'file_type')}
            skipped['skip'] = 1
            self.send_file(peer, skipped)
            self.send_file(peer, self.file(22, 'absent.bin', data=b'new content'))
        elif self.mode == 'errors':
            for identifier, kind in enumerate((2, 9998, 9999), 31):
                self.send_file(peer, self.file(identifier, f'error-{kind}', kind))
        elif self.mode == 'chunk-error':
            self.send_file(peer, self.file(35, 'failed.bin', data=b'prefix', size=100))
            self.send_file(peer, self.file(35, 'failed.bin', 2))
            self.send_file(peer, self.file(36, 'next.bin', data=b'next record'))
        elif self.mode in ('log-lost-reply', 'log-send-failed'):
            self.send_file(peer, self.file(51, 'retry.bin', data=self.payload))
        elif self.mode.startswith('resume') or self.mode == 'cancel':
            cut = 3073
            if attempt == 0:
                check('resume' not in request, 'first request resumed nonexistent file')
                self.send_file(peer, self.file(41, 'partial.bin', data=self.payload[:cut],
                                               size=len(self.payload)))
                self.first_chunk.set()
                if self.mode == 'cancel':
                    # The observer must close this blocked transfer after seeing cancellation.
                    self.release.wait(12)
                return
            offset = cut if self.mode == 'resume' else 0
            if offset:
                check(request.get('resume') == dict(path=str(self.destination / 'partial.bin'),
                                                    progress=cut), 'partial-file resume offset/path differs')
            else:
                check('resume' not in request, 'missing/mismatched temporary file sent a resume')
            self.send_file(peer, self.file(41, 'partial.bin', data=self.payload[offset:],
                                           offset=offset, size=len(self.payload)))
        else:
            # Directories arrive before children. Final metadata must survive child creation.
            self.send_file(peer, self.file(11, 'nested', 1))
            self.send_file(peer, self.file(12, 'nested/deeper', 1))
            for start, stop in ((0, 3073), (3073, 6000), (6000, len(self.payload))):
                self.send_file(peer, self.file(13, 'nested/deeper/file.bin',
                    data=self.payload[start:stop], offset=start, size=len(self.payload)))
            self.send_file(peer, self.file(14, 'nested/second.bin', data=b'second file'))
        peer.sendall(wire(dict(has_more=0)))

    def serve(self):
        while not self.stop.is_set():
            try:
                peer, _ = self.listener.accept()
            except socket.timeout:
                continue
            worker = threading.Thread(target=self.handle, args=(peer,))
            self.clients.append(worker)
            worker.start()

    def handle(self, peer):
        try:
            with peer:
                peer.settimeout(15)
                check(value(peer)['action'] == 'encrypt_channel', 'authentication before TLS')
                if self.block_activity_connection:
                    # The activity channel fails before TLS and before its
                    # authenticated request can reach the NAS handler.
                    self.block_activity_connection = False
                    self.failed_activity_sends += 1
                    return
                peer.sendall(wire({}))
                with self.tls.wrap_socket(peer, server_side=True) as tls:
                    request = value(tls)
                    action = request['action']
                    operation = request.get('subaction', action)
                    self.requests.append(operation)
                    if action == 'query_server_info':
                        reply = dict(ds_id='test-nas')
                        if self.mode == 'log-send-failed' and self.activity_fault:
                            journal = self.root / 'journal.pstream'
                            if journal.exists() and self.record()['pending_logs']:
                                self.block_activity_connection = True
                    else:
                        check(request['token'] == 'test-token' and request['ds_id'] == 'test-nas',
                              'restore missing authenticated NAS envelope')
                        if action == 'list_device_task':
                            reply = dict(tasks=[dict(task_id=99 if self.mode == 'cross-device-source' else 2,
                                device_info=dict(device_uuid='test-device',
                                    device_id=6 if self.mode == 'foreign-destination' else 5))])
                        elif action == 'get_task':
                            reply = dict(task_list=[dict(id=2, name='fixture task', task_uuid='fixture-task-uuid')])
                        elif action == 'log_report':
                            check(request['subaction'] == 'result_detail', 'wrong restore activity transport')
                            check(len(request['logs']) == 1, 'unexpected restore log batch')
                            log = request['logs'][0]
                            parameters = json.loads(log['other_params'])
                            check(log['running_task_id'] == 64 and isinstance(log['log_time'], int) and
                                  abs(log['log_time'] - time.time()) < 60, 'activity run/time differs')
                            check(parameters['running_task_id'] == 64 and parameters['task_id'] == 2 and
                                  parameters['result_id'] == 112 and parameters['task_uuid'] ==
                                  ('' if self.mode == 'cross-device-source' else 'fixture-task-uuid'),
                                  'activity JSON identity differs')
                            check(isinstance(parameters['id'], int), 'missing local event identity')
                            if self.activity_id is None:
                                self.activity_id = parameters['id']
                            check(parameters['id'] == self.activity_id, 'activity event identity changed')
                            check(log['log_type'] in (6003, 6004, 6005, 6006, 6011, 6015, 6016, 6019, 6021),
                                  f'non-uploaded/unknown restore activity: {log}')
                            check(any(all(log[key] == pending[key] for key in
                                          ('log_type', 'log_time', 'other_params'))
                                      for pending in self.record()['pending_logs']),
                                  'activity upload preceded durable log record')
                            self.log_attempts.append(log)
                            if self.mode == 'log-lost-reply' and self.activity_fault:
                                if not self.activity_rows:
                                    # Commit the row, then lose the reply.
                                    self.activity_rows.append(log)
                                    self.activity.append((log['log_type'], parameters))
                                self.activity_fault = False
                                return
                            if self.reject_logs:
                                reply = dict(error=dict(code=8193))
                                self.reject_logs = False
                            else:
                                self.activity_rows.append(log)
                                self.activity.append((log['log_type'], parameters))
                                reply = {}
                        elif action == 'get_running_task':
                            current = dict(self.running)
                            if self.mode == 'cancel' and self.first_chunk.is_set():
                                current['status'] = 3
                                self.cancel_observed.set()
                            reply = dict(running_task_list=[current])
                        elif action == 'get_running_task_result':
                            check(request['result_id'] == 112, 'wrong activity result identity')
                            reply = dict(running_task_result=dict(task_id=2, result_id=112,
                                         job_action='restore', status='cancel'))
                        else:
                            check(action == 'restore' and request['running_task_id'] == 64,
                                  f'wrong file restore action/run: {request}')
                            if operation == 'get_file':
                                self.transfer(tls, request)
                                return
                            if operation == 'update_done_ids':
                                ids = request['done_ids']
                                check(ids and len({entry['id'] for entry in ids}) == len(ids),
                                      'empty/duplicate done IDs')
                                pending = self.record()['done_ids']
                                check(all(entry in pending for entry in ids),
                                      'acknowledgement request preceded durable pending IDs')
                                for entry in ids:
                                    check(entry['id'] in self.expected and
                                          entry['error'] == self.expected[entry['id']],
                                          f'wrong record acknowledgement: {entry}')
                                self.ack_attempts.append(ids)
                                if self.mode in ('ack-inflight', 'ack-server-error'):
                                    if len(self.ack_attempts) == 1:
                                        check(time.monotonic() - self.transfer_started >= .20,
                                              'ACK ran per record instead of after the handler sleep')
                                        check(ids == [dict(id=61, error=0), dict(id=62, error=0)],
                                              'normal polling did not batch directory content')
                                        check(len(self.record()['directories']) == 2,
                                              'directory content ACK waited for deferred metadata')
                                        self.acknowledged.update({entry['id']: entry['error'] for entry in ids})
                                        self.ack_started.set()
                                        if self.mode == 'ack-inflight':
                                            # Retain a reader of the preceding generation
                                            # while the writer publishes later checkpoints.
                                            with open_snapshot(self.root / 'journal.pstream'):
                                                deadline = time.monotonic() + 6
                                                while not (self.destination / 'batch/deeper/fourth').exists():
                                                    check(time.monotonic() < deadline,
                                                          'in-flight ACK blocked the writer')
                                                    time.sleep(.01)
                                            # The NAS committed both IDs, then the response was lost.
                                            return
                                        reply = dict(error=dict(code=8193))
                                    else:
                                        expected = range(61, 65) if self.mode == 'ack-inflight' else (63, 64)
                                        check(ids == [dict(id=i, error=0) for i in expected],
                                              'ACK snapshot deletion/replay differs from official agent')
                                        self.acknowledged.update({entry['id']: entry['error'] for entry in ids})
                                        self.ack_replayed.set()
                                        reply = {}
                                elif self.mode == 'ack-final-failed':
                                    return
                                elif self.mode == 'ack-retry' and len(self.ack_attempts) == 1:
                                    return
                                else:
                                    self.acknowledged.update({entry['id']: entry['error'] for entry in ids})
                                    reply = {}
                            elif operation == 'check_complete':
                                check(self.mode != 'cancel', 'NAS cancellation sent completion mutation')
                                if self.mode != 'ack-final-failed':
                                    check(self.acknowledged == self.expected, 'finish before record acknowledgements: ' +
                                          repr({key: self.record().get(key) for key in ('local_error', 'done_ids', 'phase')}))
                                check(request['status'] == 'complete', 'wrong provisional completion status')
                                if self.mode == 'ack-retry':
                                    for failed in self.ack_attempts[0]:
                                        check(any(failed in ids for ids in self.ack_attempts[1:]),
                                              'failed done IDs removed before successful retry')
                                reply = dict(status='partial' if self.mode == 'ack-final-failed' else
                                             self.mode if self.mode in ('partial', 'error')
                                             else 'partial' if self.mode in ('errors', 'chunk-error') else 'complete')
                            else:
                                raise AssertionError(f'unexpected operation: {operation}')
                    tls.sendall(wire(reply))
        except (EOFError, ssl.SSLEOFError, ConnectionResetError, BrokenPipeError):
            # Cancellation can race with the observer's TLS handshake or final read.
            if self.mode not in ('cancel', 'restart-finish'):
                self.errors.append('unexpected peer disconnect')
        except Exception as error:
            self.errors.append(repr(error))

    def close(self):
        self.release.set()
        self.stop.set()
        self.worker.join(3)
        for worker in self.clients:
            worker.join(16)
        self.listener.close()
        check(not any(worker.is_alive() for worker in self.clients), 'fixture workers did not stop')
        check(not self.errors, f'{self.mode}: {self.errors}')


class ResidentDriver:
    """Retain official agent process-local context across connection/report retries."""
    def __init__(self, command):
        self.process = subprocess.Popen(command + ['--resident'], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def run(self):
        self.process.stdin.write('run\n')
        self.process.stdin.flush()
        line = self.process.stdout.readline().strip()
        check(line.startswith(('OK ', 'ERROR ')), f'driver stopped: {line}')
        ok = line.startswith('OK ')
        return subprocess.CompletedProcess([], 0 if ok else 1, line[3:] if ok else '',
                                           '' if ok else line[6:])

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=20)
        check(self.process.returncode == 0, self.process.stderr.read())


def run_case(driver, root, cert, key, mode, metadata):
    root.mkdir()
    server = Server(root, cert, key, mode, metadata)
    running_path, journal = root / 'running.pstream', root / 'journal.pstream'
    running_path.write_bytes(wire(server.running))
    if mode not in ('skip', 'errors', 'cancel') and not mode.startswith('resume'):
        target = server.destination / 'nested/second.bin'
        target.parent.mkdir(parents=True)
        target.write_bytes(b'old data to overwrite')
    command = [driver, str(server.port), str(cert), str(running_path), str(journal)]
    resident = ResidentDriver(command)
    try:
        result = resident.run()
        if mode == 'log-retry':
            check(len(server.log_attempts) > len(server.activity), 'activity rejection was not retried')
        if mode == 'log-lost-reply':
            check(len(server.activity_rows) == 2 and server.activity_rows[0] == server.activity_rows[1],
                  'lost activity reply did not replay the same process-local entry')
        if mode == 'foreign-destination':
            check(result.returncode != 0, 'foreign destination device accepted')
            check(not server.downloads and not server.ack_attempts and
                  'check_complete' not in server.requests and not journal.exists(),
                  'foreign destination device wrote state or mutated restore')
            return
        if mode.startswith('resume'):
            check(result.returncode != 0, 'disconnect reported success')
            record = server.record()
            check('check_complete' not in server.requests, 'disconnect sent completion')
            check(record['phase'] == 'download', 'disconnect lost download journal phase')
            partial = record['partial']
            temporary = Path(partial['temp_path'])
            check(partial['progress'] == 3073 and temporary.read_bytes() == server.payload[:3073],
                  'partial bytes/checkpoint not retained')
            if mode == 'resume-missing':
                temporary.unlink()
            elif mode == 'resume-mismatch':
                temporary.write_bytes(b'shorter partial')
            result = resident.run()
            check((server.destination / 'partial.bin').read_bytes() == server.payload,
                  'resumed file differs from source')
        expected = mode if mode in ('partial', 'error') else (
            'partial' if mode in ('errors', 'chunk-error', 'ack-final-failed') else
            'cancel' if mode == 'cancel' else 'complete')
        check(result.returncode == 0 and result.stdout.strip() == expected,
              f'{mode}: {result.stdout}{result.stderr}; requests={server.requests}; errors={server.errors}')
        record = server.record()
        check(not record['pending_logs'], 'activity reporting work was not drained')
        check(b'test-token' not in journal.read_bytes(), 'journal persisted authentication secret')
        if mode == 'cancel':
            check(server.cancel_observed.is_set(), 'observer did not see NAS cancellation')
            check('check_complete' not in server.requests, 'cancelled job sent check_complete')
            check(not (server.destination / 'partial.bin').exists(), 'cancelled partial file was installed')
        else:
            check(record['phase'] == expected, 'NAS completion outcome not saved')
            if mode != 'ack-final-failed':
                check(server.acknowledged == server.expected, 'record acknowledgements incomplete')
        if mode == 'errors':
            check(not list(server.destination.iterdir()), 'error records created destination objects')
            check([kind for kind, _ in server.activity] == [6021, 6011] and
                  record['last_local_log']['log_type'] == 6018,
                  'source/unsupported activity upload selection differs')
        elif mode == 'chunk-error':
            check(not (server.destination / 'failed.bin').exists() and
                  not list(server.destination.glob('ActiveBackupTemp_*')) and 'partial' not in record,
                  'source error retained partial content or resume state')
            check((server.destination / 'next.bin').read_bytes() == b'next record' and
                  record['last_source_error'] == 13, 'source error prevented next record or lost errno')
            check([kind for kind, _ in server.activity] == [6003] and
                  json.loads(record['last_local_log']['other_params'])['error_code'] == '13',
                  'source error activity must stay local and carry decimal errno text')
        elif mode == 'skip':
            check([kind for kind, _ in server.activity] == [6004, 6003], 'skip/install logs differ')
            check((server.destination / 'exists.bin').read_bytes() == b'preserve existing content',
                  'skip overwrote existing file')
            check((server.destination / 'absent.bin').read_bytes() == b'new content',
                  'skip failed to install absent file')
        elif mode in ('log-lost-reply', 'log-send-failed'):
            check([kind for kind, _ in server.activity] ==
                  [6003] * (2 if mode == 'log-lost-reply' else 1),
                  'wrong NAS activity rows after retry')
        elif mode in ('ack-inflight', 'ack-server-error'):
            check(len(server.ack_attempts) == 2, 'unexpected additional ACK request')
            check((server.destination / 'batch/third').read_bytes() == b'third' and
                  (server.destination / 'batch/deeper/fourth').read_bytes() == b'fourth',
                  'ACK failure interrupted file installation')
        elif mode == 'ack-final-failed':
            check(record['done_ids'] and len(server.ack_attempts) == 2 and
                  server.requests.count('check_complete') == 1,
                  'final ACK failure invented a required drain or blocked completion')
        elif not mode.startswith('resume') and mode != 'cancel':
            check((server.destination / 'nested/deeper/file.bin').read_bytes() == server.payload,
                  'multichunk restored bytes differ')
            check((server.destination / 'nested/second.bin').read_bytes() == b'second file',
                  'second restored file differs')
            if metadata:
                for relative in ('nested', 'nested/deeper', 'nested/deeper/file.bin', 'nested/second.bin'):
                    info = (server.destination / relative).stat()
                    expected_mode = 0o750 if stat.S_ISDIR(info.st_mode) else 0o640
                    check(stat.S_IMODE(info.st_mode) == expected_mode, f'{relative}: mode differs')
                    check(int(info.st_mtime) == 1600000002, f'{relative}: child creation changed mtime')
                    check(info.st_uid == os.getuid() and info.st_gid == os.getgid(),
                          f'{relative}: ownership differs')
    finally:
        resident.close()
        server.close()


def run_restart_case(driver, root, cert, key, mode):
    root.mkdir()
    server = Server(root, cert, key, mode)
    running, observation = root / 'running.pstream', root / 'journal.pstream'
    running.write_bytes(wire(server.running))
    command = [driver, str(server.port), str(cert), str(running), str(observation)]
    try:
        first = subprocess.run(command + (['--crash-before-finish'] if mode == 'restart-finish' else []),
                               capture_output=True, text=True, timeout=20)
        check(first.returncode == (77 if mode == 'restart-finish' else 1),
              f'{mode}: failed to reach interruption: {first.stderr}')
        check('check_complete' not in server.requests, 'completion request preceded crash boundary')
        before = server.record()
        attempts = len(server.ack_attempts)
        old_temp = Path(before['partial']['temp_path']) if mode == 'restart-partial' else None
        if old_temp:
            check(old_temp.read_bytes() == server.payload[:3073], 'partial file missing before restart')
            check(len(old_temp.name) == len('ActiveBackupTemp_') + 8, 'temporary naming differs from official agent')
        second = subprocess.run(command, capture_output=True, text=True, timeout=20)
        check(second.returncode == 0 and second.stdout.strip() == 'complete',
              f'{mode}: restart stranded the NAS job: {second.stderr}; {server.errors}')
        check(len(server.downloads) == 2 and all('resume' not in r for r in server.downloads),
              'restart bypassed normal get_file rehandling')
        check((server.destination / 'partial.bin').read_bytes() == server.payload,
              'restart installed partial or duplicated bytes')
        check(server.requests.count('check_complete') == 1, 'restart invented a direct completion replay')
        if old_temp:
            check(old_temp.read_bytes() == server.payload[:3073],
                  'restart reused, truncated or swept the unreferenced official agent temporary file')
        else:
            check(len(server.ack_attempts) == attempts, 'restart replayed completed IDs')
        print(f'{mode}: passed')
    finally:
        server.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('driver')
    parser.add_argument('openssl')
    parser.add_argument('--metadata', action='store_true')
    parser.add_argument('--ack-cadence', action='store_true')
    parser.add_argument('--restart', action='store_true')
    args = parser.parse_args()
    driver = str(Path(args.driver).resolve())
    with tempfile.TemporaryDirectory(prefix='opensabba-file-restore-') as directory:
        root = Path(directory)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, capture_output=True)
        cases = ('compressed', 'raw', 'null-flags', 'omitted-flags', 'explicit-flags',
                 'skip', 'errors', 'chunk-error', 'ack-retry', 'log-retry',
                 'log-lost-reply', 'resume',
                 'resume-missing', 'resume-mismatch', 'cancel', 'partial', 'error',
                 'foreign-destination', 'cross-device-source')
        if args.metadata:
            cases = ('compressed', 'raw')
        if args.ack_cadence:
            cases = ('ack-inflight', 'ack-server-error', 'ack-final-failed')
        if args.restart:
            for mode in ('restart-partial', 'restart-finish'):
                run_restart_case(driver, root / mode, cert, key, mode)
            return
        for mode in cases:
            run_case(driver, root / mode, cert, key, mode, args.metadata)
            print(f'{mode}: passed')


if __name__ == '__main__':
    main()
