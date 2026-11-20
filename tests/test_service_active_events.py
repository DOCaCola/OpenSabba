"""Control receipts remain durable and responsive while a real service restore waits.

The peer holds get_file after a process-local partial write. No snapshot driver,
privilege, production endpoint, or client-side event implementation is used.
"""
import argparse
import os
from pathlib import Path
import signal
import ssl
import subprocess
import tempfile
import threading
import time

from pstream_peer import Reader, value
from test_file_restore import Server as RestorePeer
from test_probe import check, wire
from test_service import wait_for


class Nas(RestorePeer):
    def __init__(self, root, cert, key, mode):
        self.case = mode
        self.events, self.replies, self.done = [], [], []
        self.query_count = 0
        self.cancel = False
        self.complete = False
        self.hold_running = False
        self.lost_reply = False
        self.result_queries = []
        self.portal_mode = 'success'
        self.initializations = []
        self.unlinked = False
        self.result_lost = threading.Event()
        self.advance = threading.Event()
        self.advanced = threading.Event()
        self.journals = root / 'config/opensabba'
        self.picker = root / 'picker'
        self.picker.mkdir()
        (self.picker / 'original').mkdir()
        super().__init__(root, cert, key, 'raw')

    def record(self):
        # Inspect the real writer output; production persists no restore context.
        installed = self.destination / 'partial.bin'
        partials = list(self.destination.glob('ActiveBackupTemp_*'))
        size = installed.stat().st_size if installed.exists() else max(
            (p.stat().st_size for p in partials), default=0)
        return dict(phase='complete' if installed.exists() else 'cancel' if self.cancel else 'download', current_size=size, current_count=int(installed.exists()))

    def inbox(self):
        return value(Reader((self.journals / 'events.pstream').read_bytes()))

    def handle(self, peer):
        try:
            with peer:
                peer.settimeout(15)
                check(value(peer)['action'] == 'encrypt_channel', 'plaintext credentials')
                peer.sendall(wire({}))
                with self.tls.wrap_socket(peer, server_side=True) as tls:
                    req = value(tls)
                    action, op = req['action'], req.get('subaction', req['action'])
                    self.requests.append(op)
                    if action == 'query_server_info':
                        reply = dict(ds_id='test-nas')
                    else:
                        check(req['token'] == 'test-token' and req['ds_id'] == 'test-nas', 'identity')
                        if action == 'auth':
                            self.initializations.append(req['init'])
                            self.initial_result_pending = True
                            reply = dict(token='test-token', ds_id='test-nas')
                        elif action == 'auth_admin':
                            check(req['username'] == 'admin' and req['password'] == 'fixture-password',
                                  'logout lost administrator authorization')
                            reply = {}
                        elif action == 'unlink_connection':
                            self.unlinked = True
                            reply = {}
                        elif action == 'heart_beat':
                            reply = {}
                        elif action == 'get_portal_link':
                            check(req['address'] == '127.0.0.1', 'portal address differs from official agent normalization')
                            reply = (dict(url='https://fixture.invalid/recovery') if self.portal_mode == 'success'
                                     else dict(url='') if self.portal_mode == 'empty'
                                     else dict(error=dict(code=4106)) if self.portal_mode == 'error' else {})
                        elif action == 'get_timezone':
                            reply = dict(timezone='0', epoch=str(int(time.time())))
                        elif action == 'get_task':
                            reply = dict(task_list=[dict(id=2, name='Fixture', task_uuid='fixture-task-uuid', compression=0)])
                        elif action == 'list_device_task':
                            reply = dict(tasks=[dict(task_id=2, device_info=dict(
                                device_uuid='test-device', device_id=5))])
                        elif action == 'get_running_task':
                            current = dict(self.running, status=3 if self.cancel else 1)
                            reply = dict(running_task_list=[] if self.complete or self.hold_running else [current])
                        elif action == 'get_running_task_result':
                            if self.initial_result_pending:
                                self.initial_result_pending = False
                                check('result_id' not in req, 'startup invented result identity')
                                tls.sendall(wire({}))
                                return
                            self.result_queries.append(req)
                            check(req.get('result_id') in (None,112), 'result identity changed')
                            if self.case == 'result-lost-query' and not self.result_lost.is_set():
                                self.result_lost.set()
                                return
                            reply = {} if 'result_id' not in req else dict(backup_result=dict(
                                last_success_time=1234, last_backup_status='failure'), running_task_result=dict(task_id=2, result_id=112,
                                job_action='restore', status='cancel' if self.cancel else
                                'complete' if self.complete or self.case == 'normal' else 'incomplete'))
                        elif action == 'pull_event':
                            reply = dict(event_list=[e for e in self.events if e['id'] not in req['event_list']])
                        elif action == 'get_backup_bandwidth':
                            self.query_count += 1
                            reply = dict(backup_bandwidth=0)
                        elif action == 'act_client_result':
                            receipt = next(r for r in self.inbox()['receipts']
                                           if r['payload']['id'] == req['event_id'])
                            check(receipt['node_result'] == {k: req[k] for k in receipt['node_result']},
                                  'result sent before immutable receipt')
                            self.replies.append(req)
                            if self.case == 'lost-reply' and not self.lost_reply:
                                self.lost_reply = True
                                (self.picker / 'original').rmdir()
                                (self.picker / 'changed').mkdir()
                                return
                            reply = {}
                        elif action == 'done_event':
                            ids = req['done_events']
                            receipts = self.inbox()['receipts']
                            check(all(any(r['payload']['id'] == i and r['state'] == 'ack_pending'
                                          for r in receipts) for i in ids), 'ACK before durable completion')
                            if 801 in ids:
                                check(self.inbox()['bandwidth_snapshot'] == dict(backup_bandwidth=0),
                                      'ACK before bandwidth snapshot')
                            self.done.extend(ids)
                            self.events = [e for e in self.events if e['id'] not in ids]
                            if self.case == 'result-lost-ack' and 804 in ids and not self.result_lost.is_set():
                                self.result_lost.set()
                                return
                            reply = {}
                        elif action == 'long_poll':
                            reply = dict(has_event=int(bool(self.events)))
                        elif action == 'log_report':
                            self.activity.append(req)
                            reply = {}
                        elif action == 'restore' and op == 'get_file':
                            self.downloads.append(req)
                            cut = 3073
                            if len(self.downloads) == 1:
                                check('resume' not in req, 'first download resumed')
                                self.send_file(tls, self.file(41, 'partial.bin', data=self.payload[:cut],
                                                              size=len(self.payload)))
                                self.first_chunk.set()
                            elif self.case in ('result-lost-query', 'result-lost-ack'):
                                check('resume' not in req, 'fresh process retained partial offset')
                                self.send_file(tls, self.file(41, 'partial.bin', data=self.payload[:cut],
                                                              size=len(self.payload)))
                            else:
                                check(req.get('resume') == dict(path=str(self.destination / 'partial.bin'),
                                                               progress=cut), 'resume checkpoint changed')
                            offset = cut
                            if self.case in ('normal', 'incomplete'):
                                check(self.advance.wait(12), 'result fixture never advanced transfer')
                                self.send_file(tls, self.file(41, 'partial.bin', data=self.payload[cut:6000],
                                                              offset=cut, size=len(self.payload)))
                                offset = 6000
                                self.advanced.set()
                            check(self.release.wait(12), 'held transfer was never released')
                            if self.cancel or len(self.downloads) == 1 and self.case in (
                                    'reload', 'lost-reply', 'result-lost-query', 'result-lost-ack'):
                                return
                            self.send_file(tls, self.file(41, 'partial.bin', data=self.payload[offset:],
                                                          offset=offset, size=len(self.payload)))
                            tls.sendall(wire(dict(has_more=0)))
                            return
                        elif action == 'restore' and op == 'update_done_ids':
                            check(req['done_ids'] == [dict(id=41, error=0)], 'wrong record acknowledgment')
                            self.ack_attempts.append(req['done_ids'])
                            reply = {}
                        elif action == 'restore' and op == 'check_complete':
                            check(not self.cancel, 'cancel sent completion mutation')
                            check(len(self.ack_attempts) == 1, 'completion preceded ACK')
                            self.complete = True
                            reply = dict(status='complete')
                        else:
                            raise AssertionError(f'unexpected request {req}')
                    tls.sendall(wire(reply))
        except (EOFError, ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
            pass  # Reload, reconnect, and shutdown cancel blocked sockets.
        except Exception as error:
            self.errors.append(repr(error))


def run_case(exe, root, cert, key, mode):
    root.mkdir()
    nas = Nas(root, cert, key, mode)
    private = nas.journals
    private.mkdir(parents=True, mode=0o700)
    session = private / 'session.pstream'
    session.write_bytes(wire(dict(format=2, host='127.0.0.1', port=nas.port, ca_file=str(cert),
        username='test-user', device_uuid='test-device', token='test-token', ds_id='test-nas',
        registration_state='confirmed')))
    session.chmod(0o600)
    env = dict(os.environ, XDG_CONFIG_HOME=str(private.parent))
    unavailable = subprocess.run([exe, '--status'], env=env, capture_output=True, text=True, timeout=5)
    check(unavailable.returncode == 2 and not unavailable.stdout and
          unavailable.stderr == 'Cannot access synology-backupd\n', 'status fell back to saved session')
    process = subprocess.Popen([exe, 'service', 'run'], env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        wait_for(lambda: nas.first_chunk.is_set() and nas.record()['current_size'] == 3073,
                 f'{mode}: restore never reached durable partial checkpoint')
        initial = nas.record()
        check(not list(private.glob('service-file-restore-*')), 'restore context persisted on disk')
        nas.events = [dict(id=801, action='update_backup_bandwidth'),
                      dict(id=802, action='act_client', webapi_task=dict(
                          event_id=802, subaction='list_nodes', node_path=str(nas.picker), dir_only=1)),
                      dict(id=803, action='act_client', webapi_task=dict(
                          event_id=803, subaction='list_nodes', node_path='', dir_only=1))]
        wait_for(lambda: set(nas.done) == {801, 802, 803}, f'{mode}: controls stalled behind get_file')
        check(not nas.release.is_set() and not nas.complete, 'fixture released work before control ACK')
        current = nas.record()
        check(current['current_size'] == initial['current_size'] and current['phase'] == 'download',
              'control events corrupted active journal')
        check(nas.query_count == 1, 'bandwidth event repeated query after ACK')
        if mode == 'lost-reply':
            wait_for(lambda: len(nas.downloads) == 2, 'picker failure did not resume transfer')
        for portal_mode in ('success', 'missing', 'error', 'empty'):
            nas.portal_mode = portal_mode
            visible = subprocess.run([exe, '--status'], env=env, capture_output=True,
                                     text=True, timeout=5)
            portal = 'https://fixture.invalid/recovery' if portal_mode == 'success' else (
                '' if portal_mode == 'empty' else ' - ')
            check(visible.returncode == 0 and not visible.stderr and
                  f'Recovery portal: {portal}\n\n' in visible.stdout and
                  'Service Status: Restoring...' in visible.stdout and
                  visible.stdout.endswith('Retrieved service status successfully\n'),
                  'held-transfer status/portal output differs from official agent')
        directory = [r for r in nas.replies if r['event_id'] == 802]
        check(directory[0]['node_list'] == [dict(name='original', path=str(nas.picker/'original'), is_dir=1)],
              'directory picker result differs')
        if mode == 'lost-reply':
            check(len(directory) == 2 and directory[0] == directory[1], 'lost reply changed saved listing')
        if mode in ('normal', 'incomplete', 'result-lost-query', 'result-lost-ack'):
            nas.events = [dict(id=804, action='get_running_task_result', task_id=2, version_id=9)]
            if mode not in ('normal', 'incomplete'):
                check(nas.result_lost.wait(8), 'result failure was not exercised while held')
                process.kill()
                process.communicate(timeout=5)
                pending = next(r for r in nas.inbox()['receipts'] if r['payload']['id'] == 804)
                check(pending['state'] == ('pending' if mode == 'result-lost-query' else 'ack_pending'),
                      'result transport failure lost durable receipt state')
                # A resumed restore registers its result ID again when it starts
                # downloading. Keep the restore off the NAS job list until the
                # retained event is answered, so the query shows whether restart
                # recovered any running history from disk.
                nas.hold_running = mode == 'result-lost-query'
                process = subprocess.Popen([exe, 'service', 'run'], env=env, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
            wait_for(lambda: 804 in nas.done and not any(
                r['payload']['id'] == 804 for r in nas.inbox()['receipts']),
                'result event was blocked behind held transfer')
            status = subprocess.run([exe, '--status', '--skip-portal'], env=env, capture_output=True,
                                    text=True, timeout=5)
            check(status.returncode == 0, status.stdout+status.stderr)
            if mode == 'normal':
                check('Service Status: Idle - Failed\n' in status.stdout,
                      'visible status ignored the active result or used its restore outcome as backup summary')
            elif mode == 'incomplete':
                check('Service Status: Restoring...' in status.stdout,
                      'incomplete result reset visible transfer status')
            check(nas.result_queries[0]['result_id'] == 112, 'active running history lost exact result ID')
            if mode in ('normal', 'incomplete'):
                check(nas.record()['phase'] == 'download' and nas.record()['current_size'] == 3073,
                      'result observation changed transfer phase or checkpoint')
                nas.advance.set()
                wait_for(lambda: nas.record()['current_size'] == 6000, 'transfer did not save after result ACK')
                check(nas.record()['phase'] == 'download', 'result observation prematurely completed transfer')
                nas.events = [dict(id=805, action='get_running_task_result', task_id=2, version_id=9)]
                wait_for(lambda: 805 in nas.done, 'no-match result event stalled while held')
                check('result_id' not in nas.result_queries[-1],
                      'progress save re-registered history retired by the result handler')
            elif mode == 'result-lost-query':
                check(len(nas.result_queries) == 2 and 'result_id' not in nas.result_queries[-1],
                      'restart invented process-local running history after a lost query reply')
                check(len(nas.downloads) == 1, 'restore resumed while the NAS listed no running job')
                nas.hold_running = False
                nas.events = [dict(id=806, action='update_running_task')]
            else:
                check(len(nas.result_queries) == 1, 'ack-pending restart repeated immutable result query')
        if mode == 'reload':
            result = subprocess.run([exe, '--reload', '-q'], env=env, capture_output=True, text=True, timeout=8)
            check(result.returncode == 0, result.stdout+result.stderr)
            wait_for(lambda: len(nas.downloads) == 2, 'reload failed to resume exact run')
        if mode == 'logout':
            result = subprocess.run([exe, '--logout', '-q', '--username', 'admin',
                                     '--password', 'fixture-password'], env=env, capture_output=True,
                                    text=True, timeout=15)
            check(result.returncode == 0, result.stdout + result.stderr)
            wait_for(lambda: nas.unlinked, 'active restore blocked authorized unlink')
            out, err = process.communicate(timeout=5)
            check(process.returncode == 0, out + err)
            check('check_complete' not in nas.requests and not nas.ack_attempts,
                  'logout invented a restore completion/cancellation request')
            check(not list(private.glob('service-file-restore-*')),
                  'logout depended on a durable restore journal')
            return
        if mode == 'cancel':
            nas.cancel = True
            wait_for(lambda: nas.record()['phase'] == 'cancel', 'NAS cancel failed while controls active')
            check(nas.requests.count('check_complete') == 0, 'NAS cancellation repeated completion')
        else:
            if mode in ('lost-reply', 'result-lost-query', 'result-lost-ack'):
                wait_for(lambda: len(nas.downloads) == 2, 'control failure did not resume transfer')
            nas.release.set()
            wait_for(lambda: nas.complete and nas.record()['phase'] == 'complete', f'{mode}: restore did not complete')
            check((nas.destination/'partial.bin').read_bytes() == nas.payload, 'restored contents differ')
            check(len(nas.ack_attempts) == 1 and nas.requests.count('check_complete') == 1,
                  'control failure/reload repeated completed restore work')
            if mode in ('normal', 'incomplete'):
                check(len(nas.result_queries) == 2,
                      'retained result query repeated or lost exact running history')
        process.send_signal(signal.SIGTERM)
        out, err = process.communicate(timeout=5)
        check(process.returncode == 0, out+err)
        check(not nas.inbox()['receipts'], 'completed control receipts retained')
        check(len(nas.downloads) == (2 if mode in (
            'reload', 'lost-reply', 'result-lost-query', 'result-lost-ack') else 1), 'duplicate restore dispatched')
        expected_init = [1, 1] if mode in ('result-lost-query', 'result-lost-ack') else (
            [1, 0] if mode in ('reload', 'lost-reply') else [1])
        check(nas.initializations == expected_init, 'token auth init did not identify process lifetime')
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
        nas.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    parser.add_argument('openssl')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='opensabba-active-events-') as temporary:
        root = Path(temporary)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '1',
            '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
            '-addext', 'subjectAltName=IP:127.0.0.1'], check=True, capture_output=True)
        for mode in ('normal', 'incomplete', 'reload', 'cancel', 'lost-reply', 'result-lost-query',
                     'result-lost-ack', 'logout'):
            run_case(str(Path(args.executable).resolve()), root/mode, cert, key, mode)
        print('Active restore controls, immutable replay, reload and cancellation passed.')


if __name__ == '__main__':
    main()
