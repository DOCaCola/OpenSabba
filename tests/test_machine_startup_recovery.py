"""Cold-start retirement and NAS checkpoint decision through production commands.

All block-device/driver operations are interposed; the NAS is loopback TLS.
There is deliberately no machine-discovery fixture: retired snapshot ownership
must not depend on the current kernel disk names or LVM display mappings.
"""
import copy
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from test_backup_cli import Reader, Server
from test_login import value
from test_machine_pending_recovery import write
from test_probe import check, wire
from test_service import wait_for
from test_snapshot import filesystem
from machine_service_specimens import machine_disk, machine_plan, lvm_disk
from snapshot_service_fixture import SnapshotSources


class RecoveryNas(Server):
    def __init__(self, root, cert, key, checkpoint, active=False):
        self.checkpoint, self.active = checkpoint, active
        self.logs = []
        self.done = threading.Event()
        self.recovery_query = threading.Event()
        self.recovery_queries = 0
        super().__init__(root, cert, key, b'', 'success')

    def handle(self, peer):
        try:
            with peer:
                peer.settimeout(8)
                check(value(peer)['action'] == 'encrypt_channel', 'missing TLS')
                peer.sendall(wire({}))
                with self.tls.wrap_socket(peer, server_side=True) as tls:
                    req = value(tls)
                    action, op = req['action'], req.get('subaction', req['action'])
                    self.requests.append(op)
                    if action == 'query_server_info':
                        reply = dict(ds_id='test-nas')
                    elif action == 'auth':
                        reply = dict(ds_id='test-nas', token='test-token')
                    elif action == 'get_timezone':
                        reply = dict(timezone='0', epoch=str(int(time.time())))
                    elif action == 'get_task':
                        reply = dict(task_list=[dict(id=2, name='Recovery fixture', compression=0, encryption=1,
                            task_uuid='fixture-task', source_type=3, backup_external=1,
                            custom_volume=['/', '/data'])])
                    elif action == 'get_running_task':
                        # The exact event remains present for recovery. Withhold
                        # new queue work once that decision has been persisted;
                        # this fixture does not simulate a new acquisition.
                        recovering = bool(req.get('check_backup_exist'))
                        running = dict(id=27, type=0, task_id=2, status=2,
                            detail_status=6, version_id=9 if self.checkpoint else 0,
                            result_id=112, is_backing_up=int(self.active),
                            backup_task=dict(data_format=1, error_code=0, is_cbt=0,
                                             base_version_id=0, resume_info=self.checkpoint))
                        reply = dict(running_task_list=[running] if recovering else [])
                        if recovering:
                            self.recovery_queries += 1
                            self.recovery_query.set()
                    elif action == 'get_running_task_result':
                        reply = {} if 'result_id' not in req else dict(running_task_result=dict(
                            task_id=2, result_id=112, job_action='backup', status='incomplete'))
                    elif action in ('heart_beat', 'pull_event'):
                        reply = dict(event_list=[]) if action == 'pull_event' else {}
                    elif action == 'long_poll':
                        self.stopped.wait(.05)
                        reply = dict(has_event=0)
                    elif action == 'get_backup_bandwidth':
                        reply = dict(backup_bandwidth=0)
                    elif op == 'get_base_version':
                        reply = dict(base_version_id=0)
                    elif op == 'update_backup_task':
                        check(bool(self.checkpoint) and req['running_task_id'] == 27,
                              'snapshot loss without checkpoint allocated a failed version')
                        reply = dict(running_task_id=27, version_id=9, result_id=112, data_format=1)
                    elif action == 'log_report':
                        self.logs.extend(req['logs'])
                        reply = {}
                    elif op == 'check_complete':
                        check(self.checkpoint and req['running_task_id'] == 27 and
                              req['result_id'] == 112 and
                              req['status'] == 'error', 'recovery changed event/version/outcome')
                        self.done.set()
                        reply = dict(status='error')
                    else:
                        raise AssertionError(f'unexpected recovery request {action}:{op}')
                    tls.sendall(wire(reply))
        except (EOFError, ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionError):
            pass
        except Exception as error:
            self.errors.append(repr(error))


def main():
    exe, driver, openssl, fixture = sys.argv[1:5]
    with tempfile.TemporaryDirectory(prefix='machine-startup-recovery-') as temporary:
        root = Path(temporary)
        part = filesystem(root)
        primary, boot, boot_size, root_at = machine_disk(part)
        plan = machine_plan(primary, boot, boot_size, root_at, len(part))
        pv, lv_data, pv_plan, lv, group = lvm_disk(root)
        plan.update(other_disk_count=1, selected_extra=[lv], additional_disks=[pv_plan],
                    lvm=dict(volume_groups=[group], selected_lvs=[lv]))
        sources = SnapshotSources(root)
        journal, capture = sources.capture(plan, primary, pv, {lv['image_name']: lv_data})
        artifact = copy.deepcopy(journal['artifact'])
        journal.update(boot_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', phase='snapshot-active', artifact=None)
        for reserved in [journal['reservation'], *journal['reservation']['extras']]:
            reserved.pop('filesystem_unused', None)
            reserved.pop('cache_unused', None)
        # Saved segment display strings carry old kernel names. Recovery has no
        # permission to reinterpret this inventory against today's disk names.
        journal['plan']['selected_extra'][0]['segments'][0]['mapping'] = '/dev/sdc2:0-1535'
        # Model the driver after cold boot with no reloaded snapshot slots.
        sources.manifest.write_text('\n'.join(row for row in sources.manifest.read_text().splitlines()
                                             if not row.startswith('snap '))+'\n')
        env = dict(os.environ, LD_PRELOAD=fixture, OPENSABBA_SOURCE_FIXTURE=str(sources.manifest),
                   OPENSABBA_SOURCE_TRACE=str(sources.trace))
        for phase in ('snapshot-active', 'ready'):
            current = copy.deepcopy(journal)
            current['phase'] = phase
            current['artifact'] = artifact if phase == 'ready' else None
            write(capture/'capture.pstream', current)
            (capture/'release.pstream').unlink(missing_ok=True)
            recovered = subprocess.run([exe, 'machine', 'recover', str(capture)], env=env,
                                       capture_output=True, text=True, timeout=10)
            check(recovered.returncode == 0, recovered.stdout+recovered.stderr)
            retired = value(Reader((capture/('release.pstream' if phase == 'ready' else 'capture.pstream')).read_bytes()))
            check(retired['reservation']['snapshot_released'] == 1 and
                  all(extra['released'] == 1 for extra in retired['reservation']['extras']),
                  'cold retirement did not reconcile all absent owned slots')
            check(retired['plan'] == current['plan'] and retired['snapshot'] == current['snapshot'],
                  'retirement rewrote immutable identity/topology')
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '1',
                        '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=IP:127.0.0.1'], check=True, capture_output=True)
        absent_manifest = sources.manifest.read_text()
        for checkpoint, active, deferred in (('', False, False), ('', False, True),
                                             ('', True, False), ('{"disk":{"current":"4096"}}', False, False)):
            current = copy.deepcopy(journal)
            if deferred:
                current.update(phase='recovery-required', failure_disposition='uncertain',
                               failure='earlier cleanup was deferred')
            rows = absent_manifest.splitlines()
            if deferred:
                fields = rows[0].split()
                fields[7] = '1'  # Interposed info ioctl fails with EIO.
                rows[0] = ' '.join(fields)
            sources.manifest.write_text(chr(10).join(rows)+chr(10))
            write(capture/'capture.pstream', current)
            config = root/f'config-{int(bool(checkpoint))}-{int(active)}-{int(deferred)}'
            private = config/'opensabba'
            private.mkdir(parents=True, mode=0o700)
            nas = RecoveryNas(config, cert, key, checkpoint, active)
            machine = dict(format=2, ds_id='test-nas', device_uuid='test-device', username='test-user',
                           task_id=2, task_uuid='fixture-task')
            write(private/'session.pstream', dict(format=2, host='127.0.0.1', port=nas.port,
                ca_file=str(cert), username='test-user', device_uuid='test-device', token='test-token',
                ds_id='test-nas', registration_state='confirmed'))
            pending = private/'service-machine-pending.pstream'
            prepared = copy.deepcopy(current)
            prepared.update(phase='prepared', artifact=None, snapshot=None,
                            failure='', failure_disposition='')
            for reserved in [prepared['reservation'], *prepared['reservation']['extras']]:
                for field in ('cow_unused', 'filesystem_unused', 'cache_unused', 'changes',
                              'previous_capture_id', 'previous_directory'):
                    reserved.pop(field, None)
            prepared['reservation'].update(snapshot_attempted=0, snapshot_released=0, snapshot_time=0)
            for extra in prepared['reservation']['extras']:
                extra.update(attempted=0, released=0, snapshot=None)
            write(pending, dict(task_owner=machine, run=27, task_uuid='fixture-task', capture=prepared))
            process = subprocess.Popen([exe, 'service', 'run'], env=dict(env, XDG_CONFIG_HOME=str(config)),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                check(nas.recovery_query.wait(10), f'recovery did not consult the same NAS event: {nas.errors}')
                if active:
                    # official agent defers the same event while the NAS worker is
                    # active; the independent long-poll worker remains active.
                    wait_for(lambda: nas.recovery_queries >= 2, 'active worker did not defer and retry the event')
                    wait_for(lambda: 'long_poll' in nas.requests, 'active worker deferral suppressed independent long-poll')
                else:
                    wait_for(lambda: not pending.exists(), 'startup recovery did not retire pending ownership')
                process.send_signal(signal.SIGTERM)
                out, err = process.communicate(timeout=8)
                check(process.returncode == 0 and not nas.errors, out+err+str(nas.errors))
                if active:
                    check(pending.exists(), 'active NAS worker lost pending source ownership')
                elif checkpoint:
                    check(nas.done.is_set() and nas.requests.count('update_backup_task') == 1 and
                          nas.requests.count('check_complete') == 1, 'checkpoint failure changed/repeated NAS identity')
                    details = [row['log_type'] for row in nas.logs]
                    check(details.count(7021) == 1, f'missing snapshot activity changed: {details}')
                    check((private/'service-machine-skipped-27.pstream').exists(), 'checkpoint failure was not retired')
                else:
                    check((private/f'machine-aborted-{current["id"]}.pstream').exists(),
                          'interrupted source was not archived before recapture')
                    check(not (private/'service-machine-skipped-27.pstream').exists() and
                          not (private/'backup-job.pstream').exists(), 'recapture consumed the event or invented a version')
                    if deferred:
                        cleanup = private/f'service-machine-cleanup-{current["id"]}.pstream'
                        check(cleanup.exists(), 'recapture dropped ownership of deferred cleanup')
                if not checkpoint:
                    check(not nas.logs and 'update_backup_task' not in nas.requests and
                          'check_complete' not in nas.requests, 'nonfailure recovery reported a failed version/activity')
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=8)
                nas.close()
    print('Cold snapshot retirement, no-checkpoint recapture, worker deferral and checkpoint 7021 passed')


if __name__ == '__main__':
    main()
