"""Native service: independently reconstructed images across target changes."""
import copy
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from test_backup_cli import Server, Reader
from test_probe import check, wire
from test_login import value
from test_service import wait_for
from test_snapshot import filesystem
from test_layout import mbr_entry
from machine_service_specimens import machine_disk, machine_plan, lvm_disk
from snapshot_service_fixture import SnapshotSources
from pstream_peer import upload_value
from automatic_machine_service import provide_capture, catalog_snapshot, no_snapshot_before_handshake

MIB = 1024*1024


class Nas(Server):
    def __init__(self, root, cert, key, automatic_catalog=False):
        self.step = 0
        self.task_id, self.task_uuid = 2, "fixture-task"
        self.result_tasks = {}
        self.complete = False
        self.specs = []
        self.expected = {}
        self.targets = {}
        self.names = []
        self.unused = {}
        self.fallback = {}
        self.new_names = set()
        self.completion_cbt = False
        self.mounts = []
        self.finished = threading.Event()
        self.interrupted = threading.Event()
        self.pause_drop = threading.Event()
        self.offsets = {}
        self.allow_initial_base_query = automatic_catalog
        self.automatic_catalog = automatic_catalog
        self.prepared_runs = set()
        self.long_poll_started = threading.Event()
        self.run_available = True
        self.task_fields = {}
        self.script_logs = []
        self.before_task = lambda: None
        self.long_poll_wait = self.stopped_wait
        self.events, self.done = [], []
        self.compressed_blocks = 0
        self.plaintext_uploads = 0
        self.expected_failure = False
        super().__init__(root, cert, key, b'', 'success')

    def stopped_wait(self, seconds):
        return self.stopped.wait(seconds)

    def select(self, expected, unused, fallback, completion_cbt, mounts):
        previous = self.targets
        self.new_names = set(expected)-set(previous)
        self.targets = {}
        for name, data in expected.items():
            old = previous.get(name, bytearray([0xee])*len(data))
            self.targets[name] = bytearray(old[:len(data)])
            self.targets[name].extend(bytes(len(data)-len(self.targets[name])))
        self.expected, self.unused, self.fallback = expected, unused, fallback
        self.names = list(expected)
        self.completion_cbt, self.mounts = completion_cbt, mounts
        self.complete = False
        self.finished.clear()
        self.interrupted.clear()
        self.pause_drop.clear()
        self.offsets = {name: 0 for name in expected}
        self.step += 1
        self.run_id = 26+self.step
        self.result_tasks[13+self.step] = self.task_id

    def handle(self, peer):
        try:
            with peer:
                peer.settimeout(15)
                first = value(peer)
                encrypted = first['action'] == 'encrypt_channel'
                if encrypted:
                    peer.sendall(wire({}))
                channel = self.tls.wrap_socket(peer, server_side=True) if encrypted else peer
                with channel as tls:
                    req = value(tls) if encrypted else first
                    if not encrypted:
                        check(req['action'] == 'backup' and req.get('subaction') == 'upload_block' and
                              self.task_fields.get('encryption',1) == 0, 'plaintext control or encrypted-task upload')
                        self.plaintext_uploads += 1
                    action, op = req['action'], req.get('subaction', req['action'])
                    self.requests.append(op)
                    if action == 'query_server_info':
                        reply = dict(ds_id='test-nas')
                    elif action == 'auth':
                        reply = dict(ds_id='test-nas', token='test-token')
                    elif action == 'get_timezone':
                        reply = dict(timezone='0', epoch=str(int(time.time())))
                    elif action == 'get_task':
                        self.before_task()
                        task = dict(id=2, name='Interval fixture', compression=0, encryption=1,
                            task_uuid='fixture-task', source_type=3, backup_external=1,
                            custom_volume=self.mounts)
                        task.update(self.task_fields)
                        reply = dict(task_list=[dict(task,id=7,task_uuid='other-task'),task])
                    elif action == 'get_running_task':
                        prepared = self.run_id in self.prepared_runs
                        running = dict(id=self.run_id, type=0, task_id=self.task_id, status=int(prepared),
                            version_id=8+self.step if prepared else 0, result_id=13+self.step if prepared else 0,
                            is_backing_up=0, backup_task=dict(data_format=1, error_code=0, resume_info=''))
                        if self.interrupted.is_set():
                            running.update(status=2, detail_status=6, is_backing_up=0,
                                backup_task=dict(data_format=1, error_code=0, is_cbt=1,
                                    base_version_id=7+self.step,
                                    resume_info=json.dumps({name: dict(current=str(at), transfer_current=str(at))
                                                            for name, at in self.offsets.items()})))
                        reply = dict(running_task_list=[running] if self.run_available and not self.complete else [])
                    elif action == 'get_running_task_result':
                        reply = {} if 'result_id' not in req else dict(running_task_result=dict(task_id=self.result_tasks.get(req['result_id'],2), result_id=req['result_id'],
                            job_action='backup', status=('failure' if self.expected_failure else 'complete') if req['result_id'] < 13+self.step or self.complete else 'incomplete'))
                    elif action in ('heart_beat',):
                        reply = {}
                    elif action == 'get_backup_bandwidth':
                        reply = dict(backup_bandwidth=0)
                    elif action == 'pull_event':
                        reply = dict(event_list=[e for e in self.events if e['id'] not in req['event_list']])
                    elif action == 'done_event':
                        self.done.extend(req['done_events'])
                        self.events = [e for e in self.events if e['id'] not in self.done]
                        reply = {}
                    elif action == 'long_poll':
                        check(req['timeout'] == 400, 'long-poll subscription differs from official agent')
                        self.long_poll_started.set()
                        self.long_poll_wait(60 if self.automatic_catalog else .2)
                        reply = dict(has_event=int(bool(self.events)))
                    elif op == 'get_base_version':
                        check(self.step > 1 or self.allow_initial_base_query, 'first capture queried a base')
                        reply = dict(base_version_id=7+self.step if self.step > 1 else 0)
                    elif op == 'update_backup_task':
                        check(set(req) == {'action','subaction','agent','token','ds_id','running_task_id',
                              'base_version_id','is_cbt','is_cache','check_point_backup'} and
                              req['running_task_id'] == self.run_id and req['is_cbt'] == int(self.step > 1 and self.task_id == 2) and
                              req['base_version_id'] == (7+self.step if self.step > 1 and self.task_id == 2 else 0),
                              'one changed origin discarded the NAS base')
                        check(self.run_id not in self.prepared_runs, 'automatic capture repeated its NAS handshake')
                        if self.automatic_catalog:
                            no_snapshot_before_handshake(self.root,self.run_id)
                        self.prepared_runs.add(self.run_id)
                        reply = dict(running_task_id=self.run_id, version_id=8+self.step,
                                     result_id=13+self.step, data_format=1)
                    elif op == 'update_device_spec':
                        if self.automatic_catalog:
                            check(self.long_poll_started.wait(3), 'capture suppressed the independent long-poll worker')
                            catalog_snapshot(self.root,self.run_id,8+self.step,
                                7+self.step if self.step > 1 and self.task_id == 2 else 0,self.task_uuid)
                        spec = json.loads(req['snapshot_info'])
                        self.specs.append(spec)
                        check('is_cbt' not in spec and [i['image_name'] for i in spec['device_spec']['images']] == self.names,
                              'current image inventory or initial metadata differs')
                        check([int(i['length']) for i in spec['device_spec']['images']] ==
                              [len(data) for data in self.expected.values()], 'current image geometry differs')
                        reply = {}
                    elif op == 'upload_block':
                        tls.sendall(wire(dict(success=1)))
                        for name in self.names:
                            at = self.offsets[name]
                            while at < len(self.expected[name]):
                                block = upload_value(tls)
                                size = block['length']
                                end = at+size
                                check(block['image_name'] == name and block['offset'] == at and end <= len(self.expected[name]),
                                      'image mapped to wrong base or extent')
                                used = not any(a <= at and end <= b for a, b in self.unused[name])
                                cbt = self.step > 1 and self.task_id == 2 and name not in self.new_names and not any(
                                    a <= at and end <= b for a, b in self.fallback[name])
                                check(block['used'] == int(used) and block['is_interval_cbt'] == int(cbt),
                                      f'wrong interval context: {name} {at} {size} {block["is_interval_cbt"]}')
                                if not cbt:
                                    check(block['changed'] == 1, 'fallback inherited unavailable base bytes')
                                if used and block['changed']:
                                    payload = block['buffer']
                                    if block.get('compressed'):
                                        from lz4_receiver import decode_block
                                        payload = decode_block(payload,size)
                                        self.compressed_blocks += 1
                                    check(payload == self.expected[name][at:end], 'wrong current source bytes')
                                    self.targets[name][at:end] = payload
                                else:
                                    check('buffer' not in block, 'inherited/unused data was read')
                                    if not used:
                                        self.targets[name][at:end] = bytes(size)
                                at = end
                                self.offsets[name] = at
                                if self.step == 4 and name == self.names[0] and at >= 12*MIB and not self.interrupted.is_set():
                                    self.interrupted.set()
                                    self.pause_drop.wait(15)
                                    return
                        check(upload_value(tls) == dict(close=1), 'missing upload close')
                        reply = dict(close=1)
                    elif op == 'check_complete':
                        check(req['is_cbt'] == int(self.completion_cbt), 'completion lost actual CBT outcome')
                        if self.expected_failure:
                            check(req['status'] == 'error' and 'upload_block' not in self.requests and
                                  'update_device_spec' not in self.requests,
                                  'terminal script failure uploaded a ready capture')
                        else:
                            check(all(self.targets[name] == data for name, data in self.expected.items()),
                                  'NAS reconstruction inherited wrong coordinates or image')
                        self.complete = True
                        self.finished.set()
                        reply = dict(status='error' if self.expected_failure else 'complete')
                    elif action == 'log_report' and self.task_fields:
                        check(op == 'result_detail' and len(req['logs']) == 1,
                              'unexpected retained-script reporting')
                        log = req['logs'][0]
                        check(log['log_type'] in ((7045, 7051) if self.expected_failure else (7045,)) and log['running_task_id'] == self.run_id,
                              'aborted post reported an outcome')
                        self.script_logs.append(log)
                        reply = {}
                    else:
                        raise AssertionError(f'unexpected action {action}:{op}')
                    tls.sendall(wire(reply))
        # Each stage deliberately stops its service, which can close an idle
        # poll either with TLS close_notify or without a final TLS record.
        except (EOFError, ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as error:
            self.errors.append(repr(error))


def main():
    exe, openssl, fixture = sys.argv[1:4]
    with tempfile.TemporaryDirectory(prefix='opensabba-service-interval-') as temporary:
        root = Path(temporary)
        part = filesystem(root)
        primary, boot, boot_size, root_offset = machine_disk(part)
        base_plan = machine_plan(primary, boot, boot_size, root_offset, len(part))
        pv, lv_a_data, pv_plan, lv_a, group = lvm_disk(root)
        lv_b_file = root/'other.ext4'
        with lv_b_file.open('wb') as stream:
            stream.truncate(4*MIB)
        other_uuid = '42345678-1234-5678-9abc-123456789abc'
        subprocess.run([shutil.which('mke2fs') or '/usr/sbin/mke2fs', '-q', '-t', 'ext4',
                        '-F', '-b', '4096', '-U', other_uuid, str(lv_b_file)],
                       check=True, capture_output=True)
        lv_b_data = lv_b_file.read_bytes()
        lv_b = dict(lv_a, lv_name='other', lv_uuid=group['logical_volumes'][1]['uuid'],
                    image_name='fixture_vg=other.img', length=len(lv_b_data), mount_path='/other',
                    filesystem_uuid=other_uuid, logical_path='/dev/fixture_vg/other',
                    segments=[dict(logical_offset=0, length=len(lv_b_data),
                                   pv_uuid=lv_a['segments'][0]['pv_uuid'], pv_offset=9*MIB)])
        group['logical_volumes'][1].update(name='other', file_system='ext4')
        sources = SnapshotSources(root)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '1',
                        '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=IP:127.0.0.1'], check=True, capture_output=True)
        config = root/'config'
        private = config/'opensabba'
        private.mkdir(parents=True, mode=0o700)
        nas = Nas(config, cert, key, automatic_catalog=True)
        session = dict(format=2, host='127.0.0.1', port=nas.port, ca_file=str(cert),
                       username='test-user', device_uuid='test-device', token='test-token',
                       ds_id='test-nas', registration_state='confirmed')
        saved = private/'session.pstream'
        saved.write_bytes(wire(session))
        saved.chmod(0o600)
        env = dict(os.environ, XDG_CONFIG_HOME=str(config), LD_PRELOAD=fixture,
                   OPENSABBA_SOURCE_FIXTURE=str(sources.manifest),
                   OPENSABBA_SOURCE_TRACE=str(sources.trace))
        previous = None
        process = None
        try:
            for stage in range(7):
                if stage == 6:
                    nas.task_id, nas.task_uuid = 7, "other-task"
                plan = copy.deepcopy(base_plan)
                selected_a = copy.deepcopy(lv_a)
                current_group = copy.deepcopy(group)
                if stage:
                    selected_a.update(lv_name='renamed', image_name='fixture_vg=renamed.img',
                                      logical_path='/dev/fixture_vg/renamed')
                    current_group['logical_volumes'][0]['name'] = 'renamed'
                selected = ([copy.deepcopy(lv_b), selected_a] if stage == 1 else
                            [selected_a, copy.deepcopy(lv_b)] if stage == 2 else [selected_a])
                current_primary = bytearray(primary)
                root_at = root_offset
                if stage >= 3:
                    # Grow the containing image and move just one filesystem;
                    # the FAT sibling and selected LV retain their contexts.
                    root_at = 11*MIB
                    current_primary = bytearray((34 if stage == 3 else 32)*MIB)
                    current_primary[:9*MIB] = primary[:9*MIB]
                    current_primary[root_at:root_at+len(part)] = part
                    current_primary[462:478] = mbr_entry(0x83, root_at//512, len(part)//512)
                    swap_at = root_at+len(part)+MIB
                    current_primary[478:494] = mbr_entry(0x82, swap_at//512, 4*MIB//512)
                    plan = machine_plan(current_primary, boot, boot_size, root_at, len(part))
                plan.update(other_disk_count=1, selected_extra=selected,
                            additional_disks=[copy.deepcopy(pv_plan)],
                            lvm=dict(volume_groups=[current_group], selected_lvs=copy.deepcopy(selected)))
                primary_name = 'sdb.img' if stage >= 5 else 'sda.img'
                logical = {selected_a['image_name']: lv_a_data, lv_b['image_name']: lv_b_data}
                journal, capture = sources.capture(plan, bytes(current_primary), pv, logical)
                if stage >= 5:
                    # A real discovered device identity derives a new image name.
                    journal['plan']['disk'] = '/dev/sdb'
                    sources.manifest.write_text(sources.manifest.read_text().replace('raw /dev/sda ', 'raw /dev/sdb '))
                read_mark = sources.read_mark()
                expected = {primary_name: bytes(current_primary), 'sdc.img': pv}
                expected.update((entry['image_name'], logical[entry['image_name']]) for entry in selected)
                unused = {primary_name: [(root_at+len(part)+MIB, root_at+len(part)+5*MIB)],
                          'sdc.img': [(MIB, 17*MIB)]}
                unused.update((entry['image_name'], []) for entry in selected)
                fallback = {name: [] for name in expected}
                if stage == 3:
                    fallback[primary_name] = [(root_at, root_at+len(part))]
                nas.select(expected, unused, fallback, stage in (2, 4),
                           ['/', '/data']+(['/other'] if stage in (1, 2) else []))
                capture = provide_capture(env,sources,capture,dict(source_type=3,custom_volume=nas.mounts))
                process = subprocess.Popen([exe, 'service', 'run'], env=env, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
                if stage == 3:
                    check(nas.interrupted.wait(15), f'moved-origin interruption missing: {nas.errors}')
                    process.kill()
                    process.communicate(timeout=8)
                    process = None
                    nas.pause_drop.set()
                    job_path = private/'backup-job.pstream'
                    pending = value(Reader(job_path.read_bytes()))
                    check(pending['phase'] == 'upload', 'interrupted plan was not retained')
                    changed = copy.deepcopy(pending)
                    changed['images'][0]['machine_policy']['base_schema'] += 1
                    altered = wire(changed)
                    job_path.write_bytes(altered)
                    actions = (nas.requests.count('upload_block'), nas.requests.count('update_backup_task'))
                    refused = subprocess.run([exe, 'service', 'run'], env=env, capture_output=True,
                                             text=True, timeout=15)
                    check(refused.returncode != 0 and 'retained image plans' in refused.stdout+refused.stderr,
                          'changed pending correspondence was accepted: '+refused.stdout+refused.stderr)
                    check(job_path.read_bytes() == altered and actions == (
                          nas.requests.count('upload_block'), nas.requests.count('update_backup_task')),
                          'changed pending plan mutated the journal or NAS')
                    job_path.write_bytes(wire(pending))
                    process = subprocess.Popen([exe, 'service', 'run'], env=env, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, text=True)
                if not nas.finished.wait(30):
                    process.terminate()
                    out, err = process.communicate(timeout=8)
                    raise AssertionError(f'stage {stage}: {nas.errors} {out} {err}')
                wait_for(lambda: value(Reader((private/'backup-job.pstream').read_bytes()))['phase'] == 'complete',
                         f'stage {stage}: completion not durable')
                record = value(Reader((private/'backup-job.pstream').read_bytes()))
                local = catalog_snapshot(config,nas.run_id,8+nas.step,
                    7+nas.step if 0 < stage < 6 else 0,nas.task_uuid)
                check(local['capture']['id'] == journal['id'], 'service adopted a different OS acquisition')
                check(record['direct_intervals'] == 1 and record['image_sha256'] == '',
                      'fresh target change materialized or hashed snapshot payload')
                check([entry['name'] for entry in record['images']] == list(expected),
                      'saved image order differs from current target')
                if stage == 6:
                    check("incremental" not in record, "second task inherited the first task ancestry")
                elif stage:
                    check(record['incremental']['base_version_id'] == 7+nas.step,
                          'fresh target change discarded the positive NAS base')
                    archive = private/f'backup-job-{previous["running_task_id"]}-{previous["result_id"]}.pstream'
                    check(value(Reader(archive.read_bytes())) == previous,
                          'fresh correspondence changed archived base evidence')
                process.send_signal(signal.SIGTERM)
                out, err = process.communicate(timeout=8)
                check(process.returncode == 0, out+err)
                process = None
                for row in sources.trace.read_text().splitlines()[read_mark:]:
                    kind, path, offset, length = row.split()
                    if kind == 'raw' and path == '/dev/sda':
                        offset, length = int(offset), int(length)
                        check(offset+length <= root_at or offset >= root_at+len(part),
                              'filesystem payload came from the mutable live origin')
                previous = record
                check(not nas.errors, str(nas.errors))
            print('PASS service per-origin/per-image target changes and geometry')
        finally:
            if process and process.poll() is None:
                process.terminate()
                process.communicate(timeout=8)
            nas.close()


if __name__ == '__main__':
    main()
