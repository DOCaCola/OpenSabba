"""Independent TLS receiver: mixed origin eligibility, NAS clones and resume."""
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from pstream_peer import upload_value, value
from test_probe import check, wire
from test_backup_cache import lz4_block

MIB = 1024 * 1024


def run(driver, cert, key, path, mode):
    disk_size = (10 if mode.startswith('grow') else 6) * MIB
    compressed, restart = 'lz4' in mode, mode.endswith('resume')
    names = ['disk.img', 'keep.img', 'new.img']
    sizes = dict(zip(names, [disk_size, 4*MIB, 4*MIB]))
    expected = {'disk.img': bytearray([0x40])*disk_size,
                'keep.img': bytearray([0xb6])*(4*MIB),
                'new.img': bytearray([0xd7])*(4*MIB)}
    expected['disk.img'][2*MIB:3*MIB] = bytes([0xa5])*MIB
    expected['keep.img'][2*MIB:2*MIB+65536] = bytes([0xcc])*65536
    expected['new.img'][MIB:2*MIB] = bytes(MIB)
    # Match NAS clone-by-name, retaining the base's old physical length until
    # current geometry finalization. A renamed image has no clone at all.
    targets = {'disk.img': bytearray([0x40])*(8*MIB),
               'keep.img': bytearray([0xb6])*(4*MIB),
               'new.img': bytearray([0xee])*(4*MIB)}
    targets['disk.img'][MIB:2*MIB] = bytes([0x44])*MIB
    if disk_size > len(targets['disk.img']):
        targets['disk.img'].extend(bytes(disk_size-len(targets['disk.img'])))
    errors, actions, threads = [], [], []
    offsets = dict.fromkeys(names, 0)
    uploads = finishes = metadata = 0
    stopped = threading.Event()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)

    def apply(block, name, at):
        length = block['length']
        check(block['image_name'] == name and block['offset'] == at and length > 0 and at+length <= sizes[name],
              'wrong image correspondence or coverage')
        used = not (name == 'new.img' and MIB <= at < 2*MIB)
        if name == 'disk.img':
            cbt = 4*MIB <= at < 5*MIB
            changed = not cbt
            boundary = 4*MIB if at < 4*MIB else 5*MIB if cbt else disk_size
        elif name == 'keep.img':
            cbt = True
            changed = 2*MIB <= at < 2*MIB+65536
            boundary = next(x for x in (2*MIB, 2*MIB+65536, 4*MIB) if x > at)
        else:
            cbt, changed = False, True
            boundary = MIB if at < MIB else 2*MIB if not used else 4*MIB
        check(at+length <= boundary and block['used'] == int(used) and
              block['changed'] == int(changed) and block['is_interval_cbt'] == int(cbt),
              'official agent interval flags or query boundaries differ')
        check(length <= (65536 if cbt else MIB), 'wrong context query size')
        if used and changed:
            payload = block['buffer']
            if compressed:
                check(block.get('compressed') == 1, 'missing LZ4 flag')
                payload = lz4_block(payload, length)
            check(payload == expected[name][at:at+length], 'current payload differs')
            targets[name][at:at+length] = payload
        else:
            check('buffer' not in block and block['changed_length'] == 0, 'unused/inherited range carries payload')
            if not used:
                targets[name][at:at+length] = bytes(length)
        return at+length

    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        listener.settimeout(.1)

        def handle(peer):
            nonlocal uploads, finishes, metadata
            try:
                with peer:
                    peer.settimeout(10)
                    check(value(peer)['action'] == 'encrypt_channel', 'missing TLS negotiation')
                    peer.sendall(wire({}))
                    with context.wrap_socket(peer, server_side=True) as tls:
                        request = value(tls)
                        action, op = request['action'], request.get('subaction', '')
                        actions.append(action+':'+op)
                        if action == 'query_server_info':
                            reply = {'ds_id': 'test-nas'}
                        elif action == 'client_trigger':
                            if op == 'get_base_version':
                                reply = dict(base_version_id=8)
                            else:
                                check(op == 'update_backup_task' and request['is_cbt'] == 1 and
                                      request['base_version_id'] == 8, 'mixed run lost its NAS base')
                                reply = dict(running_task_id=27, version_id=9, result_id=112, data_format=1)
                        elif action == 'get_running_task_result':
                            reply = {'running_task_result': dict(task_id=2, result_id=112,
                                     job_action='backup', status='incomplete')}
                        elif action == 'get_running_task':
                            check(restart and uploads == 1, 'unexpected checkpoint query')
                            reply = {'running_task_list': [dict(id=27, type=0, task_id=2,
                                version_id=9, result_id=112, status=2, detail_status=6,
                                is_backing_up=0, backup_task=dict(error_code=0, is_cbt=1,
                                base_version_id=8, resume_info=json.dumps({name: dict(current=str(at),
                                transfer_current=str(at)) for name, at in offsets.items()})))]}
                        elif action == 'backup' and op == 'update_device_spec':
                            metadata += 1
                            check('is_cbt' not in json.loads(request['snapshot_info']), 'mutable completion CBT in initial metadata')
                            reply = {}
                        elif action == 'backup' and op == 'upload_block':
                            uploads += 1
                            check(request['resume'] == int(uploads == 2), 'wrong upload restart policy')
                            tls.sendall(wire(dict(success=1)))
                            for name in names:
                                at = offsets[name]
                                while at < sizes[name]:
                                    at = apply(upload_value(tls), name, at)
                                    offsets[name] = at
                                    if restart and uploads == 1 and name == 'new.img' and at == MIB:
                                        return
                            check(upload_value(tls) == {'close': 1}, 'missing upload close')
                            reply = {'close': 1}
                        elif action == 'backup' and op == 'check_complete':
                            check(request['is_cbt'] == 0 and request['status'] == 'complete' and
                                  all(offsets[name] == sizes[name] for name in names), 'completion lost actual context outcomes')
                            finishes += 1
                            reply = {'status': 'complete'}
                        else:
                            raise AssertionError(f'unexpected request {action}:{op}')
                        tls.sendall(wire(reply))
            except Exception as error:
                errors.append(repr(error))

        def serve():
            while not stopped.is_set():
                try:
                    peer, _ = listener.accept()
                except socket.timeout:
                    continue
                thread = threading.Thread(target=handle, args=(peer,))
                threads.append(thread)
                thread.start()

        server = threading.Thread(target=serve)
        server.start()
        try:
            result = subprocess.run([driver, str(listener.getsockname()[1]), str(cert), mode, str(path)],
                                    capture_output=True, text=True, timeout=30)
            check(result.returncode == 0, f'{mode}: {result.stdout} {result.stderr}; {actions}; {errors}')
        finally:
            stopped.set()
            server.join(2)
            for thread in threads:
                thread.join(11)
    check(not errors and uploads == (2 if restart else 1) and finishes == metadata == 1,
          f'{mode}: incomplete lifecycle {errors} {actions}')
    for name in names:
        del targets[name][sizes[name]:]
        check(targets[name] == expected[name], f'{name}: independent NAS reconstruction differs')


def main():
    with tempfile.TemporaryDirectory(prefix='opensabba-interval-transfer-') as temporary:
        root = Path(temporary)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([sys.argv[2], 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       capture_output=True, check=True)
        for mode in ('shrink-raw', 'grow-lz4', 'shrink-lz4-resume', 'grow-raw-resume'):
            run(str(Path(sys.argv[1]).resolve()), cert, key, root/(mode+'.pstream'), mode)
    print('PASS mixed image/origin raw/LZ4, grow/shrink and immutable checkpoint resume')


if __name__ == '__main__':
    main()
