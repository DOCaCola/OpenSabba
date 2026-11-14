"""Real CLI resumes after durable checkpoints; rejected resumes leave files intact."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from test_restore_cli import Server, Reader
from test_login import value
from test_probe import check, wire
from proxy_peer import Proxy


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    parser.add_argument('openssl')
    parser.add_argument('--proxy', action='store_true')
    args = parser.parse_args()
    exe = str(Path(args.executable).resolve())
    image = bytes(range(256)) * (32768+2)
    cases = ('success', 'renumbered-device', 'prefix-corrupt', 'replacement', 'symlink', 'hardlink', 'truncated',
             'oversized', 'public', 'locked', 'foreign-result', 'terminal-result', 'pending-cancel',
             'missing-checkpoint', 'invalid-offset', 'verified', 'finish', 'checkpoint-failed',
             'offline', 'user-pause', 'cancelled-run', 'unknown-status', 'changed-cancel',
             'changed-result', 'selected-primary-wire', 'selected-secondary')
    if args.proxy:
        cases += ('proxy-reject',)
    with tempfile.TemporaryDirectory(prefix='opensabba-resume-') as temporary:
        root = Path(temporary)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:resume.test.invalid'],
                       check=True, capture_output=True)
        for mode in cases:
            config = root/mode
            private = config/'opensabba'
            private.mkdir(parents=True, mode=0o700)
            initial_mode = 'lost-close' if mode in ('verified', 'finish') else (
                'checkpoint-failed' if mode == 'checkpoint-failed' else 'resume-drop')
            server = Server(config, cert, key, image, initial_mode)
            if mode in ('selected-primary-wire', 'selected-secondary'):
                server.image_name = ('sda.img' if mode == 'selected-primary-wire'
                                     else 'reload-test-disk-1')
            env = dict(os.environ, XDG_CONFIG_HOME=str(config))
            session = dict(format=2, host='127.0.0.1', port=server.port, ca_file=str(cert),
                           username='test-user', device_uuid='test-device', token='test-token',
                           ds_id='test-nas', registration_state='confirmed')
            proxy = None
            if args.proxy:
                proxy = Proxy(server.port)
                proxy.authority = f"resume.test.invalid:{server.port}".encode()
                proxy.credentials = b"resume-user:resume-proxy-secret"
                session.update(host="resume.test.invalid", proxy_host="127.0.0.1", proxy_port=proxy.port,
                               proxy_username="resume-user", proxy_password="resume-proxy-secret")
            backup = dict(schema=1, ds_id='test-nas', username='test-user', device_uuid='test-device',
                          phase='complete', running_task_id=64, task_id=2, version_id=1, result_id=112,
                          data_format=1, image_name='test-image', image_size=len(image),
                          image_sha256=hashlib.sha256(image).hexdigest(),
                          snapshot_info=b'{}', requested_outcome='complete')
            if mode in ('selected-primary-wire', 'selected-secondary'):
                primary = image if mode == 'selected-primary-wire' else b'P' * len(image)
                secondary = b'P' * len(image) if mode == 'selected-primary-wire' else image
                backup.update(schema=4, compression='none',
                              image_name='sda.img',
                              image_size=len(primary), image_sha256=hashlib.sha256(primary).hexdigest(),
                              images=[dict(name='sda.img', size=len(primary),
                                           sha256=hashlib.sha256(primary).hexdigest()),
                                      dict(name='reload-test-disk-1', size=len(secondary),
                                           sha256=hashlib.sha256(secondary).hexdigest())])
            for name, record in [('session', session), ('backup-job', backup)]:
                path = private/(name+'.pstream')
                path.write_bytes(wire(record))
                path.chmod(0o600)
            destination, journal = config/'restored.img', private/'restore-job.pstream'
            def cli(*arguments):
                result = subprocess.run([exe, *arguments], env=env, capture_output=True, text=True, timeout=30)
                check('resume-proxy-secret' not in result.stdout+result.stderr, 'proxy credential leaked')
                return result
            lock = None
            try:
                command = ('restore', 'image', str(destination))
                if mode == 'selected-secondary':
                    command += ('--image-name', 'reload-test-disk-1')
                first = cli(*command)
                check(first.returncode != 0, 'initial download unexpectedly completed')
                private.chmod(0o700)
                record = value(Reader(journal.read_bytes()))
                if mode in ('selected-primary-wire', 'selected-secondary'):
                    check(record['image_name'] == server.image_name and
                          record['image_size'] == len(image) and
                          record['image_sha256'] == hashlib.sha256(image).hexdigest(),
                          'selected image identity not bound to restore checkpoint')
                offset = len(image) if mode in ('verified', 'finish') else (
                    0 if mode == 'checkpoint-failed' else 4*1024*1024)
                check(record['checkpoint']['offset'] == offset, 'incorrect durable offset')
                check(record['checkpoint']['sha256'] == hashlib.sha256(image[:offset]).hexdigest(), 'prefix digest')
                check(record['checkpoint']['inode'] == destination.stat().st_ino, 'file identity not recorded')
                if mode == 'renumbered-device':
                    record['checkpoint']['device'] += 1
                if mode == 'prefix-corrupt':
                    with destination.open('r+b') as out:
                        out.write(b'\xff')
                if mode in ('replacement', 'symlink'):
                    moved = config/'original.img'
                    destination.rename(moved)
                    if mode == 'replacement':
                        destination.write_bytes(moved.read_bytes())
                        destination.chmod(0o600)
                    else:
                        destination.symlink_to(moved)
                if mode == 'hardlink':
                    os.link(destination, config/'alias.img')
                if mode == 'truncated':
                    with destination.open('r+b') as out:
                        out.truncate(offset-512)
                if mode == 'oversized':
                    with destination.open('r+b') as out:
                        out.truncate(len(image)+512)
                if mode == 'public':
                    destination.chmod(0o644)
                if mode == 'locked':
                    lock = destination.open('r+b')
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if mode == 'pending-cancel':
                    record['resolution'] = dict(state='cancel-pending', outcome='cancel')
                if mode == 'missing-checkpoint':
                    del record['checkpoint']
                if mode == 'invalid-offset':
                    record['checkpoint']['offset'] = len(image)+512
                if mode == 'finish':
                    record['phase'] = 'finish'
                journal.write_bytes(wire(record))
                if mode == 'foreign-result':
                    server.result_id = 113
                if mode == 'terminal-result':
                    server.result_status = 'cancel'
                if mode in ('offline', 'user-pause', 'cancelled-run', 'unknown-status'):
                    server.run_status = 2 if mode in ('offline', 'user-pause') else (3 if mode == 'cancelled-run' else 5)
                    server.detail_status = 6 if mode == 'offline' else 7
                if mode in ('changed-cancel', 'changed-result'):
                    server.run_status, server.detail_status = 2, 6
                    server.change_during_range = mode.removeprefix('changed-')
                server.mode = 'success'
                if mode == 'proxy-reject':
                    proxy.response = b"HTTP/1.1 407 Authentication required\r\n\r\n"
                server.range_start = offset
                previous_file, previous_journal = destination.read_bytes(), journal.read_bytes()
                prior_requests = len(server.requests)
                resumed = cli('restore', 'resume')
                good = mode in ('success', 'renumbered-device', 'verified', 'checkpoint-failed', 'offline',
                                'selected-primary-wire', 'selected-secondary')
                check((resumed.returncode == 0) == good, f'{mode}: {resumed.stdout}{resumed.stderr}')
                recent = server.requests[prior_requests:]
                check('image_restore' not in recent, 'resume created a second NAS job')
                if good:
                    check(destination.read_bytes() == image, 'resumed bytes differ')
                    status = json.loads(cli('restore', 'status', '--json').stdout)
                    check(status['phase'] == 'complete' and status['verified'] == 1 and
                          status['downloaded_bytes'] == len(image), 'resume not durably complete')
                    count = (len(image)-offset+1024*1024-1)//(1024*1024)
                    check(recent.count('range') == count, 'resume reread durable ranges')
                    before = len(server.requests)
                    check(cli('restore', 'resume').returncode != 0 and len(server.requests) == before,
                          'terminal restore resumed')
                elif mode in ('changed-cancel', 'changed-result'):
                    check(destination.read_bytes() == image[:offset], 'changed NAS job appended bytes')
                    check(value(Reader(journal.read_bytes()))['checkpoint']['offset'] == offset,
                          'changed NAS job advanced checkpoint')
                    check('check_complete' not in recent, 'changed NAS job completed')
                else:
                    check(destination.read_bytes() == previous_file and journal.read_bytes() == previous_journal,
                          'rejected resume modified file or journal')
                    check('read_image_requests' not in recent and 'check_complete' not in recent,
                          'rejected resume changed NAS restore')
            finally:
                private.chmod(0o700)
                if lock:
                    lock.close()
                if proxy:
                    proxy.close()
                    check(not proxy.errors, str(proxy.errors))
                server.close()
        print(f'{len(cases)} restore resume cases passed')


if __name__ == '__main__':
    main()
