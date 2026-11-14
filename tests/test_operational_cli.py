"""official agent account logout and saved-endpoint editing through the real Linux CLI."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile

from pstream_peer import Reader, value
from test_login import terminal
from test_probe import check, wire
from test_registration import Nas
from test_service import wait_for


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    parser.add_argument('openssl')
    parser.add_argument('source_fixture')
    args = parser.parse_args()
    executable = str(Path(args.executable).resolve())
    with tempfile.TemporaryDirectory(prefix='opensabba-operations-') as directory:
        root = Path(directory)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=IP:127.0.0.1'], check=True, capture_output=True)
        nas, replacement = Nas(cert,key), Nas(cert,key)
        nas.allow_client_disconnect = replacement.allow_client_disconnect = True
        nas.jobs = replacement.jobs = []
        env = dict(os.environ, XDG_CONFIG_HOME=str(root/'config'), TZ='CET-1')
        private = root/'config/opensabba'
        session = private/'session.pstream'
        process = None

        def cli(*options, expected=0, data=None):
            result = subprocess.run([executable,*options],env=env,input=data,capture_output=True,
                                    text=True,timeout=15,start_new_session=True)
            check(result.returncode == expected,result.stdout+result.stderr)
            check('admin-password-837' not in result.stdout+result.stderr,'admin password leaked')
            return result

        def login():
            cli('--connect','-q','-a','127.0.0.1','--port',str(nas.port),'--ca-file',str(cert),
                '-u','test-user','-p','test-password-742')

        admin = ('--username','test-admin','--password','admin-password-837')
        try:
            cli('--logout','-q',*admin,expected=5)
            login()
            before = session.read_bytes()
            count = len(nas.requests)
            cli('--logout','-q',expected=1)
            check(session.read_bytes() == before and len(nas.requests) == count,'quiet logout prompted or sent incomplete credentials')
            nas.admin_mode = 'reject'
            cli('--logout','-q',*admin,expected=3)
            check(session.read_bytes() == before,'admin rejection erased session')
            nas.admin_mode = 'normal'
            code, output = terminal([executable,'--logout'],env,logout_answer='n')
            check(code == 0 and session.read_bytes() == before,'declined logout changed session')
            code, output = terminal([executable,'--logout'],env,logout_answer='',admin=True)
            check(code == 0 and not session.exists(),output)
            check(nas.requests[-1]['action'] == 'unlink_connection','logout omitted NAS unlink')
            check((private/'identity.pstream').exists() and (private/'certificates.pstream').exists(),
                  'logout removed device identity or certificate trust')
            login()
            nas.admin_mode = 'otp'
            code, output = terminal([executable,'--logout'],env,logout_answer='y',admin=True,retry_otp='654321')
            check(code == 0 and not session.exists(),output)
            nas.admin_mode = 'normal'
            login()
            nas.mode = 'unlink-reject'
            cli('--logout','-q',*admin)
            check(not session.exists(),'official agent logout retained credentials after unlink error')
            nas.mode = 'normal'
            login()
            # Model an interrupted capture whose boot topology cannot be
            # rediscovered. No snapshot acquisition was attempted, so this
            # fixture never opens a synosnap slot or a host block device.
            capture_id = 'c'*32
            capture_dir = root/('capture-'+capture_id)
            capture_dir.mkdir(mode=0o700)
            plan = dict(disk=str(root/'missing-disk'),cow_directory=str(root),
                        layout=dict(length=4096,sector_size=512),
                        root=dict(offset=512,length=3584,device=str(root/'missing-root')),
                        boot=dict(device_number='0:0',mount_id=1,mount_path='/boot/firmware',
                                  filesystem='vfat',mount_options='rw',super_options='rw'))
            reservation = dict(raw_directory=str(capture_dir),raw_directory_inode=capture_dir.stat().st_ino,
                               raw_cache_policy=dict(cached_enabled=0),raw_storage_ready=1,
                               directory=str(capture_dir),minor=254,snapshot_time=0,
                               snapshot_attempted=0,snapshot_released=0,extras=[])
            manifest = root/'snapshot-sources.txt'
            manifest.write_text(f'control /dev/synosnap-ctl {root / "missing-control"} 0 0 0 0 0 - - -'+chr(10))
            env.update(LD_PRELOAD=str(Path(args.source_fixture).resolve()),
                       OPENSABBA_SOURCE_FIXTURE=str(manifest))
            reservation['snapshot_attempted'] = 1
            # The acquisition intent atomically includes its sampled NAS time.
            reservation['snapshot_time'] = 1700000000
            capture = dict(schema=5,id=capture_id,
                           boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                           phase='snapshot-intent',plan=plan,reservation=reservation,
                           snapshot=None,artifact=None,failure='',failure_disposition='',logs=[])
            machine = dict(format=2,ds_id=nas.ds_id,device_uuid=value(Reader(session.read_bytes()))['device_uuid'],
                           username='test-user',task_id=2,task_uuid='fixture-task')
            # Pending ownership is the immutable prepared reservation; the
            # separate capture journal records the attempted ioctl's progress.
            reserved = copy.deepcopy(capture)
            reserved['phase'] = 'prepared'
            reserved['reservation']['snapshot_attempted'] = 0
            reserved['reservation']['snapshot_time'] = 0
            pending = dict(task_owner=machine,task_uuid="fixture-task",run=27,capture=reserved)

            def write_private(path, record):
                path.write_bytes(wire(record))
                path.chmod(0o600)

            write_private(capture_dir/'capture.pstream',capture)
            write_private(private/'service-machine-pending.pstream',pending)
            cleanup = private/('service-machine-cleanup-'+capture_id+'.pstream')
            before = session.read_bytes()
            unlinks = sum(r['action'] == 'unlink_connection' for r in nas.requests)
            cli('--logout','-q',*admin,expected=1)
            check(not (private/'service-machine-pending.pstream').exists() and cleanup.exists(),
                  'failed retirement did not transfer durable ownership to cleanup journal')
            check(value(Reader((capture_dir/'capture.pstream').read_bytes()))['phase'] == 'recovery-required',
                  'fixture did not reach resource recovery')
            cli('--logout','-q',*admin,expected=1)
            check(session.read_bytes() == before and cleanup.exists(),
                  'failed or retried retirement erased recovery credentials')
            check(sum(r['action'] == 'unlink_connection' for r in nas.requests) == unlinks,
                  'failed retirement unlinked the NAS')
            retired = value(Reader((capture_dir/'capture.pstream').read_bytes()))
            retired['phase'] = 'aborted'
            retired['reservation']['snapshot_released'] = 1
            write_private(capture_dir/'capture.pstream',retired)
            cli('--logout','-q',*admin)
            check(not session.exists() and not cleanup.exists(),'confirmed retirement did not allow logout')
            login()
            old = value(Reader(session.read_bytes()))
            cli('--reload','-q','--address','',expected=1)
            check(value(Reader(session.read_bytes())) == old,'empty quiet address changed session')
            code, output = terminal([executable,'--reload','--address',''],env,address='127.0.0.1')
            check(code == 0 and value(Reader(session.read_bytes())) == old,output)
            configured = dict(old,proxy_username='old-proxy-user',proxy_password='old-proxy-password',
                              proxy_auth='ntlm',proxy_domain='OLD',proxy_workstation='OLD',proxy_ntlm_version=2)
            session.write_bytes(wire(configured))
            cli('--reload','-q','--proxy-username','')
            check(value(Reader(session.read_bytes())) == old,'empty proxy username retained proxy credentials')
            cli('--reload','-q','--username','someone-else',expected=11)
            check(value(Reader(session.read_bytes())) == old,'reload changed account')
            replacement.ds_id = 'foreign-nas'
            cli('--reload','-q','--port',str(replacement.port),expected=4)
            check(value(Reader(session.read_bytes())) == old,'failed edit changed session')
            check(all(request['action'] == 'query_server_info' for request in replacement.requests),
                  'edit sent token to another NAS')
            replacement.ds_id = nas.ds_id
            replacement.token = nas.token
            cli('--reload','-q','--port',str(replacement.port))
            changed = value(Reader(session.read_bytes()))
            check(changed['port'] == replacement.port and changed['token'] == old['token'] and
                  changed['device_uuid'] == old['device_uuid'],'edit replaced device identity or token')
            cli('--reload','-q','--port',str(nas.port))
            nas.poll_mode = replacement.poll_mode = 'stall'
            process = subprocess.Popen([executable,'service','run'],env=env,
                                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            wait_for(lambda:any(r['action'] == 'long_poll' for r in nas.requests),'service never polled')
            rotated = value(Reader(session.read_bytes()))['token']
            replacement.token = rotated
            cli('--reload','-q','--port',str(replacement.port))
            wait_for(lambda:any(r['action'] == 'auth' for r in replacement.requests), 'edited service did not reconnect')
            saved = value(Reader(session.read_bytes()))
            check(saved['port'] == replacement.port and saved['token'] == replacement.token,'service edit lost rotated token')
            check(process.poll() is None,'edit stopped service process')
            cli('--logout','-q',*admin)
            out, err = process.communicate(timeout=8)
            check(process.returncode == 0 and not session.exists(),out+err)
            check(any(r['action'] == 'auth_admin' for r in replacement.requests),'service logout omitted admin auth')
            check(not nas.errors and not replacement.errors,str(nas.errors+replacement.errors))
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()
            nas.close()
            replacement.close()
        print('PASS official agent admin logout, OTP, edit validation, service reload and token preservation')


if __name__ == '__main__':
    main()
