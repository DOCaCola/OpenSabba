"""Independent NAS checkpoint oracle for real CLI upload recovery."""
from pstream_peer import upload_value

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from test_backup_cli import Server as BaseServer, Reader
from test_login import value
from test_probe import check, wire
from proxy_peer import Proxy
from lz4_receiver import decode_block


class Server(BaseServer):
    def handle(self, peer):
        try:
            with peer:
                peer.settimeout(10)
                check(value(peer)['action'] == 'encrypt_channel', 'plaintext credentials')
                peer.sendall(wire({}))
                with self.tls.wrap_socket(peer, server_side=True) as tls:
                    req = value(tls)
                    action = req['action']
                    self.requests.append(req.get('subaction', action))
                    if action == 'query_server_info':
                        tls.sendall(wire({'ds_id': 'test-nas'}))
                        return
                    check(req['token'] == 'test-token', 'wrong authentication')
                    if action == 'get_task':
                        tls.sendall(wire(dict(task_list=[dict(id=2,name='Resume fixture',encryption=1)])))
                    elif action == 'heart_beat':
                        tls.sendall(wire({}))
                    elif action == 'get_running_task_result':
                        check(req['result_id'] == 112, 'wrong result lookup')
                        tls.sendall(wire({'running_task_result': dict(task_id=2, result_id=112,
                            job_action='backup', status='complete' if self.mode == 'terminal' else 'incomplete')}))
                    elif action == 'get_running_task':
                        check(req['check_backup_exist'] == 1, 'previous worker was not checked')
                        resume = json.dumps({'test-image': {'current': str(self.offset),
                            'transfer_current': str(self.offset), 'mac_progress': None}})
                        if self.mode == 'compressed':
                            resume = json.dumps({'test-image': {'current': str(self.offset),
                                'transfer_current': str(len(self.image)+8192), 'mac_progress': None}})
                        if self.mode == 'transfer-overflow':
                            resume = json.dumps({'test-image': {'current': str(self.offset),
                                'transfer_current': '18446744073709551616', 'mac_progress': None}})
                        if self.mode == 'empty':
                            resume = ''
                        if self.mode == 'escaped':
                            resume = resume.replace('test-image', 'test\\u002dimage').replace('current"', 'curr\\u0065nt"')
                        if self.mode == 'different-image':
                            resume = resume.replace('test-image', 'other-image')
                        if self.mode == 'missing-current':
                            resume = '{"test-image":{"transfer_current":"0"}}'
                        if self.mode == 'numeric-current':
                            resume = '{"test-image":{"current":512,"transfer_current":"512"}}'
                        if self.mode == 'duplicate':
                            resume = '{"test-image":{"current":"0","current":"512","transfer_current":"512"}}'
                        if self.mode == 'overflow':
                            resume = '{"test-image":{"current":"18446744073709551616","transfer_current":"0"}}'
                        if self.mode == 'negative':
                            resume = '{"test-image":{"current":"-512","transfer_current":"0"}}'
                        if self.mode == 'trailing':
                            resume += '{}'
                        if self.mode == 'mac':
                            resume = resume.replace('null', '{}')
                        if self.mode == 'second-image':
                            resume = resume[:-1] + ',"other":{}}'
                        job = dict(id=27, type=0, task_id=2, version_id=1, result_id=112,
                                   status=1, detail_status=0, is_backing_up=0,
                                   backup_task=dict(error_code=0, resume_info=resume))
                        if self.mode == 'offline':
                            job.update(status=2, detail_status=6)
                        if self.mode == 'paused':
                            job.update(status=2, detail_status=7)
                        if self.mode == 'cancelled':
                            job['status'] = 3
                        if self.mode == 'active':
                            job['is_backing_up'] = 1
                        if self.mode == 'no-active-flag':
                            del job['is_backing_up']
                        if self.mode == 'wrong-result':
                            job['result_id'] = 113
                        if self.mode == 'wrong-version':
                            job['version_id'] = 2
                        if self.mode == 'wrong-type':
                            job['type'] = 2
                        if self.mode == 'server-error':
                            job['backup_task']['error_code'] = 8017
                        if self.mode == 'save-failure':
                            (self.root/'opensabba').chmod(0o500)
                        if self.mode == 'source-mutated':
                            with (self.root/'source.img').open('r+b') as out:
                                out.write(b'changed')
                        jobs = [] if self.mode == 'missing-job' else [job]
                        if self.mode == 'duplicate-job':
                            jobs.append(job)
                        tls.sendall(wire({'running_task_list': jobs}))
                    else:
                        check(action == 'backup', 'unexpected action')
                        check(req['running_task_id'] == 27, 'another run substituted')
                        record = self.record()
                        if req['subaction'] == 'upload_block':
                            check(req['resume'] == 1 and record['phase'] == 'upload', 'missing resume intent')
                            check(record['resume_offset'] == self.offset, 'client used its own sent count')
                            tls.sendall(wire({'success': 1}))
                            at = self.offset
                            performance = {}
                            while at < len(self.image):
                                block = upload_value(tls, performance)
                                check(block['image_name'] == 'test-image' and block['offset'] == at,
                                      'wrong resumed image or offset')
                                count = min(1024*1024, len(self.image)-at)
                                payload = block['buffer']
                                if self.mode == 'compressed':
                                    check(block['compressed'] == 1, 'resume lost journal compression policy')
                                    payload = decode_block(payload, block['length'])
                                else:
                                    check('compressed' not in block, 'raw journal changed compression')
                                check(block['length'] == count and payload == self.image[at:at+count],
                                      'resumed data differs')
                                check(block['used'] == block['changed'] == 1 and block['is_interval_cbt'] == 0,
                                      'unexpected block mode')
                                at += count
                                self.requests.append('block')
                            check(upload_value(tls, performance) == {'close': 1}, 'missing close')
                            check(set(performance) == ({'read_disk', 'send'} if self.offset < len(self.image) else set()) and all(
                                item['size'] == len(self.image)-self.offset and item['time'] > 0
                                for item in performance.values()),
                                'resume restored obsolete counters or counted compressed bytes')
                            if self.mode == 'lost-close':
                                return
                            tls.sendall(wire({'close': 1}))
                        elif req['subaction'] == 'check_complete':
                            check(record['phase'] == 'finish' and req['result_id'] == 112 and
                                  req['status'] == 'complete', 'missing completion intent')
                            if self.mode == 'lost-finish':
                                return
                            tls.sendall(wire({'status': 'complete'}))
                        else:
                            raise AssertionError('resume replayed metadata or preparation')
        except Exception as error:
            self.errors.append(repr(error))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    parser.add_argument('openssl')
    parser.add_argument('--proxy', action='store_true')
    args = parser.parse_args()
    exe = str(Path(args.executable).resolve())
    image = bytes(range(256))*8194
    cases = ('success', 'empty', 'escaped', 'offline', 'full', 'unaligned', 'oversized', 'different-image',
             'missing-current', 'numeric-current', 'duplicate', 'overflow', 'negative', 'trailing',
             'mac', 'second-image', 'terminal', 'paused', 'cancelled', 'active', 'no-active-flag',
             'wrong-result', 'wrong-version', 'wrong-type', 'server-error', 'save-failure', 'source-mutated',
             'missing-job', 'duplicate-job', 'wrong-source', 'finish', 'metadata', 'pending-cancel',
             'lost-close', 'lost-finish', 'compressed', 'schema2-raw', 'missing-compression',
             'bad-compression', 'schema1-compression', 'transfer-overflow')
    if args.proxy:
        cases += ('proxy-reject',)
    with tempfile.TemporaryDirectory(prefix='opensabba-backup-resume-') as temporary:
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
            source = config/'source.img'
            source.write_bytes(image)
            server = Server(config, cert, key, image, mode)
            server.offset = 1024*1024+512
            if mode == 'empty':
                server.offset = 0
            if mode == 'full':
                server.offset = len(image)
            if mode == 'unaligned':
                server.offset = 1
            if mode == 'oversized':
                server.offset = len(image)+512
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
                if mode == 'proxy-reject':
                    proxy.response = b"HTTP/1.1 407 Authentication required\r\n\r\n"
            record = dict(schema=1, ds_id='test-nas', username='test-user', device_uuid='test-device',
                          phase=mode if mode in ('finish', 'metadata') else 'upload',
                          running_task_id=27, task_id=2, version_id=1, result_id=112, data_format=1,
                          image_name='test-image', image_size=len(image), sent_bytes=len(image),
                          image_sha256=hashlib.sha256(image).hexdigest(), snapshot_info=b'{}',
                          requested_outcome='complete')
            if mode in ('compressed', 'schema2-raw', 'missing-compression', 'bad-compression'):
                record.update(schema=2, compression='lz4' if mode == 'compressed' else 'none')
            if mode == 'missing-compression':
                del record['compression']
            if mode in ('bad-compression', 'schema1-compression'):
                record['compression'] = 'unknown'
            if mode == 'metadata':
                del record['sent_bytes']
            if mode == 'pending-cancel':
                record['resolution'] = dict(state='cancel-pending', outcome='cancel')
            for name, data in [('session', session), ('backup-job', record)]:
                path = private/(name+'.pstream')
                path.write_bytes(wire(data))
                path.chmod(0o600)
            journal = private/'backup-job.pstream'
            before = journal.read_bytes()
            if mode == 'wrong-source':
                source.write_bytes(b'\xff'*len(image))
            env = dict(os.environ, XDG_CONFIG_HOME=str(config))
            def cli():
                result = subprocess.run([exe, 'backup', 'resume', str(source)], env=env,
                                        capture_output=True, text=True, timeout=25)
                check('resume-proxy-secret' not in result.stdout+result.stderr, 'proxy credential leaked')
                return result
            try:
                result = cli()
                good = mode in ('success', 'empty', 'escaped', 'offline', 'full', 'compressed', 'schema2-raw')
                check((result.returncode == 0) == good, f'{mode}: {result.stdout}{result.stderr}')
                after = value(Reader(journal.read_bytes()))
                if good:
                    check(after['phase'] == 'complete' and after['resume_offset'] == server.offset,
                          'resumed run not complete')
                    check(server.requests.count('block') == (len(image)-server.offset+1048575)//1048576,
                          'committed ranges were resent')
                elif mode in ('lost-close', 'lost-finish'):
                    check(after['phase'] == ('upload' if mode == 'lost-close' else 'finish'),
                          'ambiguous outcome marked complete')
                    if mode == 'lost-close':
                        server.mode, server.offset = 'success', len(image)
                        check(cli().returncode == 0, 'lost close could not resume at NAS end position')
                    else:
                        count = len(server.requests)
                        check(cli().returncode != 0 and len(server.requests) == count, 'finish replayed')
                else:
                    check(journal.read_bytes() == before, 'rejected resume changed journal')
                    check('upload_block' not in server.requests and 'check_complete' not in server.requests,
                          'rejected resume mutated backup')
            finally:
                private.chmod(0o700)
                if proxy:
                    proxy.close()
                    check(not proxy.errors, str(proxy.errors))
                server.close()
        print(f'{len(cases)} backup resume cases passed')


if __name__ == '__main__':
    main()
