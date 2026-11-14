"""Independent receiver: task encryption selects only the image-data channel."""
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from pstream_peer import value, upload_value
from test_probe import check, wire


def run(driver, cert, key, mode):
    encrypted, multi, resume = 'plain' not in mode, mode.startswith('multi'), 'resume' in mode
    names = ['disk-0','disk-1'] if multi else ['disk-0']
    expected = dict(zip(names,[bytes([0xa5])*16384,bytes([0x5a])*16384]))
    errors, controls, uploads, clients = [], [], [], []
    stopped = threading.Event()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert,key)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0))
        listener.listen()
        listener.settimeout(.1)
        def handle(peer):
            try:
                with peer:
                    peer.settimeout(8)
                    first = value(peer)
                    secured = first['action']=='encrypt_channel'
                    if secured:
                        peer.sendall(wire({}))
                    channel = context.wrap_socket(peer,server_side=True) if secured else peer
                    with channel:
                        req = value(channel) if secured else first
                        action, op = req['action'], req.get('subaction',req['action'])
                        if op=='upload_block':
                            check(secured==encrypted,'upload ignored the task encryption setting')
                            check(req['running_task_id']==27 and req['resume']==int(resume) and
                                  req['is_cache']==int(mode.startswith('cache')),'upload identity/flags changed')
                            uploads.append(secured)
                            channel.sendall(wire(dict(success=1)))
                            for name in names:
                                payload = bytearray()
                                while len(payload)<len(expected[name]):
                                    block = upload_value(channel)
                                    check(block['image_name']==name and block['offset']==len(payload) and
                                          block['length']==len(block['buffer']),'invalid upload extent')
                                    payload.extend(block['buffer'])
                                check(payload==expected[name],'wrong independently reconstructed image')
                            check(upload_value(channel)==dict(close=1),'wrong data close')
                            reply = dict(close=1)
                        else:
                            check(secured,'task disabled encryption on a control connection')
                            controls.append(op)
                            if action=='query_server_info':
                                reply = dict(ds_id='test-nas')
                            elif op=='update_backup_task':
                                reply = dict(running_task_id=27,version_id=9,result_id=112,data_format=1)
                            elif op=='update_device_spec':
                                check(req['snapshot_info']==b'{}','metadata changed')
                                reply = {}
                            elif action=='get_running_task_result':
                                reply = dict(running_task_result=dict(task_id=2,result_id=112,
                                    job_action='backup',status='incomplete'))
                            elif action=='get_running_task':
                                reply = dict(running_task_list=[dict(id=27,type=0,task_id=2,status=1,
                                    version_id=9,result_id=112,is_backing_up=0,
                                    backup_task=dict(error_code=0,resume_info=json.dumps({name:
                                        dict(current='0',transfer_current='0') for name in names})))])
                            elif op=='check_complete':
                                check(req['status']=='complete','wrong completion')
                                reply = dict(status='complete')
                            else:
                                raise AssertionError(f'unexpected control {op}')
                        channel.sendall(wire(reply))
            except Exception as error:
                errors.append(repr(error))
        def serve():
            while not stopped.is_set():
                try:
                    peer, _ = listener.accept()
                except socket.timeout:
                    continue
                client = threading.Thread(target=handle,args=(peer,))
                clients.append(client)
                client.start()
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            result = subprocess.run([driver,str(listener.getsockname()[1]),str(cert),mode],
                capture_output=True,text=True,timeout=20)
            check(result.returncode==0,f'{mode}: {result.stderr}; {errors}; {controls}')
        finally:
            stopped.set()
            worker.join(3)
            for client in clients:
                client.join(10)
    check(not errors and uploads==[encrypted] and controls.count('update_backup_task')==1 and
          controls.count('update_device_spec')==1 and controls.count('check_complete')==1,
          f'{mode}: wrong channels or duplicated control: {errors}; {controls}; {uploads}')


def main():
    driver, openssl = (str(Path(arg).resolve()) for arg in sys.argv[1:3])
    with tempfile.TemporaryDirectory(prefix='opensabba-backup-transport-') as temporary:
        root = Path(temporary)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-noenc','-days','1',
            '-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost',
            '-addext','subjectAltName=IP:127.0.0.1'],check=True,capture_output=True)
        for kind in ('single','multi','cache'):
            for cipher in ('plain','tls'):
                for replay in ('','-resume'):
                    run(driver,cert,key,f'{kind}-{cipher}{replay}')


if __name__=='__main__':
    main()
