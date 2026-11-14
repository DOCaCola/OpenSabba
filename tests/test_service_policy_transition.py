"""Change the NAS policy after real durable source publication, before dispatch."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from test_probe import check, wire
from test_service import wait_for
from test_snapshot import filesystem
from machine_service_specimens import machine_disk, machine_plan, external_disk
from snapshot_service_fixture import SnapshotSources
from automatic_machine_service import provide_capture, load
from test_service_interval_parity import Nas, MIB


def main():
    exe, openssl, fixture = (str(Path(arg).resolve()) for arg in sys.argv[1:4])
    with tempfile.TemporaryDirectory(prefix='opensabba-policy-transition-') as temporary:
        root = Path(temporary)
        part = filesystem(root)
        primary, boot, boot_size, root_at = machine_disk(part)
        extra, extra_plan = external_disk(root)
        plan = machine_plan(primary,boot,boot_size,root_at,len(part))
        plan.update(additional_disks=[extra_plan],other_disk_count=1)
        sources = SnapshotSources(root)
        _, capture = sources.capture(plan,bytes(primary),extra)
        config = root/'config'
        private = config/'opensabba'
        private.mkdir(parents=True,mode=0o700)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-noenc','-days','1',
            '-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost',
            '-addext','subjectAltName=IP:127.0.0.1'],check=True,capture_output=True)
        nas = Nas(config,cert,key,automatic_catalog=True)
        nas.select({'sda.img':bytes(primary),'sdc.img':extra},
            {'sda.img':[(root_at+len(part)+MIB,root_at+len(part)+5*MIB)],
             'sdc.img':[(18*MIB,22*MIB)]},{'sda.img':[],'sdc.img':[]},False,['/','/data'])
        nas.task_fields = dict(source_type=1)
        session = dict(format=2,host='127.0.0.1',port=nas.port,ca_file=str(cert),username='test-user',
            device_uuid='test-device',token='test-token',ds_id='test-nas',registration_state='confirmed')
        (private/'session.pstream').write_bytes(wire(session))
        (private/'session.pstream').chmod(0o600)
        env = dict(os.environ,XDG_CONFIG_HOME=str(config),LD_PRELOAD=fixture,
            OPENSABBA_SOURCE_FIXTURE=str(sources.manifest),OPENSABBA_SOURCE_TRACE=str(sources.trace))
        provide_capture(env,sources,capture,dict(source_type=1))
        held, release = threading.Event(), threading.Event()
        def before_task():
            source = private/'service-source.pstream'
            if source.exists() and not held.is_set():
                binding = load(source)
                check(binding['claimed_run'] == 0 and binding['capture']['phase'] == 'ready',
                      'policy edit did not occur after unclaimed durable capture publication')
                held.set()
                check(release.wait(15),'dispatch policy gate was not released')
        nas.before_task = before_task
        # Keep independent control dispatch responsive while the execution-side
        # task request waits; observe the actual change_task receipt durably.
        def poll(seconds):
            deadline = time.monotonic()+seconds
            while not nas.stopped.is_set() and not nas.events and time.monotonic()<deadline:
                nas.stopped.wait(.02)
        nas.long_poll_wait = poll
        process = subprocess.Popen([exe,'service','run'],env=env,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,text=True)
        try:
            check(held.wait(20),f'capture did not publish: {nas.errors}; exit={process.poll()}')
            original = load(private/'service-source.pstream')['capture']
            marker = root/'must-not-run'
            content = f'touch "{marker}"\n'.encode()
            nas.task_fields = dict(source_type=3,custom_volume=['/'],compression=1,encryption=0,
                pre_post_script_setting=dict(pre_script_enabled=1,post_script_enabled=1,
                    script_exec_mode=1,pre_script_error=0,post_script_error=0,
                    pre_script_extension='.sh',post_script_extension='.sh'),
                pre_script_content=content,post_script_content=content)
            nas.events = [dict(id=901,action='change_task')]
            wait_for(lambda: 901 in nas.done,'control worker did not durably observe policy edit')
            observed = load(private/'events.pstream')['task_snapshot']
            check(any(t['id']==2 and t['source_type']==3 and t['custom_volume']==['/'] for t in observed),
                  'edited task was not persisted before release')
            release.set()
            check(nas.finished.wait(30),f'policy transition failed: {nas.errors}; exit={process.poll()}')
            wait_for(lambda: load(private/'backup-job.pstream')['phase']=='complete','completion not durable')
            job = load(private/'backup-job.pstream')
            check(job['source_capture']==original and job['compression']=='lz4' and nas.compressed_blocks>0 and
                  nas.plaintext_uploads==1,
                  'dispatch changed captured bytes or ignored refreshed compression')
            check(nas.requests.count('update_backup_task')==1 and len(nas.specs)==1 and
                  [i['image_name'] for i in nas.specs[0]['device_spec']['images']]==['sda.img','sdc.img'],
                  'policy edit recaptured or dropped the previously selected data disk')
            check(not marker.exists(),'new script policy replayed the completed snapshot boundary')
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=8)
            check(process.returncode==0,out+err)
            process = None
        finally:
            release.set()
            if process:
                process.kill()
                process.communicate(timeout=8)
            nas.close()


if __name__=='__main__':
    main()
