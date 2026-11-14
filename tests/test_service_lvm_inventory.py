"""Native automatic LV-only full/CBT backup with uncaptured VG/PV inventory.

The real capture reader and session run against independent frozen ext4 bytes;
only OS acquisition and Linux device calls are interposed. No lab devices.
"""
import copy
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from test_probe import check
from test_service import wait_for
from machine_service_specimens import lvm_disk
from snapshot_service_fixture import SnapshotSources
from automatic_machine_service import provide_capture, catalog_snapshot, load
from test_service_interval_parity import Nas, MIB


def main():
    exe, openssl, fixture = map(lambda arg: str(Path(arg).resolve()), sys.argv[1:4])
    with tempfile.TemporaryDirectory(prefix='opensabba-lvm-inventory-') as temporary:
        root = Path(temporary)
        _, data, pv_plan, lv, vg = lvm_disk(root)
        # The selected LV's VG has a second PV on an uncaptured disk. Neither
        # that membership nor an unrelated scratch VG authorizes disk payload.
        vg['physical_volumes'].append(dict(name='/dev/sdd1',uuid='uncaptured-pv',size=4*MIB))
        vg['total_size'] += 4*MIB
        scratch = dict(name='scratch',uuid='scratch-vg',extent_size=4*MIB,mda_size=4096,
            total_size=4*MIB,physical_volumes=[dict(name='/dev/sde1',uuid='scratch-pv',size=4*MIB)],
            logical_volumes=[dict(name='idle',uuid='scratch-lv',file_system='ext4',size=4*MIB)])
        unselected = copy.deepcopy(pv_plan)
        unselected.update(disk_number=0,image_name='sdc.img',layout_policy='linux-layout-v1')
        plan = dict(root=lv,selected_extra=[],excluded=[],additional_disks=[],other_disk_count=3,
            unselected_disks=[unselected],unselected_logical=[],
            lvm=dict(volume_groups=[vg,scratch],selected_lvs=[lv]))
        sources = SnapshotSources(root)
        config = root/'config'
        private = config/'opensabba'
        private.mkdir(parents=True,mode=0o700)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-noenc','-days','1',
            '-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost',
            '-addext','subjectAltName=IP:127.0.0.1'],check=True,capture_output=True)
        nas = Nas(config,cert,key,automatic_catalog=True)
        from test_probe import wire
        session = dict(format=2,host='127.0.0.1',port=nas.port,ca_file=str(cert),username='test-user',
            device_uuid='test-device',token='test-token',ds_id='test-nas',registration_state='confirmed')
        (private/'session.pstream').write_bytes(wire(session))
        (private/'session.pstream').chmod(0o600)
        env = dict(os.environ,XDG_CONFIG_HOME=str(config),LD_PRELOAD=fixture,
            OPENSABBA_SOURCE_FIXTURE=str(sources.manifest),OPENSABBA_SOURCE_TRACE=str(sources.trace))
        process = None
        try:
            for stage in range(2):
                current = bytearray(data)
                if stage:
                    current[-65536:] = b'\x6a'*65536
                journal, capture = sources.capture(plan,None,logical=bytes(current))
                mark = sources.read_mark()
                nas.select({lv['image_name']:bytes(current)},{lv['image_name']:[]},
                    {lv['image_name']:[]},bool(stage),['/data'])
                capture = provide_capture(env,sources,capture,dict(source_type=3,custom_volume=['/data']))
                process = subprocess.Popen([exe,'service','run'],env=env,stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,text=True)
                check(nas.finished.wait(35),f'LV-only backup failed: {nas.errors}; status={process.poll()}')
                wait_for(lambda: load(private/'backup-job.pstream')['phase'] == 'complete','LV backup completion')
                spec = nas.specs[-1]
                check(spec['device_spec']['volume_groups'] == [vg,scratch], 'global VG/PV/LV metadata was filtered')
                physical, logical = spec['disk_images']
                check(physical['image_name'] == 'sdc.img' and physical['need_upload'] is False and
                    logical['image_name'] == lv['image_name'] and logical['need_upload'] is True,
                    'PV membership promoted a physical image')
                check(set(spec['device_spec']['disk_layout']) == {'0'} and
                    spec['device_spec']['disk_layout']['0'][0]['device_name'] == '/dev/sdc1',
                    'uncaptured physical layout disappeared')
                check(not any(row.startswith('raw ') for row in sources.trace.read_text().splitlines()[mark:]),
                    'LV-only backup opened an uncaptured physical source')
                catalog_snapshot(config,nas.run_id,8+nas.step,7+nas.step if stage else 0)
                if stage:
                    sources.verify_incremental_reads(mark,{'/dev/synosnap2':[(len(data)-65536,65536)]})
                process.send_signal(signal.SIGTERM)
                out, err = process.communicate(timeout=8)
                check(process.returncode == 0,out+err)
                process = None
                check(not nas.errors,nas.errors)
        finally:
            if process:
                process.kill()
                process.communicate(timeout=8)
            nas.close()


if __name__ == '__main__':
    main()
