"""Production SnapshotReader OS failures through transfer and service completion.

No real driver, disk, mount or service configuration is touched. LD_PRELOAD maps
only explicit device aliases to temporary specimen files.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from test_service_recovery import run
from test_probe import check, wire


def main():
    driver, openssl, fixture = map(lambda arg: str(Path(arg).resolve()), sys.argv[1:4])
    with tempfile.TemporaryDirectory(prefix='opensabba-read-errors-') as directory:
        root = Path(directory)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-noenc','-days','1',
                        '-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost',
                        '-addext','subjectAltName=IP:127.0.0.1'],check=True,capture_output=True)
        control, data, dev = root/'control', root/'snapshot', root/'dev.txt'
        control.touch(mode=0o600)
        data.write_bytes(bytes([42])*8192)
        dev.write_text('240:0\n')
        uuid = '1234567890abcdef1234567890abcdef'
        manifest = root/'manifest'
        manifest.write_text(f'control /dev/synosnap-ctl {control} 0 0 0 0 0 - - -\n'
                            f'snap /dev/synosnap0 {data} 0 8192 240 0 1 {uuid} /dev/source /cow\n'
                            f'text /sys/class/block/synosnap0/dev {dev} 0 0 0 0 0 - - -\n')
        identity = root/'identity.pstream'
        identity.write_bytes(wire(dict(minor=0,uuid=uuid,sequence=1,origin_path='/dev/source',cow_path='/cow')))
        for mode, fault in [('read-enodata','0 512 61 0 0'),('read-eio-skip','512 512 5 0 0'),
                            ('read-eio-fatal','0 512 5 -5 0'),('read-cow','0 512 5 0 1')]:
            trace = root/f'{mode}.trace'
            env = dict(os.environ,LD_PRELOAD=fixture,OPENSABBA_SOURCE_FIXTURE=str(manifest),
                       OPENSABBA_SOURCE_TRACE=str(trace),OPENSABBA_READ_IDENTITY=str(identity),
                       OPENSABBA_SOURCE_READ_FAULT='/dev/synosnap0 '+fault)
            run(driver,cert,key,root,mode,env)
            reads = [row.split() for row in trace.read_text().splitlines()]
            check(len(reads) == (31 if mode == 'read-enodata' else 10 if mode == 'read-eio-skip' else 1),
                  f'{mode}: wrong OS read attempts {reads}')
            check(all(row[0:2] == ['snap','/dev/synosnap0'] for row in reads),'reader switched source')
            if mode == 'read-eio-skip':
                check([(int(row[2]),int(row[3])) for row in reads] ==
                      [(0,4096), *[(at,512) for at in range(0,4096,512)], (4096,4096)],
                      f'fallback did not return to the ordinary block size: {reads}')
            print(mode+': production SnapshotReader, result details, completion and next worker operation passed')


if __name__ == '__main__':
    main()
