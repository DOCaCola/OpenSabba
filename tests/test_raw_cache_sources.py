"""Exercise production retained readers against isolated frozen/raw specimens."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from snapshot_service_fixture import SnapshotSources, MIB
from test_probe import check, wire

probe, fixture = map(lambda path: str(Path(path).resolve()), sys.argv[1:3])


def partition(number, offset, length, kind, bootable=0):
    return dict(number=number, offset=offset, length=length, attributes=0,
                mbr_type=kind, bootable=bootable, type_guid='', uuid='')


with tempfile.TemporaryDirectory(prefix='opensabba-raw-cache-') as temporary:
    root = Path(temporary)
    primary = bytes([0x31])*(26*MIB)
    secondary = bytes([0x41])*(16*MIB)
    swap = dict(partition=3, offset=14*MIB, length=8*MIB,
                filesystem='swap', mount_path='')
    extra_swap = dict(swap, partition=1, offset=2*MIB)
    extra = dict(layout=dict(scheme='MBR', sector_size=512, length=len(secondary),
        disk_id='secondary', partitions=[
            partition(1, 2*MIB, 8*MIB, 0x82),
            partition(2, 10*MIB, 4*MIB, 0x07, 1)]),
        layout_policy='linux-layout-v1', volume_policy='linux-bare-metal-v1',
        swap_page_size=4096, selected_extra=[], excluded=[extra_swap,
            dict(partition=2, offset=10*MIB, length=4*MIB, filesystem='ntfs', mount_path='')])
    plan = dict(layout=dict(scheme='MBR', sector_size=512, length=len(primary),
        disk_id='primary', partitions=[
            partition(1, MIB, 2*MIB, 0x06),
            partition(2, 4*MIB, 8*MIB, 0x83),
            partition(3, 14*MIB, 8*MIB, 0x82)]),
        layout_policy='linux-layout-v1', volume_policy='linux-bare-metal-v1',
        swap_page_size=4096, other_disk_count=1,
        boot=dict(partition=1, offset=MIB, length=2*MIB, filesystem='vfat',
                  mount_path='/boot', filesystem_uuid='boot'),
        root=dict(partition=2, offset=4*MIB, length=8*MIB, filesystem='ext4',
                  mount_path='/', filesystem_uuid='root'),
        excluded=[swap], selected_extra=[], additional_disks=[extra])
    sources = SnapshotSources(root)
    journal, capture = sources.capture(plan, primary, secondary)
    expected_paths = []
    retained = []
    # Literal oracle for official agent small raw-cache intervals, independently of C++.
    candidates = [[(0, MIB), (3*MIB, MIB), (12*MIB, 2*MIB),
                   (14*MIB, 4096), (14*MIB+4096, 8*MIB-4096),
                   (22*MIB, 3*MIB), (25*MIB, MIB)],
                  [(0, MIB), (MIB, MIB), (2*MIB, 4096),
                   (2*MIB+4096, 8*MIB-4096), (14*MIB, MIB), (15*MIB, MIB)]]
    disks = [journal['plan'], *journal['plan']['additional_disks']]
    artifacts = [journal['artifact'], *journal['artifact']['additional_images']]
    for index, (disk, artifact, original, intervals) in enumerate(
            zip(disks, artifacts, (primary, secondary), candidates)):
        body = disk['excluded'][0]['offset']+4096
        failures = {(0, MIB), (body-4096, 4096), (body, 8*MIB-4096)}
        disk['raw_cache_failures'] = [dict(offset=at, length=length)
            for at, length in sorted(failures)]
        expected = bytearray(original)
        expected[body:body+8*MIB-4096] = bytes(8*MIB-4096)
        cache = capture/('raw.cache' if index == 0 else f'raw-{index}.cache')
        cache.chmod(0o600)
        with cache.open('r+b') as saved, (capture/f'origin-{index}.data').open('r+b') as origin:
            for at, length in intervals:
                if (at, length) in failures:
                    if at != body:
                        origin.seek(at)
                        current = bytes([0xd1+index])*length
                        origin.write(current)
                        expected[at:at+length] = current
                    # Untrusted partial bytes must never become a cache source.
                    saved.seek(at)
                    saved.write(bytes([0xef])*min(4096, length))
                else:
                    saved.seek(at)
                    saved.write(original[at:at+length])
                    artifact['cached_regions'].append(dict(offset=at, length=length,
                        md5=hashlib.md5(original[at:at+length]).hexdigest()))
                    retained.append((cache, at))
                    # A successful cache must stay frozen during later raw writes.
                    origin.seek(at)
                    origin.write(bytes([0xc1+index])*length)
        cache.chmod(0o400)
        expected_path = root/f'expected-{index}.data'
        expected_path.write_bytes(expected)
        expected_paths.append(str(expected_path))
    journal_path = capture/'capture.pstream'
    journal_path.write_bytes(wire(journal))
    env = dict(os.environ, LD_PRELOAD=fixture, OPENSABBA_SOURCE_FIXTURE=str(sources.manifest),
               OPENSABBA_SOURCE_TRACE=str(sources.trace))
    result = subprocess.run([probe, str(capture), *expected_paths], env=env,
                            capture_output=True, text=True, timeout=30)
    check(result.returncode == 0, result.stdout+result.stderr)
    sources.verify_reads()
    for line in sources.trace.read_text().splitlines():
        kind, path, at, length = line.split()
        if kind != 'raw':
            continue
        disk = disks[0 if path == '/dev/sda' else 1]
        body = disk['excluded'][0]['offset']+4096
        check(int(at)+int(length) <= body or int(at) >= body+8*MIB-4096,
              'failed swap cache body was read from the live disk')
    # A short raw read must preserve its prefix, emit an unchanged EOF record
    # only through the current disk interval, then read subsequent intervals.
    result = subprocess.run([probe, str(capture), *expected_paths],
                            env=dict(env, OPENSABBA_RAW_EOF='1'),
                            capture_output=True, text=True, timeout=30)
    check(result.returncode == 0, result.stdout+result.stderr)
    # Static files can live on the NAS-selected task volume while their
    # authoritative capture journal remains in the private agent state area.
    raw_directory = root/'task-raw-files'
    raw_directory.mkdir(mode=0o700)
    for name in ('raw.cache', 'raw-1.cache'):
        (capture/name).rename(raw_directory/name)
    retained = [(raw_directory/path.name, at) for path, at in retained]
    journal['reservation'].update(raw_directory=str(raw_directory),
                                  raw_directory_inode=raw_directory.stat().st_ino)
    journal_path.write_bytes(wire(journal))
    result = subprocess.run([probe, str(capture), *expected_paths], env=env,
                            capture_output=True, text=True, timeout=30)
    check(result.returncode == 0, result.stdout+result.stderr)
    cache, at = retained[0]
    cache.chmod(0o600)
    with cache.open('r+b') as stream:
        stream.seek(at)
        stream.write(b'\x00')
    cache.chmod(0o400)
    result = subprocess.run([probe, str(capture), *expected_paths], env=env,
                            capture_output=True, text=True, timeout=10)
    check(result.returncode != 0 and 'raw cache interval content changed' in result.stderr,
          'successful cache corruption silently downgraded to a live read')
    # If a destination cannot be created, official agent keeps no cached bytes and
    # reads type2 source intervals; the failed swap body remains type5.
    journal, capture = sources.capture(plan, primary, secondary)
    journal['reservation'].update(output=None, raw_storage_ready=0)
    for row in journal['reservation']['disks']:
        row['output'] = None
    expected_paths = []
    for index, (disk, artifact, data, intervals) in enumerate(zip(
            [journal['plan'], *journal['plan']['additional_disks']],
            [journal['artifact'], *journal['artifact']['additional_images']],
            (primary, secondary), candidates)):
        disk['raw_cache_failures'] = [dict(offset=at, length=length) for at, length in intervals]
        artifact['cached_regions'] = []
        (capture/('raw.cache' if index == 0 else f'raw-{index}.cache')).unlink()
        expected = bytearray(data)
        body = disk['excluded'][0]['offset']+4096
        expected[body:body+8*MIB-4096] = bytes(8*MIB-4096)
        path = root/f'no-cache-expected-{index}'
        path.write_bytes(expected)
        expected_paths.append(str(path))
    (capture/'capture.pstream').write_bytes(wire(journal))
    result = subprocess.run([probe, str(capture), *expected_paths], env=env,
                            capture_output=True, text=True, timeout=30)
    check(result.returncode == 0, result.stdout+result.stderr)
    print('PASS production raw cache fallback sources, integrity, full/incremental/resume')
