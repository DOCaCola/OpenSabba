"""Disk/snapshot specimens for the native OS interposition fixture.

The service uses its production reader; only Linux device open/stat/ioctl/pread
are redirected. Origin filesystem bytes deliberately differ from the frozen
snapshot, and all driver mutations fail inside the fixture.
"""
import copy
import hashlib
import struct
from pathlib import Path
from test_probe import wire

MIB = 1024 * 1024


def merged_ranges(ranges):
    result = []
    for offset, length in sorted(ranges):
        assert offset >= 0 and length > 0, "invalid expected snapshot read range"
        end = offset + length
        if result and offset <= result[-1][1]:
            result[-1] = result[-1][0], max(end, result[-1][1])
        else:
            result.append((offset, end))
    return result


def covered(ranges, begin, end):
    return any(start <= begin and end <= stop for start, stop in ranges)


def ext4_context_metadata_reads(data):
    """Filesystem initialization and empty bad-blocks inode read set.

    Read the superblock, full descriptor pages, initialized allocation bitmaps
    and bad-block inode metadata
    using the cached group-0 descriptor. Each context owns its own parser.
    These mke2fs specimens have no meta_bg, bigalloc or listed bad blocks.
    Derive addresses from the specimen, never observed reads or upload plans.
    """
    sb = memoryview(data)[1024:2048]
    u16 = lambda value, at: struct.unpack_from('<H', value, at)[0]
    u32 = lambda value, at: struct.unpack_from('<I', value, at)[0]
    assert u16(sb, 0x38) == 0xef53
    incompat, ro = u32(sb, 0x60), u32(sb, 0x64)
    assert not incompat & 0x10 and not ro & 0x200, 'fixture needs explicit meta_bg/bigalloc oracle'
    block = 1024 << u32(sb, 0x18)
    blocks = u32(sb, 4) | (u32(sb, 0x150) << 32 if incompat & 0x80 else 0)
    first, per_group = u32(sb, 0x14), u32(sb, 0x20)
    clusters = u32(sb, 0x24)
    assert clusters and clusters % 8 == 0
    groups = (blocks-first+per_group-1)//per_group
    descriptor_size = u16(sb, 0xfe) if incompat & 0x80 else 32
    gdt_at = (first+1)*block
    gdt_length = ((groups*descriptor_size+block-1)//block)*block
    # Retain the existing source-identity sector probe separately from the
    # Filesystem initialization reads begin at the superblock.
    reads = [(0, 512), (1024, 1024), (gdt_at, gdt_length)]
    first_inode_table = None
    for group in range(groups):
        gd = memoryview(data)[gdt_at+group*descriptor_size:gdt_at+(group+1)*descriptor_size]
        bitmap = u32(gd, 0) | (u32(gd, 32) << 32 if incompat & 0x80 else 0)
        if not (ro & 0x410 and u16(gd, 18) & 2):
            reads.append((bitmap*block, clusters//8))
        if group == 0:
            first_inode_table = u32(gd, 8) | (u32(gd, 40) << 32 if incompat & 0x80 else 0)
    inode_at = first_inode_table*block
    inode = memoryview(data)[inode_at:inode_at+128]
    assert len(inode) == 128 and not any(inode[40:100]), 'fixture needs explicit bad-block tree oracle'
    reads.append((inode_at, 128))
    return reads


def verify_snapshot_read_coverage(rows, required, metadata=None):
    """Independent read oracle; repeated reads never authorize new offsets.

    Expected payload ranges come from the test's explicit mutations, transport
    boundaries and missing-base fallback, not saved CBT plans or upload blocks.
    Metadata permissions are exact official agent read shapes, independently calculated
    from each frozen filesystem. Repetitions cannot authorize adjacent bytes.
    """
    permitted = {path: merged_ranges(ranges) for path, ranges in required.items()}
    metadata = ({path: [(0, 512), (1024, 1024)] for path in required}
                if metadata is None else metadata)
    observed = {path: [] for path in required}
    count = 0
    for row in rows:
        kind, path, offset, length = row.split()
        if kind != "snap":
            continue
        begin, length = int(offset), int(length)
        end = begin + length
        assert length > 0 and path in permitted and (
            covered(permitted[path], begin, end) or (begin, length) in metadata[path]), (
            "snapshot read entered an inherited payload range", path, begin, length, permitted.get(path))
        observed[path].append((begin, length))
        count += 1
    assert count, "incremental transfer never read its changed snapshots"
    for path, ranges in required.items():
        actual = merged_ranges(observed[path])
        for begin, end in merged_ranges(ranges):
            assert covered(actual, begin, end), (
                "incremental snapshot payload coverage is incomplete", path, begin, end, actual)
    return count


class SnapshotSources:
    def __init__(self, root):
        self.root = root
        self.manifest = root / 'sources.txt'
        self.trace = root / 'source-reads.txt'
        self.previous = None
        self.volumes = {}
        self.generation = 0
        self.origins = []
        self.snapshot_files = {}

    def capture(self, plan, primary, secondary=None, logical=None):
        self.generation += 1
        generation = self.generation
        directory = self.root / f'capture-{generation:032x}'
        directory.mkdir(mode=0o700)
        plan = copy.deepcopy(plan)
        plan.setdefault('selected_extra', [])
        plan.setdefault('additional_disks', [])
        plan['cow_directory'] = str(directory)
        if 'layout' in plan:
            plan.update(disk='/dev/sda', device_number='8:0', disk_sequence=7)
        if 'boot' in plan:
            plan['boot'].update(device_number='8:1', mount_id=1,
                                mount_options='rw,relatime', super_options='rw')
        disks = ([plan] if 'layout' in plan else []) + plan['additional_disks']
        payloads = ([primary] if primary is not None else []) + ([secondary] if secondary is not None else [])
        primary_identity = None
        rows = []
        control = self.root / 'control'
        control.touch(mode=0o600)
        rows.append(f'control /dev/synosnap-ctl {control} 0 0 0 0 0 - - -')
        artifacts, disk_reservations = [], []
        origin_paths = []
        for index, (disk, data) in enumerate(zip(disks, payloads)):
            disk.setdefault('selected_extra', [])
            disk.update(disk='/dev/sda' if index == 0 else '/dev/sdc',
                        device_number=f'8:{index*32}', disk_sequence=7)
            origin = directory / f'origin-{index}.data'
            origin.write_bytes(data)
            origin_paths.append(origin)
            rows.append(f'raw {disk["disk"]} {origin} 0 {len(data)} 8 {index*32} 7 - - -')
            cache = directory / ('raw.cache' if index == 0 else f'raw-{index}.cache')
            with cache.open('wb') as stream:
                stream.truncate(len(data))
            cache.chmod(0o400)
            identity = dict(device=cache.stat().st_dev, inode=cache.stat().st_ino)
            artifact = dict(length=len(data), sector_size=512, sha256='', cached_regions=[])
            if index:
                artifact['disk_index'] = index
                disk_reservations.append(dict(disk_index=index, output=identity))
            else:
                primary_identity = identity
            artifacts.append(artifact)
        volumes = [plan['root'], *plan['selected_extra']]
        for disk in plan['additional_disks']:
            volumes.extend(disk['selected_extra'])
        reservations, current = [], {}
        self.snapshot_files = {}
        for index, volume in enumerate(volumes):
            minor = index + 2
            previous = self.volumes.get(volume['filesystem_uuid'])
            uuid = previous[0]['uuid'] if previous else hashlib.md5(volume['filesystem_uuid'].encode()).hexdigest()
            volume.update(device='/dev/fixture-lv-'+volume['filesystem_uuid'][:8] if 'lv_uuid' in volume else
                          ('/dev/sda2' if index == 0 else '/dev/sdc1'))
            if 'lv_uuid' in volume:
                data = logical[volume['image_name']] if isinstance(logical, dict) else logical
                artifacts.append(dict(length=len(data), sector_size=512, sha256='',
                                      image_name=volume['image_name'], lv_uuid=volume['lv_uuid']))
            else:
                disk_index = volume.get('disk_index', 0)
                data = payloads[disk_index][volume['offset']:volume['offset']+volume['length']]
                # A read from the origin rather than synosnap is observably wrong.
                with origin_paths[disk_index].open('r+b') as stream:
                    stream.seek(volume['offset'])
                    stream.write(b'\xa7' * 4096)
                self.origins.append((str(disks[disk_index]['disk']), volume['offset'], volume['length']))
            frozen = directory / f'snapshot-{minor}.data'
            frozen.write_bytes(data)
            self.snapshot_files[f'/dev/synosnap{minor}'] = frozen
            frozen.chmod(0o400)
            cow = f'/.synosnap_data/fixture-{minor}-{generation}'
            snapshot = dict(minor=minor, uuid=uuid, sequence=generation,
                            origin_path=volume['device'], cow_path=cow)
            rows.append(f'snap /dev/synosnap{minor} {frozen} 0 {len(data)} 240 {minor} '
                        f'{generation} {uuid} {volume["device"]} {cow}')
            dev = directory / f'dev-{minor}.txt'
            dev.write_text(f'240:{minor}\n')
            rows.append(f'text /sys/class/block/synosnap{minor}/dev {dev} 0 0 0 0 0 - - -')
            reservation = dict(minor=minor, mount_path=volume['mount_path'], cow_path=str(directory/'cow'),
                               cow_relative=cow, cow_unused=[], filesystem_unused=[],
                               attempted=1, released=0, snapshot=snapshot)
            previous = self.volumes.get(volume['filesystem_uuid'])
            if previous:
                old_snapshot, old_data = previous
                bitmap = bytearray(((len(data)+65535)//65536+7)//8)
                for block, offset in enumerate(range(0, len(data), 65536)):
                    if old_data[offset:offset+65536] != data[offset:offset+65536]:
                        bitmap[block//8] |= 1 << (block % 8)
                reservation.update(changes=bytes(bitmap), previous_capture_id=self.previous['id'],
                                   previous_directory=self.previous['reservation']['directory'],
                                   prior=dict(snapshot=old_snapshot, cow_unused=[]))
            current[volume['filesystem_uuid']] = snapshot, data
            reservations.append(reservation)
        primary_reservation = reservations[0]
        primary_snapshot = primary_reservation.pop('snapshot')
        primary_reservation.pop('attempted')
        primary_reservation.pop('released')
        primary_reservation.update(raw_directory=str(directory), raw_directory_inode=directory.stat().st_ino,
                                   raw_cache_policy=dict(cached_enabled=0),raw_storage_ready=1,
                                   directory=str(directory), output=primary_identity,
                                   snapshot_attempted=1, snapshot_released=0,
                                   snapshot_time=122+generation, disks=disk_reservations)
        primary_reservation['extras'] = reservations[1:]
        artifact = artifacts[0]
        if len(artifacts) > 1:
            artifact['additional_images'] = artifacts[1:]
        journal = dict(schema=5, id=f'{generation:032x}',
                       boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                       phase='ready', failure='', failure_disposition='', logs=[], plan=plan,
                       reservation=primary_reservation, snapshot=primary_snapshot, artifact=artifact)
        saved = directory/'capture.pstream'
        saved.write_bytes(wire(journal))
        saved.chmod(0o600)
        self.manifest.write_text('\n'.join(rows)+'\n')
        self.previous, self.volumes = journal, current
        return journal, directory

    def read_mark(self):
        return len(self.trace.read_text().splitlines()) if self.trace.exists() else 0

    def verify_incremental_reads(self, mark, required):
        metadata = {path: ext4_context_metadata_reads(self.snapshot_files[path].read_bytes())
                    for path in required}
        return verify_snapshot_read_coverage(self.trace.read_text().splitlines()[mark:],
                                             required, metadata)

    def verify_reads(self):
        rows = [line.split() for line in self.trace.read_text().splitlines()]
        assert any(kind == 'snap' for kind, *_ in rows), 'no production snapshot reads'
        for kind, path, offset, length in rows:
            if kind != 'raw':
                continue
            offset, length = int(offset), int(length)
            for origin, start, size in self.origins:
                assert path != origin or offset+length <= start or offset >= start+size, (
                    'filesystem payload was read from its changing origin', path, offset, length)
