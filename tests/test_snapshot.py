"""Real mke2fs images; independent partition tables and recovery metadata checks."""
import argparse
import binascii
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import uuid

from test_probe import check
from test_layout import mbr_entry

FS_UUID = uuid.UUID('12345678-1234-5678-9abc-123456789abc')


def filesystem(root, bad_blocks=()):
    contents = root / 'contents'
    contents.mkdir()
    (contents / 'restore-check.txt').write_text('OpenSabba independent restore specimen\n')
    part = root / 'partition.ext4'
    with part.open('wb') as stream:
        stream.truncate(16*1024*1024)
    bad_options = []
    if bad_blocks:
        listed = root/'badblocks.txt'
        listed.write_text(''.join(f'{block}\n' for block in bad_blocks))
        bad_options = ['-l', str(listed)]
    subprocess.run([shutil.which('mke2fs') or '/usr/sbin/mke2fs', '-q', '-t', 'ext4',
                    '-F', '-b', '4096', '-U', str(FS_UUID), '-d', str(contents), *bad_options, str(part)],
                   check=True, capture_output=True)
    subprocess.run([shutil.which('e2fsck') or '/usr/sbin/e2fsck', '-fn', str(part)],
                   check=True, capture_output=True)
    return part.read_bytes()


def disk(part, sector=512, scheme='MBR'):
    offset = 1024*1024
    image = bytearray(len(part)+2*offset)
    image[510:512] = b'\x55\xaa'
    image[offset:offset+len(part)] = part
    if scheme == 'MBR':
        image[446:462] = mbr_entry(0x83, offset//sector, len(part)//sector)
    else:
        sectors = len(image)//sector
        image[446:462] = mbr_entry(0xee, 1, sectors-1)
        entries = bytearray(16384)
        entries[:16] = uuid.UUID('0fc63daf-8483-4772-8e79-3d69d8477de4').bytes_le
        entries[16:32] = uuid.UUID('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee').bytes_le
        struct.pack_into('<QQ', entries, 32, offset//sector, (offset+len(part))//sector-1)
        backup_table = sectors - 1 - len(entries)//sector
        for current, alternate, table in ((1, sectors-1, 2), (sectors-1, 1, backup_table)):
            header = bytearray(sector)
            header[:8] = b'EFI PART'
            struct.pack_into('<IIIIQQQQ', header, 8, 0x10000, 92, 0, 0, current, alternate,
                             2+len(entries)//sector, backup_table-1)
            header[56:72] = uuid.UUID('11223344-5566-7788-99aa-bbccddeeff00').bytes_le
            struct.pack_into('<QIII', header, 72, table, 128, 128, binascii.crc32(entries))
            struct.pack_into('<I', header, 16, binascii.crc32(header[:92]))
            image[current*sector:(current+1)*sector] = header
            image[table*sector:table*sector+len(entries)] = entries
    return image


def check_spec(spec, size, sector=512, scheme='MBR'):
    check(spec['agent_version'] == '5059', 'agent dialect')
    device = spec['device_spec']
    check(all(device[key] is False for key in ('is_volume', 'is_bootable', 'is_system_mbr')),
          'false host/boot claims or incorrect JSON boolean types')
    check(device['mount_map'] == {} and device['volume_groups'] == [] and
          device['unsupported_volumes'] == [], 'invented mounted volumes')
    stats = device['images'][0]
    check(stats['image_name'] == 'test-image' and stats['excluded_length'] == '0', 'image identity')
    for key in ('length', 'used_length', 'original_used_length', 'changed_length',
                'transfer_length', 'transfer_length_4k'):
        check(stats[key] == str(size), f'wrong byte statistics: {key}')
    volumes = device['disk_layout']['0']
    check(len(volumes) == 1 and volumes[0]['volume_name'] == str(FS_UUID) and
          volumes[0]['file_system'] == 'ext4' and volumes[0]['bytes_per_sector'] == sector,
          'wrong filesystem identity or sector size')
    image = spec['disk_images'][0]
    check(image['disk_layout'] == scheme and image['disk_number'] == '0' and
          image['image_name'] == 'test-image' and image['need_upload'] is True, 'image descriptor')
    at = 0
    check([v['type'] for v in image['intervals']] == [3, 1, 3], 'partition/gap coverage')
    for interval in image['intervals']:
        start, end = int(interval['disk_start']), int(interval['disk_end'])
        check(start == at and start < end, 'gap or overlap in recovery intervals')
        for prefix in ('source', 'destination'):
            check(interval[prefix+'_start'] == str(start) and interval[prefix+'_end'] == str(end),
                  'wrong fixed-file offset mapping')
        check(interval['path'] == 'test-image', 'host source path leaked')
        at = end
    check(at == size, 'tail missing from recovery metadata')
    check(image['intervals'][1]['volume_name'] == str(FS_UUID), 'partition GUID used as filesystem UUID')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    args = parser.parse_args()
    executable = str(Path(args.executable).resolve())
    with tempfile.TemporaryDirectory(prefix='opensabba-snapshot-') as directory:
        root = Path(directory)
        part = filesystem(root)
        path = root / 'disk.img'

        def run(data, sector=512, expected=True):
            path.write_bytes(data)
            result = subprocess.run([executable, 'image-spec', str(path), '--sector-size', str(sector),
                                     '--image-name', 'test-image'], capture_output=True, text=True, timeout=5)
            check((result.returncode == 0) == expected, result.stdout + result.stderr)
            if expected:
                return json.loads(result.stdout)
            check(result.stdout == '', 'partial metadata emitted on failure')

        for sector in (512, 4096):
            for scheme in ('MBR', 'GPT'):
                data = disk(part, sector, scheme)
                check_spec(run(data, sector), len(data), sector, scheme)
        good = disk(part)
        sb = 1024*1024+1024
        for relative in (0x38, 0x68, 0x175, 0x3fc, 0x150):
            bad = good.copy()
            bad[sb+relative] ^= 1
            run(bad, expected=False)
        # Disable metadata checksum to exercise semantic validation separately.
        for field, fmt, invalid in ((0x3a, '<H', 0), (0x60, '<I', 0x44),
                                    (0x18, '<I', 63), (4, '<I', 0xffffffff),
                                    (0x14, '<I', 1), (0xe4, '<I', 1)):
            bad = good.copy()
            struct.pack_into('<I', bad, sb+0x64, 0)
            struct.pack_into(fmt, bad, sb+field, invalid)
            run(bad, expected=False)
        bad = good.copy()
        bad[450] = 7
        run(bad, expected=False)
        bad = good.copy()
        bad[sb+0x68:sb+0x78] = b'\0'*16
        struct.pack_into('<I', bad, sb+0x64, 0)
        run(bad, expected=False)
        # Two independently valid partitions with colliding filesystem identity.
        bad = bytearray(len(good)+len(part))
        bad[:len(good)] = good
        offset = 1024*1024+len(part)
        bad[offset:offset+len(part)] = part
        bad[462:478] = mbr_entry(0x83, offset//512, len(part)//512)
        run(bad, expected=False)
    print('Real ext4 MBR/GPT metadata and corruption tests passed')


if __name__ == '__main__':
    main()
