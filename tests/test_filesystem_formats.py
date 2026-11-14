"""Independent mkfs specimens for all supported Linux data filesystems."""
import argparse
import json
import re
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import uuid

from test_layout import mbr_entry
from test_probe import check


def specimen(root, kind):
    is_xfs = kind.startswith('xfs')
    size = 384 * 1024 * 1024 if is_xfs else 64 * 1024 * 1024
    part = root / f'{kind}.part'
    with part.open('wb') as out:
        out.truncate(size)
    if is_xfs:
        mkfs = shutil.which('mkfs.xfs') or '/usr/sbin/mkfs.xfs'
        command = [mkfs, '-f', '-m', 'crc=0' if kind == 'xfs-v4' else 'crc=1']
        if kind == 'xfs-ag-nonpower':
            command += ['-d', 'agsize=96m', '-l', 'agnum=3']
        command.append(str(part))
    else:
        mkfs = shutil.which('mke2fs') or '/usr/sbin/mke2fs'
        fs_type = 'ext2' if kind == 'ext2-r0' else 'ext4' if kind.startswith('ext4') else kind
        command = [mkfs, '-q', '-F', '-t', fs_type, '-U',
                   str(uuid.uuid5(uuid.NAMESPACE_DNS, kind + '.opensabba')), str(part)]
        if kind == 'ext2-r0':
            command[5:5] = ['-r', '0']
        if kind == 'ext4-bigalloc':
            command[5:5] = ['-O', 'bigalloc', '-b', '4096', '-C', '16384']
        if kind == 'ext4-meta-bg':
            command[5:5] = ['-O', 'meta_bg,^resize_inode', '-g', '256', '-N', '1024']
        if kind == 'ext4-sparse2':
            command[5:5] = ['-O', 'sparse_super2,^sparse_super,^resize_inode']
    subprocess.run(command, check=True, capture_output=True)
    return part


def allocation_oracle(part, kind, probe):
    """Compare with filesystem tools, including their lazy-group/AGFL logic."""
    with part.open('rb') as source:
        raw = source.read(2048)
    free = bytearray(part.stat().st_size // 512)
    def mark(offset, length):
        free[offset // 512:(offset + length) // 512] = b'\1' * (length // 512)
    if kind.startswith('xfs'):
        block = struct.unpack_from('>I', raw, 4)[0]
        agblocks = struct.unpack_from('>I', raw, 84)[0]
        output = subprocess.run(['/usr/sbin/xfs_db', '-r', '-c', 'freesp -d', str(part)],
                                check=True, capture_output=True, text=True).stdout
        for line in output.splitlines():
            match = re.fullmatch(r'\s*(\d+)\s+(\d+)\s+(\d+)', line)
            if match:
                ag, at, count = map(int, match.groups())
                mark((ag * agblocks + at) * block, count * block)
    else:
        block = 1024 << struct.unpack_from('<I', raw, 1024 + 0x18)[0]
        cluster = 1 << (struct.unpack_from('<I', raw, 1024 + 0x1c)[0] -
                        struct.unpack_from('<I', raw, 1024 + 0x18)[0])
        output = subprocess.run(['/usr/sbin/dumpe2fs', str(part)],
                                check=True, capture_output=True, text=True).stdout
        for listed in re.findall(r'^  Free blocks:[ \t]*([^\n]*)$', output, re.MULTILINE):
            for extent in listed.split(','):
                numbers = [int(n) for n in extent.strip().split('-') if n]
                if numbers:
                    start, end = numbers[0], numbers[-1]
                    mark(start * block, (end - start + cluster) * block)
    expected = []
    for at, available in enumerate(free):
        if not available:
            continue
        offset = at * 512
        if expected and sum(expected[-1]) == offset:
            expected[-1][1] += 512
        else:
            expected.append([offset, 512])
    result = subprocess.run([probe, str(part)], check=True, capture_output=True, text=True)
    observed = [[int(n) for n in line.split()] for line in result.stdout.splitlines()]
    check(observed == expected, f'{kind}: filesystem allocation differs from native tools')


def image(root, part):
    target = root / 'disk.img'
    offset = 1024 * 1024
    with target.open('wb') as out:
        mbr = bytearray(512)
        mbr[446:462] = mbr_entry(0x83, offset // 512, part.stat().st_size // 512)
        mbr[510:512] = b'\x55\xaa'
        out.write(mbr)
        out.seek(offset)
        with part.open('rb') as source:
            shutil.copyfileobj(source, out, 1024 * 1024)
        out.truncate(offset + part.stat().st_size + offset)
    return target


def crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return (~crc) & 0xffffffff


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    parser.add_argument('allocation_probe')
    args = parser.parse_args()
    if not Path(shutil.which('mkfs.xfs') or '/usr/sbin/mkfs.xfs').is_file():
        raise RuntimeError('mkfs.xfs is required for filesystem_formats_integration')
    with tempfile.TemporaryDirectory(prefix='opensabba-formats-') as directory:
        root = Path(directory)
        tested = []
        for kind in ('ext2', 'ext2-r0', 'ext3', 'ext4', 'ext4-bigalloc',
                     'ext4-meta-bg', 'ext4-sparse2', 'xfs', 'xfs-v4', 'xfs-ag-nonpower'):
            part = specimen(root, kind)
            allocation_oracle(part, kind, args.allocation_probe)
            target = image(root, part)
            def inspect(expected=True):
                result = subprocess.run(
                    [args.executable, 'image-spec', str(target), '--sector-size', '512',
                     '--image-name', 'format-specimen'],
                    capture_output=True, text=True, timeout=30)
                check((result.returncode == 0) == expected, result.stdout + result.stderr)
                return json.loads(result.stdout) if expected else result.stderr
            spec = inspect()
            volume = spec['device_spec']['disk_layout']['0'][0]
            expected_type = 'xfs' if kind.startswith('xfs') else (
                'ext2' if kind == 'ext2-r0' else 'ext4' if kind.startswith('ext4') else kind)
            check(volume['file_system'] == expected_type and volume['volume_name'] != '',
                  f'{kind} was mislabeled or lost identity')
            with target.open('r+b') as out:
                position = 1024 * 1024 + (0 if kind.startswith('xfs') else 1024)
                out.seek(position)
                is_xfs = kind.startswith('xfs')
                original = out.read(4096 if is_xfs else 1024)
                mutations = [
                    (4 if is_xfs else 0x18, b'\xff\xff\xff\xff',
                     'geometry' if is_xfs else 'block size'),
                    (32 if is_xfs else 0x68, b'\0' * 16, 'UUID'),
                ]
                if is_xfs:
                    mutations.append((104, b'\0\0', 'geometry'))
                if kind != 'xfs-v4':
                    mutations.append((224 if is_xfs else 0x38, b'\0' * 4,
                                      'checksum' if is_xfs else 'filesystem'))
                for relative, value, reason in mutations:
                    changed = bytearray(original)
                    changed[relative:relative+len(value)] = value
                    if is_xfs and kind != 'xfs-v4' and relative != 224:
                        sector = struct.unpack_from('>H', changed, 102)[0]
                        changed[224:228] = b'\0' * 4
                        struct.pack_into('<I', changed, 224, crc32c(changed[:sector]))
                    if kind.startswith('ext4'):
                        struct.pack_into('<I', changed, 0x3fc, (~crc32c(changed[:0x3fc])) & 0xffffffff)
                    out.seek(position)
                    out.write(changed)
                    out.flush()
                    error = inspect(False)
                    check(reason.lower() in error.lower(), f'{kind}: unexpected rejection: {error}')
                    out.seek(position)
                    out.write(original)
                    out.flush()
                if not is_xfs:
                    changed = bytearray(original)
                    changed[0x3a:0x3c] = b'\0\0'
                    out.seek(position)
                    out.write(changed)
                    out.flush()
                    check('clean' in inspect(False).lower(), f'{kind}: dirty offline image accepted')
                    out.seek(position)
                    out.write(original)
                    out.flush()
                if kind == 'ext3':
                    changed = bytearray(original)
                    flags = struct.unpack_from('<I', changed, 0x60)[0]
                    struct.pack_into('<I', changed, 0x60, flags | 0x8)
                    out.seek(position)
                    out.write(changed)
                    out.flush()
                    check('external journal' in inspect(False).lower(),
                          'ext3 external journal accepted')
                    out.seek(position)
                    out.write(original)
                    out.flush()
                if kind == 'xfs-ag-nonpower':
                    log_start = struct.unpack_from('>Q', original, 48)[0]
                    dblocks = struct.unpack_from('>Q', original, 8)[0]
                    check(log_start >= dblocks, 'fixture did not exercise encoded AG address')
                    aglog = original[124]
                    agcount = struct.unpack_from('>I', original, 88)[0]
                    agblocks = struct.unpack_from('>I', original, 84)[0]
                    for bad_log in ((agcount << aglog), ((agcount-1) << aglog) | agblocks):
                        changed = bytearray(original)
                        struct.pack_into('>Q', changed, 48, bad_log)
                        sector = struct.unpack_from('>H', changed, 102)[0]
                        changed[224:228] = b'\0' * 4
                        struct.pack_into('<I', changed, 224, crc32c(changed[:sector]))
                        out.seek(position)
                        out.write(changed)
                        out.flush()
                        check('log geometry' in inspect(False).lower(),
                              'out-of-range XFS AG log address accepted')
                        out.seek(position)
                        out.write(original)
                        out.flush()
            check(inspect()['device_spec']['disk_layout']['0'][0]['file_system'] == expected_type,
                  f'{kind} restoration failed')
            tested.append(kind)
    print('/'.join(tested), 'independent filesystem metadata specimens passed')


if __name__ == '__main__':
    main()
