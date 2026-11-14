"""Independent MBR/GPT fixtures, including individually valid but conflicting copies."""
import argparse
import binascii
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import uuid

from test_probe import check

DISK = uuid.UUID('11223344-5566-7788-99aa-bbccddeeff00')
TYPE = uuid.UUID('0fc63daf-8483-4772-8e79-3d69d8477de4')
PART = uuid.UUID('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')


def mbr_entry(kind, start, count):
    result = bytearray(16)
    result[4] = kind
    struct.pack_into('<II', result, 8, start, count)
    return result


def gpt(sector=512):
    sectors = 128
    image = bytearray(sectors * sector)
    image[510:512] = b'\x55\xaa'
    image[446:462] = mbr_entry(0xee, 1, sectors-1)
    entries = bytearray(16384)
    entries[:16] = TYPE.bytes_le
    entries[16:32] = PART.bytes_le
    first = 2 + len(entries) // sector
    last = sectors - 2 - len(entries) // sector
    struct.pack_into('<QQQ', entries, 32, first, first + 7, 0)

    def header(current, alternate, table):
        result = bytearray(sector)
        result[:8] = b'EFI PART'
        struct.pack_into('<IIIIQQQQ', result, 8, 0x10000, 92, 0, 0, current, alternate, first, last)
        result[56:72] = DISK.bytes_le
        struct.pack_into('<QIII', result, 72, table, 128, 128, binascii.crc32(entries))
        struct.pack_into('<I', result, 16, binascii.crc32(result[:92]))
        return result
    backup_table = sectors - 1 - len(entries) // sector
    image[sector:2*sector] = header(1, sectors-1, 2)
    image[2*sector:2*sector+len(entries)] = entries
    image[backup_table*sector:(sectors-1)*sector] = entries
    image[(sectors-1)*sector:] = header(sectors-1, 1, backup_table)
    return image, first


def repair_header(image, sector, lba):
    at = sector * lba
    struct.pack_into('<I', image, at+16, 0)
    struct.pack_into('<I', image, at+16, binascii.crc32(image[at:at+92]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    args = parser.parse_args()
    exe = str(Path(args.executable).resolve())
    with tempfile.TemporaryDirectory(prefix='opensabba-layout-') as directory:
        path = Path(directory) / 'disk.img'
        def run(data, sector=512, expected=True):
            path.write_bytes(data)
            result = subprocess.run([exe, 'image-layout', str(path), '--sector-size', str(sector)],
                                    text=True, capture_output=True, timeout=5)
            check((result.returncode == 0) == expected, result.stdout + result.stderr)
            if expected:
                return json.loads(result.stdout)
        mbr = bytearray(128*512)
        mbr[510:512] = b'\x55\xaa'
        mbr[446:462] = mbr_entry(0x83, 8, 64)
        parsed = run(mbr)
        check(parsed['scheme'] == 'MBR' and parsed['partitions'][0]['offset'] == 4096 and
              parsed['partitions'][0]['length'] == 32768, 'MBR extent mismatch')
        for kind in (5, 15, 0x85):
            broken = mbr.copy()
            broken[450] = kind
            run(broken, expected=False)
        broken = mbr.copy()
        broken[462:478] = mbr_entry(0x83, 60, 30)
        run(broken, expected=False)
        broken[462:478] = mbr_entry(0x83, 126, 30)
        run(broken, expected=False)
        for sector in (512, 4096):
            image, first = gpt(sector)
            parsed = run(image, sector)
            check(parsed['disk_id'] == str(DISK) and parsed['scheme'] == 'GPT', 'GPT disk GUID')
            p = parsed['partitions'][0]
            check(p['uuid'] == str(PART) and p['type_guid'] == str(TYPE) and
                  p['offset'] == first*sector and p['length'] == 8*sector, 'GPT partition mismatch')
            for at in (sector+24, 2*sector+100, 127*sector+24, 126*sector):
                broken = image.copy()
                broken[at] ^= 1
                run(broken, sector, False)
            # Both CRCs valid but headers refer to different disks.
            broken = image.copy()
            broken[127*sector+56] ^= 1
            repair_header(broken, sector, 127)
            run(broken, sector, False)
            # Bounds checked before attempting to allocate attacker-supplied table.
            broken = image.copy()
            struct.pack_into('<II', broken, sector+80, 0xffffffff, 128)
            repair_header(broken, sector, 1)
            run(broken, sector, False)
            # Hybrid partition table is deliberately unsupported.
            broken = image.copy()
            broken[462:478] = mbr_entry(0x83, first, 8)
            run(broken, sector, False)
            # Valid CRCs with overlapping GPT partitions.
            broken = image.copy()
            table = bytearray(broken[2*sector:2*sector+16384])
            table[128:256] = table[:128]
            table[144:160] = uuid.UUID('bbbbbbbb-cccc-dddd-eeee-ffffffffffff').bytes_le
            backup_table = 127 - 16384//sector
            for loc in (2, backup_table):
                broken[loc*sector:loc*sector+16384] = table
            for loc in (1,127):
                struct.pack_into('<I', broken, loc*sector+88, binascii.crc32(table))
                repair_header(broken, sector, loc)
            run(broken, sector, False)
        run(b'\0' * 4096, expected=False)
        run(mbr, 1024, False)
        print('MBR/GPT geometry, checksums, mirrored copies, overlap and resource bounds: passed')


if __name__ == '__main__':
    main()
