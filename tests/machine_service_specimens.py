"""Independent FAT/ext4/LVM specimens shared by native service receivers."""
import hashlib
import shutil
import struct
import subprocess
from test_snapshot import FS_UUID
from test_layout import mbr_entry

def machine_disk(part):
    mib = 1024 * 1024
    boot = mib
    boot_size = 8 * mib
    root = 10 * mib
    image = bytearray(root + len(part) + mib)
    image[510:512] = b'\x55\xaa'
    image[446:462] = mbr_entry(0x06, boot // 512, boot_size // 512)
    image[462:478] = mbr_entry(0x83, root // 512, len(part) // 512)
    image[root:root + len(part)] = part
    image[boot] = 0xeb
    image[boot + 2] = 0x90
    struct.pack_into('<H', image, boot + 11, 512)
    image[boot + 13] = 1
    struct.pack_into('<H', image, boot + 14, 1)
    image[boot + 16] = 2
    struct.pack_into('<H', image, boot + 17, 512)
    struct.pack_into('<H', image, boot + 19, boot_size // 512)
    image[boot + 21] = 0xf8
    struct.pack_into('<H', image, boot + 22, 64)
    image[boot + 38] = 0x29
    struct.pack_into('<I', image, boot + 39, 0x1234abcd)
    image[boot + 510:boot + 512] = b'\x55\xaa'
    for fat in (boot + 512, boot + 512 + 64 * 512):
        struct.pack_into('<HH', image, fat, 0xfff8, 0xffff)
    # A single physical image must also skip excluded partitions on the wire.
    swap = len(image)
    image.extend(bytes(4 * 1024 * 1024))
    image[478:494] = mbr_entry(0x82, swap // 512, 4 * 1024 * 1024 // 512)
    return image, boot, boot_size, root


def machine_plan(image, boot, boot_size, root, root_size):
    def partition(number, offset, length, kind):
        return dict(number=number, offset=offset, length=length, attributes=0,
                    mbr_type=kind, bootable=0, type_guid='', uuid='')

    layout = dict(scheme='MBR', sector_size=512, length=len(image), disk_id='00000000',
                  partitions=[partition(1, boot, boot_size, 0x06),
                              partition(2, root, root_size, 0x83),
                              partition(3, root + root_size + 1024*1024, 4*1024*1024, 0x82)])
    return dict(layout=layout, other_disk_count=0,
                boot=dict(partition=1, device='/dev/sda1', offset=boot, length=boot_size,
                          mount_path='/boot/firmware', filesystem='vfat',
                          filesystem_uuid='1234-ABCD'),
                root=dict(partition=2, device='/dev/sda2', offset=root, length=root_size,
                          mount_path='/', filesystem='ext4',
                          filesystem_uuid=str(FS_UUID)),
                excluded=[dict(partition=3, offset=root + root_size + 1024*1024,
                               length=4*1024*1024, mount_path='', filesystem='swap')])


def external_disk(root):
    mib = 1024*1024
    contents = root/"extra-contents"
    contents.mkdir()
    (contents/"selected.txt").write_text("selected from second disk\n")
    partition = root/"extra.ext4"
    with partition.open("wb") as stream:
        stream.truncate(16*mib)
    extra_uuid = "22345678-1234-5678-9abc-123456789abc"
    subprocess.run([shutil.which("mke2fs") or "/usr/sbin/mke2fs", "-q", "-t", "ext4",
                    "-F", "-b", "4096", "-U", extra_uuid, "-d", str(contents), str(partition)],
                   check=True, capture_output=True)
    part = partition.read_bytes()
    image = bytearray(24*mib)
    image[510:512] = b"\x55\xaa"
    image[446:462] = mbr_entry(0x83, mib//512, len(part)//512)
    image[462:478] = mbr_entry(0x83, 18*mib//512, 4*mib//512)
    image[mib:mib+len(part)] = part
    layout = dict(scheme="MBR", sector_size=512, length=len(image), disk_id="00000000",
        partitions=[
            dict(number=1, offset=mib, length=len(part), attributes=0,
                 mbr_type=0x83, bootable=0, type_guid="", uuid=""),
            dict(number=2, offset=18*mib, length=4*mib, attributes=0,
                 mbr_type=0x83, bootable=0, type_guid="", uuid="")])
    plan = dict(layout=layout, selected_extra=[
        dict(partition=1, device="/dev/sdc1", offset=mib, length=len(part), mount_path="/data",
             filesystem="ext4", filesystem_uuid=extra_uuid, disk_index=1)],
        excluded=[dict(partition=2, offset=18*mib, length=4*mib,
                       mount_path="", filesystem="")])
    return bytes(image), plan


def lvm_disk(root):
    """Independent 2-MDA PV specimen; label sector 3, PV header offset 128."""
    mib = 1024*1024
    pv_uuid = "cirf6F-63C1-Qk0t-XPzE-y9A8-2Cml-z4RX56"
    vg_uuid = "q04wOI-lPGf-DSZg-TYVi-mTCu-zH1g-eph3oB"
    lv_uuid = "MxX85h-78Vn-7Tc8-MS1V-33Hk-0HyZ-mglV98"
    lv_fs_uuid = "32345678-1234-5678-9abc-123456789abc"
    contents = root/"lv-contents"
    contents.mkdir()
    (contents/"selected.txt").write_text("selected LVM volume\n")
    lv_file = root/"selected.ext4"
    with lv_file.open("wb") as stream:
        stream.truncate(8*mib)
    subprocess.run([shutil.which("mke2fs") or "/usr/sbin/mke2fs", "-q", "-t", "ext4",
                    "-F", "-b", "4096", "-U", lv_fs_uuid, "-d", str(contents), str(lv_file)],
                   check=True, capture_output=True)
    lv = lv_file.read_bytes()
    pv = bytearray(16*mib)
    label = memoryview(pv)[3*512:4*512]
    label[:8] = b"LABELONE"
    struct.pack_into("<Q", label, 8, 3)
    struct.pack_into("<I", label, 20, 128)
    label[24:32] = b"LVM2 001"
    label[128:160] = pv_uuid.replace("-", "").encode()
    struct.pack_into("<QQ", label, 160, len(pv), mib)
    struct.pack_into("<QQ", label, 176, 12*mib, 0)
    struct.pack_into("<QQ", label, 200, 4096, 4096)
    struct.pack_into("<QQ", label, 216, 15*mib, 4096)
    checksum = 0xf597a6cf
    for octet in label[20:]:
        checksum ^= octet
        for _ in range(8):
            checksum = (checksum >> 1) ^ (0xedb88320 if checksum & 1 else 0)
    struct.pack_into("<I", label, 16, checksum)
    pv[4096:4104] = b"PV-MDA-1"
    pv[15*mib:15*mib+8] = b"PV-MDA-2"
    image = bytearray(24*mib)
    image[510:512] = b"\x55\xaa"
    image[446:462] = mbr_entry(0x8e, mib//512, len(pv)//512)
    # The source PV supplies validated fingerprints to the plan. Its entire
    # partition is excluded from the physical NAS wire image.
    layout = dict(scheme="MBR", sector_size=512, length=len(image), disk_id="00000000",
                  partitions=[dict(number=1, offset=mib, length=len(pv), attributes=0,
                                   mbr_type=0x8e, bootable=0, type_guid="", uuid="")])
    excluded = dict(partition=1, device="/dev/sdc1", offset=mib, length=len(pv), mount_path="",
                    filesystem="LVM2_member", pv_uuid=pv_uuid, vg_uuid=vg_uuid,
                    pv_wire_policy="whole-partition-zero",
                    pv_metadata_length=mib, pv_extent_length=12*mib,
                    pv_mda_size=4096, pv_mda_count=2,
                    pv_metadata_sha256=hashlib.sha256(pv[:mib]).hexdigest(),
                    pv_tail_length=3*mib,
                    pv_tail_sha256=hashlib.sha256(pv[13*mib:]).hexdigest())
    selected = dict(lv_name="selected", lv_uuid=lv_uuid, vg_uuid=vg_uuid,
                    image_name="fixture_vg=selected.img", length=len(lv), offset=0,
                    partition=0, disk_index=0, mount_path="/data", filesystem="ext4",
                    filesystem_uuid=lv_fs_uuid, logical_path="/dev/fixture_vg/selected",
                    segments=[dict(logical_offset=0, length=len(lv),
                                   pv_uuid=pv_uuid, pv_offset=mib)])
    group = dict(name="fixture_vg", uuid=vg_uuid, extent_size=4*mib, mda_size=4096,
                 total_size=12*mib, physical_volumes=[dict(name="/dev/sdc1",
                     uuid=pv_uuid, size=12*mib)],
                 logical_volumes=[dict(name="selected", uuid=lv_uuid,
                     file_system="ext4", size=len(lv)),
                     dict(name="excluded", uuid="dW8KcU-MfCo-awHT-Aqhj-CK4U-TPmW-51AfRb",
                          file_system="", size=4*mib)])
    return bytes(image), lv, dict(disk="/dev/sdc", layout=layout,
                                  selected_extra=[], excluded=[excluded]), selected, group
