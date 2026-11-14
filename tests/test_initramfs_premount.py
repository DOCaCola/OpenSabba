"""Execute the boot hook with command fixtures; never touch a real block device.

Only absolute filesystem endpoints are relocated into a temporary directory.
The shell executes the production decisions, with kernel/device commands supplied
as shell functions. This runs on native Windows/MSYS2 as well as Linux.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SHELL = sys.argv.pop(1)
HOOK = Path(__file__).resolve().parents[1] / "packaging/initramfs/opensabba-premount"

COMMANDS = r'''
trace() { printf '%s\n' "$*" >> "$TRACE"; }
# Only the block-device predicate uses test; other predicates use real [.
test() { trace "block-test $2"; command test "$BLOCK_READY" = 1; }
modprobe() { trace "modprobe $*"; return "$MODULE_STATUS"; }
udevadm() { trace "udevadm $*"; }
blkid() {
    trace "blkid $*"
    if command [ -f "$VG_ACTIVE" ]; then printf '%s' "$FS_AFTER";
    else printf '%s' "$FS_BEFORE"; fi
}
vgchange() {
    trace "vgchange $*"
    if command [ "$1" = -ay ]; then : > "$VG_ACTIVE"; fi
}
blockdev() {
    trace "blockdev $*"
    if command [ "$1" = --setro ]; then return "$SETRO_STATUS"; fi
    return "$SETRW_STATUS"
}
mount() { trace "mount $*"; return "$MOUNT_STATUS"; }
umount() { trace "umount $*"; return "$UMOUNT_STATUS"; }
'''


class PremountTests(unittest.TestCase):
    def run_hook(self, *, root="/dev/dm-0", filesystem=None, records=(0, 0), **changes):
        with tempfile.TemporaryDirectory(prefix="opensabba-premount-") as temporary:
            work = Path(temporary)
            # Use paths relative to cwd so native Python and the MSYS shell agree.
            (work / "root/etc/synosnap/dla").mkdir(parents=True)
            for number, status in enumerate(records):
                record = work / f"root/etc/synosnap/dla/reload_{number}"
                record.write_text(
                    f"#!/bin/sh\nprintf 'reload {number}\n' >> trace\nexit {status}\n",
                    encoding="utf-8", newline="\n")
                record.chmod(0o755)
            source = HOOK.read_text(encoding="utf-8")
            source = source.replace("/dev/kmsg", "kmsg")
            source = source.replace("mountpoint=/etc/synosnap/dla/mnt", "mountpoint=root")
            source = source.replace("/sbin/vgchange", "vgchange")
            (work / "hook").write_text(COMMANDS + source, encoding="utf-8", newline="\n")
            env = dict(os.environ, ROOT=root, TRACE="trace", VG_ACTIVE="vg-active",
                       BLOCK_READY="1", MODULE_STATUS="0", FS_BEFORE="ext4", FS_AFTER="ext4",
                       SETRO_STATUS="0", SETRW_STATUS="0", MOUNT_STATUS="0", UMOUNT_STATUS="0")
            env.pop("ROOTFSTYPE", None)
            if filesystem is not None:
                env["ROOTFSTYPE"] = filesystem
            env.update({key: str(value) for key, value in changes.items()})
            result = subprocess.run([SHELL, "hook"], cwd=work, env=env, text=True,
                                    encoding="utf-8", capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            # Failed stale commands are retained for the next boot, and do
            # not stop subsequent reloads or cause an origin-missing sweep.
            self.assertEqual(sorted(path.name for path in (work / "root/etc/synosnap/dla").iterdir()),
                             [f"reload_{number}" for number in range(len(records))])
            return (work / "trace").read_text(encoding="utf-8").splitlines()

    @staticmethod
    def prefix(origin="/dev/dm-0", probe=True):
        result = ["modprobe synosnap", f"block-test {origin}"]
        if probe:
            result.append(f"blkid -s TYPE -o value {origin}")
        return result

    @staticmethod
    def mount(origin="/dev/dm-0", filesystem="ext4"):
        return [f"blockdev --setro {origin}", f"mount -t {filesystem} -o ro {origin} root"]

    def test_clean_root_order_and_reload_failure_continuation(self):
        self.assertEqual(self.run_hook(records=(22, 0)), self.prefix() + self.mount() + [
            "udevadm settle", "reload 0", "reload 1", "umount -f root", "blockdev --setrw /dev/dm-0"])

    def test_multiple_stale_reloads_are_kept_and_iteration_continues(self):
        self.assertEqual(self.run_hook(records=(22, 22, 0)), self.prefix() + self.mount() + [
            "udevadm settle", "reload 0", "reload 1", "reload 2",
            "umount -f root", "blockdev --setrw /dev/dm-0"])

    def test_dirty_root_mount_failure_skips_every_reload_without_recovery_retry(self):
        self.assertEqual(self.run_hook(MOUNT_STATUS=30), self.prefix() + self.mount() + [
            "blockdev --setrw /dev/dm-0"])

    def test_supplied_filesystem_type_precedes_probe_and_lvm(self):
        self.assertEqual(self.run_hook(filesystem="xfs", FS_BEFORE="", records=()),
                         self.prefix(probe=False) + self.mount(filesystem="xfs") + [
                             "udevadm settle", "umount -f root", "blockdev --setrw /dev/dm-0"])

    def test_missing_type_activates_then_deactivates_lvm_even_with_existing_node(self):
        for mount_status in (0, 30):
            with self.subTest(mount_status=mount_status):
                expected = self.prefix() + ["vgchange -ay", "blkid -s TYPE -o value /dev/dm-0"]
                expected += self.mount()
                if not mount_status:
                    expected += ["udevadm settle", "reload 0", "reload 1", "umount -f root"]
                expected += ["vgchange -an", "blockdev --setrw /dev/dm-0"]
                self.assertEqual(self.run_hook(FS_BEFORE="", MOUNT_STATUS=mount_status), expected)

    def test_device_settle_precedes_type_probe(self):
        expected = self.prefix()
        expected.insert(2, "udevadm settle")
        self.assertEqual(self.run_hook(BLOCK_READY=0, MOUNT_STATUS=30),
                         expected + self.mount() + ["blockdev --setrw /dev/dm-0"])

    def test_official_root_device_links(self):
        for root, origin in (
            ("block:/dev/mapper/vg-root", "/dev/mapper/vg-root"),
            ("UUID=test-uuid", "/dev/disk/by-uuid/test-uuid"),
            ("LABEL=root/label", r"/dev/disk/by-label/root\x2flabel"),
            ("PARTUUID=test-partuuid", "/dev/disk/by-partuuid/test-partuuid"),
            ("PARTLABEL=root-part", "/dev/disk/by-partlabel/root-part"),
            # official agent's UUID expansion uses ROOT rather than the normalized rbd.
            ("block:UUID=test-uuid", "/dev/disk/by-uuid/block:UUID=test-uuid"),
        ):
            with self.subTest(root=root):
                self.assertEqual(self.run_hook(root=root, MOUNT_STATUS=30),
                                 self.prefix(origin) + self.mount(origin) + [f"blockdev --setrw {origin}"])

    def test_blockdev_and_unmount_failure_do_not_abort_boot(self):
        self.assertEqual(self.run_hook(SETRO_STATUS=1, UMOUNT_STATUS=1, SETRW_STATUS=1),
                         self.prefix() + self.mount() + ["udevadm settle", "reload 0", "reload 1",
                                                        "umount -f root", "blockdev --setrw /dev/dm-0"])

    def test_missing_module_or_root_does_no_device_work(self):
        self.assertEqual(self.run_hook(MODULE_STATUS=1), ["modprobe synosnap"])
        self.assertEqual(self.run_hook(root=""), ["modprobe synosnap"])


if __name__ == "__main__":
    unittest.main()
