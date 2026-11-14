#!/bin/sh
set -eu
# The privileged container exposes host devices and read-only kernel modules.
for module in loop dm_mod dm_raid dm_mirror dm_thin_pool dm_cache; do
  modprobe "$module"
done
# Container udev cannot reliably receive host device-mapper events. Have LVM
# create its own mapper nodes synchronously instead of waiting on host udev.
printf 'activation { udev_sync = 0 udev_rules = 0 }\n' > /etc/lvm/lvm.conf
dmsetup version
dmsetup targets
cmake -S . -B build-test -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build-test --parallel 2
# Volume-inventory and retention tests require a block-backed / and /tmp.
# Clone this job's installed Debian userspace onto an owned ext4 loop root;
# Docker's overlay root has no block-device identity. No tests are excluded.
fixture_image="$RUNNER_TEMP/opensabba-test.ext4"
fixture_root="$RUNNER_TEMP/opensabba-test-root"
truncate -s 8G "$fixture_image"
mkfs.ext4 -F -q "$fixture_image"
fixture_device=$(losetup --find --show "$fixture_image")
fixture_uuid=$(blkid -s UUID -o value "$fixture_device")
mkdir -p /dev/disk/by-uuid "$fixture_root"
ln -s "$fixture_device" "/dev/disk/by-uuid/$fixture_uuid"
mount "$fixture_device" "$fixture_root"
trap 'umount -R "$fixture_root"; rm "/dev/disk/by-uuid/$fixture_uuid"; losetup -d "$fixture_device"; rm "$fixture_image"; rmdir "$fixture_root"' EXIT
# Exclude runner mounts and virtual filesystems from the Debian userspace copy.
# Separate archive/extract commands ensure a failed copy cannot be masked.
tar --one-file-system -C / -cf "$RUNNER_TEMP/opensabba-userspace.tar" bin etc home lib lib64 opt root sbin usr var
tar -C "$fixture_root" -xf "$RUNNER_TEMP/opensabba-userspace.tar"
rm "$RUNNER_TEMP/opensabba-userspace.tar"
mkdir -p "$fixture_root/dev" "$fixture_root/proc" "$fixture_root/sys" "$fixture_root/__w" "$fixture_root/tmp" "$fixture_root/run"
chmod 1777 "$fixture_root/tmp"
for path in dev proc sys; do
  mount --rbind "/$path" "$fixture_root/$path"
  mount --make-rslave "$fixture_root/$path"
done
mount --bind /__w "$fixture_root/__w"
chroot "$fixture_root" /bin/sh -c 'cd "$1"; sh .github/scripts/run-tests.sh' sh "$PWD"
