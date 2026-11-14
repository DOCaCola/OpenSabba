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
# Retention fixtures resolve the filesystem behind /tmp through /sys/dev/block;
# Docker's overlay filesystem has no such block device. Use an owned ext4 loop.
fixture_image="$RUNNER_TEMP/opensabba-test.ext4"
truncate -s 4G "$fixture_image"
mkfs.ext4 -F -q "$fixture_image"
fixture_device=$(losetup --find --show "$fixture_image")
fixture_uuid=$(blkid -s UUID -o value "$fixture_device")
mkdir -p /dev/disk/by-uuid
ln -s "$fixture_device" "/dev/disk/by-uuid/$fixture_uuid"
mount "$fixture_device" /tmp
chmod 1777 /tmp
trap 'umount /tmp; rm "/dev/disk/by-uuid/$fixture_uuid"; losetup -d "$fixture_device"; rm "$fixture_image"' EXIT
cmake -S . -B build-test -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build-test --parallel 2
# Run real loop/LVM and privileged device-node/xattr restore cases as root.
privileged='^(lvm_kernel_layouts|file_restore_official_filesystem_integration)$'
ctest --test-dir build-test --output-on-failure -R "$privileged" --output-junit privileged.xml
# Permission-denial fault injection requires an ordinary user. Run every other
# test without root; the two tests excluded here were executed above.
chown -R 65534:65534 build-test
mkdir /tmp/opensabba-ci-home
chown 65534:65534 /tmp/opensabba-ci-home
setpriv --reuid=65534 --regid=65534 --clear-groups \
  env HOME=/tmp/opensabba-ci-home USER=nobody LOGNAME=nobody \
  ctest --test-dir build-test --output-on-failure --parallel 2 -E "$privileged" --output-junit unprivileged.xml
# CTest treats a fixture returning 77 as success; CI must never silently skip it.
python3 - <<'PY'
import xml.etree.ElementTree as ET
for report in ['privileged.xml', 'unprivileged.xml']:
    root = ET.parse('build-test/' + report).getroot()
    skipped = [case.attrib['name'] for case in root.iter('testcase') if case.find('skipped') is not None]
    if skipped:
        raise SystemExit('Unexpected skipped tests: ' + ', '.join(skipped))
PY
