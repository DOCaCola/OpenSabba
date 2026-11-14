#!/bin/sh
set -eu
# The privileged container exposes host devices and read-only kernel modules.
# lvm_kernel_layouts owns its loop PVs and needs these device-mapper targets.
for module in loop dm_mod dm_raid dm_mirror dm_thin_pool dm_cache; do
  modprobe "$module"
done
/usr/lib/systemd/systemd-udevd --daemon
udevadm trigger
udevadm settle
cmake -S . -B build-test -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build-test --parallel 2
ctest --test-dir build-test --output-on-failure --parallel 2 --output-junit results.xml
# CTest treats a fixture returning 77 as success; CI must never silently skip it.
python3 - <<'PY'
import xml.etree.ElementTree as ET
root = ET.parse('build-test/results.xml').getroot()
skipped = [case.attrib['name'] for case in root.iter('testcase') if case.find('skipped') is not None]
if skipped:
    raise SystemExit('Unexpected skipped tests: ' + ', '.join(skipped))
PY
