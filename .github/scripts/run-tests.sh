#!/bin/sh
set -eu
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
