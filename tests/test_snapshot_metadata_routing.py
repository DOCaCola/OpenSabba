"""Real production snapshot descriptors, interposed onto temporary ext4 files."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from machine_service_specimens import machine_disk, machine_plan
from snapshot_service_fixture import SnapshotSources
from test_snapshot import filesystem


def main():
    probe, fixture = (str(Path(arg).resolve()) for arg in sys.argv[1:3])
    with tempfile.TemporaryDirectory(prefix='opensabba-metadata-routing-') as directory:
        root = Path(directory)
        part = filesystem(root, bad_blocks=[3500])
        image, boot, boot_size, root_at = machine_disk(part)
        plan = machine_plan(image, boot, boot_size, root_at, len(part))
        sources = SnapshotSources(root)
        _, capture = sources.capture(plan, image)
        descriptors = root/'descriptors.txt'
        env = dict(os.environ, LD_PRELOAD=fixture, OPENSABBA_SOURCE_FIXTURE=str(sources.manifest),
                   OPENSABBA_SOURCE_TRACE=str(sources.trace),
                   OPENSABBA_SOURCE_DESCRIPTOR_TRACE=str(descriptors))
        subprocess.run([probe, str(capture)], env=env, check=True, capture_output=True, text=True, timeout=30)
        events = [line.split() for line in descriptors.read_text().splitlines()]
        events = [row for row in events if row[1:3] == ['snap', '/dev/synosnap2']]
        opened, observed, direct = [], [], []
        identities = {}
        for event, _, path, fd, flags, offset, length, alignment in events:
            fd, flags, offset, length, alignment = map(int, (fd, flags, offset, length, alignment))
            if event == 'open':
                assert not flags & os.O_DIRECT
                opened.append(fd)
                continue
            assert event == 'read' and fd in opened
            if flags & os.O_DIRECT:
                assert len(opened) in (2, 4) and fd == opened[-1]
                assert (offset, length, alignment) == (2*1024*1024, 4096, 0)
                direct.append(fd)
            else:
                assert fd == opened[0 if len(opened) <= 2 else 2]
            observed.append((offset, length, bool(flags & os.O_DIRECT)))
            if not flags & os.O_DIRECT and (offset, length) in ((0, 512), (1024, 1024)):
                identities.setdefault(fd, []).append((offset, length))
        assert len(opened) == 4 and len(set(opened)) == 4 and direct == [opened[1], opened[3]]
        # Each source initializes bad-block context and reads filesystem
        # identity for device-spec metadata. The standalone reader additionally
        # initializes allocation context explicitly; the machine source already
        # carries its captured allocation map. No synthetic image policy runs.
        # official agent initializes allocation context separately ( -> )
        # from bad-block context (), using buffered FS init reads.
        pair = [(0, 512), (1024, 1024)]
        assert identities == {opened[0]: pair * 2, opened[2]: pair * 3}, identities
        assert observed.count((0, 512, False)) == 5, observed
        assert observed.count((1024, 1024, False)) == 5, observed
        print('all filesystem context/identity reads used buffered metadata descriptors; payload used O_DIRECT')


if __name__ == '__main__':
    main()
