"""Own loop PVs only; exercise real LVM layouts without synosnap or NAS access."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from lvm_layout_fixture import collect


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f'{args} exited {result.returncode}: {result.stdout}{result.stderr}')
    return result.stdout.strip()


def main():
    if os.geteuid():
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode:
            print("Root privileges unavailable for loop-backed LVM fixture")
            return 77
        return subprocess.call(["sudo", "-n", sys.executable, __file__, *sys.argv[1:]])
    for tool in ("lvm", "losetup", "dmsetup"):
        if not shutil.which(tool):
            print(f"{tool} unavailable")
            return 77
    vg = f"opensabba_layout_test_{os.getpid()}"
    loops = []
    created = False
    with tempfile.TemporaryDirectory(prefix="opensabba-layout-", dir="/lab" if Path("/lab").is_dir() else None) as root:
        directory = Path(root)
        try:
            for index in range(4):
                path = directory / f"pv{index}"
                with path.open("wb") as file:
                    file.truncate(512 * 1024 * 1024)
                loops.append(run("losetup", "-f", "--show", str(path)))
            run("pvcreate", "-y", *loops)
            run("vgcreate", vg, *loops)
            created = True
            run("lvcreate", "-L", "32M", "-n", "linear", vg, loops[0])
            run("lvextend", "-L", "64M", f"{vg}/linear", loops[2])
            run("lvcreate", "-L", "32M", "-i", "2", "-n", "striped", vg)
            run("lvcreate", "-L", "32M", "--type", "raid1", "-m", "1", "-n", "raid", vg)
            run("lvcreate", "-L", "32M", "--type", "mirror", "-m", "1",
                "--mirrorlog", "disk", "-n", "mirrored", vg)
            run("lvcreate", "-L", "64M", "--type", "thin-pool", "-n", "pool", vg)
            run("lvcreate", "-V", "128M", "--thinpool", "pool", "-n", "thin", vg)
            run("lvcreate", "-L", "32M", "-n", "cached", vg)
            run("lvcreate", "-L", "32M", "--type", "cache-pool", "-n", "cachepool", vg)
            run("lvconvert", "-y", "--type", "cache", "--cachepool", f"{vg}/cachepool", f"{vg}/cached")
            run("lvcreate", "-L", "8M", "-n", "inactive", "-an", vg)
            for name in ("linear", "striped", "raid", "mirrored", "thin", "cached"):
                marker = (f"OpenSabba {name} logical bytes\n".encode() * 512)[:4096]
                with open(f"/dev/{vg}/{name}", "r+b", buffering=0) as file:
                    file.seek(1024 * 1024)
                    file.write(marker)
                    os.fsync(file.fileno())
                    file.seek(1024 * 1024)
                    assert file.read(len(marker)) == marker
            collect(directory, vg)
            run(str(Path(sys.argv[1]).resolve()), str(directory))
            before = (directory / "pvs.txt").read_text().splitlines()
            # Enlarge each container by the batch-C 512 KiB, leaving its label,
            # extent count and VG metadata unchanged (no pvresize).
            for index, loop in enumerate(loops):
                with (directory / f"pv{index}").open("r+b") as file:
                    file.truncate(512 * 1024 * 1024 + 512 * 1024)
                run("losetup", "-c", loop)
            collect(directory, vg)
            after = (directory / "pvs.txt").read_text().splitlines()
            assert len(before) == len(after) == 4
            for old, new in zip(before, after):
                old, new = old.split("|"), new.split("|")
                assert old[:9] == new[:9]
                assert int(new[9]) == int(old[9]) + 512 * 1024
            run(str(Path(sys.argv[1]).resolve()), str(directory))
        finally:
            if created:
                # Stop monitoring and deactivate mapper targets before deleting
                # metadata so PV devices are no longer held open at pvremove.
                run("vgchange", "--monitor", "n", vg)
                run("vgchange", "-an", vg)
                run("vgremove", "-fy", vg)
            if loops:
                run("pvremove", "-fy", *loops)
                run("losetup", "-d", *loops)
    print("Real linear/multi-PV/striped/RAID/mirror/thin/cache LVM fixture passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
