"""Collect read-only LVM reports and mapper graphs for owned test VGs."""
from pathlib import Path
import os
import subprocess

VG_COLUMNS = "vg_name,vg_uuid,vg_attr,vg_extent_size,vg_size,vg_mda_size,vg_seqno,pv_count,lv_count,vg_missing_pv_count,vg_lock_type,vg_sysid"
PV_COLUMNS = "pv_name,pv_uuid,vg_uuid,pv_size,pe_start,pv_mda_size,pv_attr,pv_pe_count,pv_mda_count,dev_size"
LV_COLUMNS = "lv_name,lv_uuid,vg_uuid,lv_path,lv_dm_path,lv_attr,lv_size,segtype,seg_start,seg_size,seg_pe_ranges,lv_kernel_major,lv_kernel_minor"


def run(*args):
    return subprocess.check_output(args, text=True).strip() + "\n"


def collect(directory, vg):
    directory = Path(directory)
    for tool, columns in (("vgs", VG_COLUMNS), ("pvs", PV_COLUMNS), ("lvs", LV_COLUMNS)):
        args = [tool, "--noheadings", "--separator", "|", "--units", "b", "--nosuffix",
                "-o", columns, "--select", f"vg_name={vg}"]
        if tool == "lvs":
            args += ["--segments", "--all"]
        (directory / f"{tool}.txt").write_text(run(*args))
    pvs = [row.strip().split("|")[0] for row in (directory / "pvs.txt").read_text().splitlines()]
    for pv in pvs:
        with open(pv, "rb", buffering=0) as source:
            (directory / f"pv-label-{os.path.basename(pv)}.bin").write_bytes(source.read(2048))
    (directory / "devices.txt").write_text("".join(
        f"{pv}|{os.major(os.stat(pv).st_rdev)}|{os.minor(os.stat(pv).st_rdev)}\n" for pv in pvs))
    rows = []
    for node in sorted(Path("/sys/block").glob("dm-*")):
        name = (node / "dm/name").read_text().strip()
        if not name.startswith(vg.replace("-", "--") + "-"):
            continue
        major, minor = (node / "dev").read_text().strip().split(":")
        uuid = (node / "dm/uuid").read_text().strip()
        dependencies = ",".join(sorted((child / "dev").read_text().strip()
                                       for child in (node / "slaves").iterdir()))
        table = run("dmsetup", "table", "--major", major, "--minor", minor)
        index = len(rows)
        (directory / f"node-{index}.txt").write_text(table)
        rows.append(f"{major}|{minor}|{name}|{uuid}|{dependencies}\n")
    (directory / "nodes.txt").write_text("".join(rows))
