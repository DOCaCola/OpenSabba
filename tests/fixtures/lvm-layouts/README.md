# Disposable LVM topology fixtures

Reports come from a disposable fixture VG on four 512 MiB loop PVs, independent of backed-up hosts. They model linear, striped, RAID1, legacy mirror, thin, cached, hidden and inactive LVs. UUIDs are fixture identities.

`lvm_layout_fixture.py` collects the reports; `test_lvm_kernel_layouts.py` recreates the layouts with fresh loop devices and cleans them up. Portable tests verify ownership, mappings, hidden classification and identity across device renumbering.
