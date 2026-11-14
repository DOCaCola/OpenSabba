# Machine capture

Every automatic job discovers current disks/volumes and applies NAS entire-device, system-volume or custom selection. Any selected supported filesystem can own the primary snapshot slot; journal field `root` denotes that owner and does not fabricate a `/` mount or boot selection.

Discovery validates MBR/GPT, kernel offsets, mounts, source identities and private work storage in the host mount namespace. Supported sources are ext2/ext3/ext4/XFS direct partitions and public filesystem LVM2 LVs in complete local VGs. Linear, multi-PV, striped, RAID, mirror, thin and cached LVs use logical devices. Hidden/inactive/pool components remain inventory metadata. Encrypted/non-LVM stacks, shared/incomplete VGs and loop machine topology are rejected.

LVM validation checks UUIDs, label CRC, segments, live mapper tables and hidden-to-physical dependencies. Participating physical disks contribute layout and storage-independence checks. UUID topology survives device renumbering.

Selected LVs upload as separate `VG=LV.img` images. Physical images omit entire PV partitions, avoiding overwrite of recovery-created metadata. Wire inventory does not preserve stripes, redundancy, thin provisioning or cache relationships; recovery compatibility needs layout-specific validation.

Capture retains snapshots through upload, then transitions to tracking. It reads sent intervals directly and keeps small raw/static caches, without full local filesystem copies. Raw/static intervals use ordinary device reads without invented remount/freeze policy. Successful cache identity/digest failures are errors; failed creation follows recorded direct/unused classification.

Private journal/cache storage is separate from driver COWs. NAS cache policy resolves storage by volume/task UUID across mount changes. New jobs revalidate current policy; resumed reservations retain exact earlier ownership.

Missing custom members produce warning 7096 while surviving origins continue; unrelated disks are omitted for system/custom selection. Application consistency depends on pre/post scripts. See [policy](task-policy.md), [tracking](persistent-machine-cbt.md), [planning](incremental-plan.md) and [resume](backup-resume.md).
