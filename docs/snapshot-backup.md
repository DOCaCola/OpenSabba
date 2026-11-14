# Single-volume snapshot backup design

The single-volume provider sends an owned synosnap ext2/ext3/ext4/XFS filesystem through the shared image pipeline with task-selected compression, durable journals and checkpoint recovery.

Metadata validation checks type, UUID, geometry, self-contained journal/log and supported checksums. Mounted/recovery flags are accepted only for an owned frozen snapshot; offline images require clean metadata. This is not a full consistency checker.

Its container uses 512-byte sectors, a generated nonbootable MBR, a Linux partition at 1 MiB and a 1 MiB zero tail. Partition bytes come from the snapshot. MBR identity derives from snapshot UUID, making reopened generation bytes stable. Containers beyond MBR sector limits are rejected. Time comes from creation intent.

The container represents data, without the host bootloader/layout. Machine capture uses separate metadata. Filesystem freezing alone does not quiesce applications.

The source verifies `/dev/synosnapN` registration/size and checks COW/UUID/sequence/health around reads under the control lock. No origin substitution is permitted. Interrupted jobs require the same active source, recorded size/digest, compression and exact NAS job. Release/tracking makes that readable snapshot unavailable.

The installed CLI uses automatic service capture; explicit mutation workflows belong to the optional diagnostic executable. See [recovery](job-recovery.md), [incremental planning](incremental-plan.md) and [generations](snapshot-generations.md).
