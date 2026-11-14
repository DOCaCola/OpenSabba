# Persistent machine change tracking

Automatic capture retains tracking between jobs. First snapshots establish full intervals; renewal uses retained generation maps and the NAS base. Raw/FAT boot and partition-table intervals keep reread rules.

Each origin uses `MOUNT/.synosnap_data/SECONDS_UUID`, with distinct random v4 UUID per renewal/origin. Allocation zero selects the driver's default 10% of the origin. Journals/small raw caches use separate private work storage.

Renewal requires healthy incremental mode and exact origin/minor/COW/UUID/sequence. It opens a new COW and preserves preceding maps plus immutable ancestry. Compact history has 64 KiB bits. Planning combines required maps without hashing/comparing whole images.

Resolved uploads transition to tracking and update reload records, discarding readable snapshot blocks while retaining change context. Pending jobs protect exact sources/maps. Dependency pruning releases only resolved, retired, unneeded owned files.

The driver excludes its COW inode from tracking. Capture records internal COW/history physical extents at the boundary and sends them unused. Free filesystem ranges are excluded independently. Neither is read as payload. Used/changed flags are independent; `used=0, changed=0` is possible, and `is_interval_cbt` marks context.

Reload records under `/etc/synosnap` use literal block-device basenames. Initramfs restores root tracking before writes; the driver unit reloads other origins and shutdown prepares state. Ownership/generation checks bind actual devices; UUID topology handles renumbering without invented ancestry.

Missing pending sources allow recapture only with empty NAS checkpoints; otherwise 7021 preserves recovery state. Power loss, dirty COW and kernel/filesystem variations need driver validation. See [startup](service-startup.md), [ordering](snapshot-read-ordering.md), [indexes](cow-index.md), [resume](backup-resume.md) and [recovery](job-recovery.md).
