# Image data transfer

The sender handles fixed files and validated snapshots. Fixed input is nonempty and 512-byte aligned. Size/mtime/ctime checks detect ordinary mutations, without making a mounted filesystem consistent. Snapshot providers enforce driver ownership/health.

Blocks carry `image_name`, logical byte `offset`, `length`, numeric `used`, `changed`, `is_interval_cbt` and payload when required. Full used data has `used=1, changed=1`; inherited/unused records carry classifications without payload.

LZ4 uses independent blocks, not frames. `compressed=1` preserves logical length while buffer size can exceed it for incompressible data. Decode must exactly match logical length. Compression failure stops transfer. Default blocks are 1 MiB; configured sizes are 512-byte multiples up to 4 MiB. Memory scales with block size.

The authenticated TLS channel initializes `backup/upload_block` for a prepared job, requires `success=1`, sends maps without per-block acknowledgments and exchanges `close=1`. Data close does not finalize a job. Mutation, cancellation, server errors, disconnects and lost replies retain recovery state.

Deadlines apply per block. Partial upload resumes only from the NAS checkpoint with exact source/job validation. Saved task compression remains fixed. Machine jobs share one named-image channel across selected disks/LVs.

Independent TLS peers and a separate LZ4 decoder reconstruct fixture bytes. Test SHA-256 is a local oracle, not a wire digest. See [lifecycle](backup-lifecycle.md), [resume](backup-resume.md) and [bandwidth](bandwidth.md).
