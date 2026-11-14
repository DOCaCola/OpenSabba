# Backup resume

Resume binds exact NAS/account/device, task/run/version/result and source identity. Active writers, terminal results, cancellation, malformed checkpoints or changed sources prevent upload. Local sent progress never authorizes skipping server data.

Query running state with `check_backup_exist=1`; require the exact job, no error and `is_backing_up=0`. Only `backup_task.resume_info` selects position. Its Linux JSON map keys are image names, with decimal-string `current`/`transfer_current` and optional null `mac_progress`. Empty state means no persisted intervals. Invalid counters, unknown images/fields and out-of-range offsets are rejected.

`current` is logical position. `transfer_current` counts payload and can exceed logical size for incompressible LZ4; it never selects source offsets. Compression, range plans, ancestry and CBT base stay fixed.

Automatic capture reopens exact snapshots/raw caches without whole-image hashes. Missing snapshots permit recapture only with an empty checkpoint; otherwise 7021 retains unavailable-source state. Fixed-file/explicit-volume providers retain size/digest checks.

Resume initializes `backup/upload_block` with `resume=1`, sends remaining ranges, requires close and completes the same job. Creation/preparation/metadata are not repeated. Lost close replies can be recovered by querying checkpoint again, including full logical completion.

Uncertain create/metadata/finalization requires [reconciliation](job-recovery.md). Locking, durable intent, heartbeats and cancellation apply throughout. See [transfer](image-transfer.md) and [tracking](persistent-machine-cbt.md).
