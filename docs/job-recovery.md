# Interrupted job recovery

Private versioned journals bind NAS/account/device, task/run/version/result and exact source ownership. Atomic synchronized writes record intent before mutation and replies afterward. Crashes can leave uncertain operations requiring observation.

Recovery distinguishes create, preparation/metadata, upload, completion and cancel. It queries exact known jobs/results, never adopts similar work, replaces an uncertain create or declares success from local sent bytes. Unknown/conflicting identity preserves credentials/state.

Resume requires stopped prior writers, valid server checkpoint and original source/base/plan. Missing snapshots permit recapture only with empty checkpoints. See [resume](backup-resume.md).

Reservations validate origin, COW pathname/device/inode, minor, UUID, sequence and phase. Fresh recovered generations require valid new identity and sequence one without invented ancestry. Healthy initialized ownership renews from its validated predecessor. Forged markers and unsupported phases fail.

Pruning marks requested generations and follows dependency ownership. Pending jobs, current tracking and exact bases protect maps/snapshots/caches. Resolved retired chains release only owned unneeded files; immutable links preserve ancestry. Pathname similarity does not establish ownership.

Restart, boot reload and logout share these rules. Lock timeout schedules no delayed credential deletion. See [startup](service-startup.md), [tracking](persistent-machine-cbt.md) and [logout](logout.md).
