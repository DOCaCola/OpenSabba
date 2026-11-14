# Snapshot generations and change tracking

An active snapshot provides stable readable data while observing origin writes. Tracking transition discards readable saved blocks but retains their change index. Renewal reserves a new COW, keeps the driver UUID, increments sequence by one and preserves prior history for planning.

Transitions validate origin/COW/UUID/sequence/mode/health under the control lock. Unresolved jobs prevent discarding their sources. Foreign, failed or recycled generations cannot become sources.

Intent precedes ioctl submission. Reconciliation observes without replay: original tracking mode means renewal did not finish; a new snapshot is adopted only with exact next identity and reserved pathname/device/inode. Unexpected generations are refused. Atomic synchronized journals allow interrupted adoption to finish. Unhealthy owned generations remain recoverable but cannot supply backup bytes.

Linux LP64 tracking ioctl is `0x40044105`, renewal `0x40184106`. Renewal arguments occupy 24 bytes: COW pointer at 0, allocation at 8, minor at 16. Allocation is MiB; automatic capture passes zero for driver default.

Unresolved jobs and exact bases protect needed history. See [indexes](cow-index.md), [planning](incremental-plan.md) and [persistent tracking](persistent-machine-cbt.md).
