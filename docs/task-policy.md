# NAS task policy

Assigned policy determines source selection, compression, scripts, cache and scheduling. Supported policy is validated before acquisition; unsupported settings fail explicitly.

Entire-device jobs discover participating disks; system jobs select system/boot members; custom jobs use configured mount paths without fabricating root/boot. Missing members report 7096 while survivors continue. Unrelated disks are omitted for system/custom selection.

Sources include ext2/ext3/ext4/XFS direct partitions and supported LVM LVs. Bare-metal classification omits ordinary unmounted/unsupported/unknown filesystems, preserves marked raw ranges and splits swap at system page size. Omitted-only disks are skipped. Physical PV bodies are omitted when separate LV images represent filesystems.

Allocation removes free space and internal COW/history extents. `used=0` is independent of `changed`. Journals seal ranges/identities; incompatible bases require full planning.

Nested script flags are decoded before pre/post execution; cancellation/results are retained privately. Freezing alone does not quiesce applications. Task-selected none/LZ4 compression stays saved for resume. Cache replay validates volume/task identity.

See [capture](machine-capture.md), [planning](incremental-plan.md), [bandwidth](bandwidth.md) and [discovery](task-discovery.md).
