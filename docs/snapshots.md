# Snapshot driver boundary

OpenSabba uses the separate [synosnap fork](https://github.com/Peppershade/abb-linux-agent). No driver source/module is included. Build/load it for the running kernel and use its [read-ordering fix](snapshot-read-ordering.md).

Fixed-width ioctl layouts have compile-time ABI checks. Setup freezes/synchronizes the origin before installing tracking and resuming writes. Sources bind origin, COW path, driver minor, UUID and sequence, with COW device/inode ownership retained in private journals.

Lifecycle intent is durable before mutation. Recovery observes the exact slot without repeating uncertain setup, renewal or destruction. Wrong generations, recycled slots and changed COW identity are rejected. Reads check identity, state, cancellation and driver errors before/after access.

Payload reads use only the verified snapshot device. The advisory control lock protects OpenSabba operations; other managers may not honor it, requiring exclusive lifecycle management.

Automatic capture retains on-origin COW tracking. Explicit single-volume fixtures have separate external-storage/allocation controls. Journals/raw caches use private work storage. See [capture](machine-capture.md), [generations](snapshot-generations.md) and [tracking](persistent-machine-cbt.md).

Validate concurrent-write consistency, transitions, cancellation, COW exhaustion, restart and kernel updates. Healthy status alone cannot prove consistency. Application quiescence depends on configured scripts.
