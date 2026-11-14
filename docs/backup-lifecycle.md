# Backup lifecycle

The library supports task discovery, creation, preparation/handshake, metadata publication, named-image upload, completion, cancellation and result lookup. Channel close acknowledges only the data phase; final job transition establishes completion.

Requests bind endpoint/account/device and exact returned task/run/version/result IDs. Capture supplies geometry, filesystem/mount metadata, LVM inventory and sizes. Raw/filesystem intervals have distinct allocation/source rules; geometry inspection alone is insufficient.

Policy is checked before acquisition. Pre-script precedes snapshot boundary. Publication/post-script order follows the capture journal; post-script failure cannot undo an already published usable set. Script output stays private and local-only activities are not sent to the NAS.

Journals persist intent before external mutation and accepted replies before progression. Lost create/metadata/complete replies are reconciled by exact job/result queries, without blind replay. Ambiguous ownership preserves journals/resources.

Uploads share saved compression/bandwidth and explicit used/changed ranges. Resume trusts the NAS checkpoint. Snapshot sources remain readable until resolution, then enter tracking. Dependency-aware cleanup protects unresolved sources/bases. See [capture](machine-capture.md), [policy](task-policy.md), [resume](backup-resume.md) and [recovery](job-recovery.md).
