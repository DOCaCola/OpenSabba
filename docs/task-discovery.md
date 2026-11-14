# Task discovery and online status

After registration the service requests assigned metadata and running-job observations, retaining sanitized display fields and exact ownership IDs. Server-reported work is not assumed to run locally.

Task events persist refreshed metadata before acknowledgment. Running-job observations remain separate from transfer journals. Dispatch validates current policy and discovers current storage; normal operation needs no local disk/image/COW-size/incremental switch.

`--status` queries local service state; online status can also inspect current NAS observations. Missing service or failed operations return errors. Status omits tokens/proxy secrets.

The NAS volume picker uses read-only node events, listing mounted block filesystems and public LVs with display/mount metadata. Directory requests return child metadata without acquiring snapshots. See [events](events.md), [policy](task-policy.md) and [usage](usage.md).
