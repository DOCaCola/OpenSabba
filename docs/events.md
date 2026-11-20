# Durable NAS event inbox

`events.pstream` uses private permissions, atomic replacement, synchronization and bounds of 4 MiB, 100,000 nodes and depth 64. Storage/validation failure stops before acknowledgment. The inbox binds NAS/device/account identity; unsupported payloads remain private and pending.

`change_task` persists refreshed metadata before acknowledgment; `update_running_task` persists sanitized observations. Neither claims capture/transfer success. Job journals retain one writer and exact task/event/source ownership.

`update_backup_bandwidth` queries the rate and atomically saves its result with acknowledgment intent. Null means never refreshed; empty map means no update; an unsigned rate includes zero. Missing required results invalidate completed receipts. Policy is published after persistence; new uploads start from handshake policy.

`act_client` with `webapi_task.subaction=list_nodes` lists mounted block filesystems, including supported LVs, for empty `node_path`. Other paths list children with `name`, `path`, numeric `is_dir`. Directory-only mode includes symlinks, even dangling/file links. Empty lists omit `node_list`; errors encode negative errno as sign-extended unsigned integers.

Exact replies are durable before transmission and replayed before acknowledgment after restart. Changed mounts cannot replace saved replies. Listing is read-only.

`update_agent` is ignored because OpenSabba does not self-update. As the official agent does when it skips an update, the service sends `download_installer` with subaction `finish_update` to close the NAS update attempt, then acknowledges the event and logs that the request was ignored. It never queries, downloads or runs an installer.

`get_running_task_result` sends an optional matching historical `result_id`, omitted when absent, without echoing event/task/version IDs. Transport/server errors retain receipts. Observations/timestamps stay separate from transfer journals.

One control worker owns the inbox during capture, backup, cache replay and restore. Synchronized observations/bandwidth cross worker boundaries; job journals retain their owner. See [service](service.md).
