# Upload bandwidth policy

The NAS handshake supplies unsigned bytes/second allowance; zero is unlimited. One synchronized policy covers raw, LZ4, cached and resumed uploads. Pacing counts actual payload bytes, not logical offsets.

The pacer starts with full allowance and accounts for elapsed time in waits. Cancellation remains observable. Resume does not bypass policy; new uploads use handshake policy rather than saved event state.

The service periodically refreshes rates and handles `update_backup_bandwidth` independently of capture. Event results are durable before policy publication/acknowledgment. Empty responses preserve policy; supplied zero removes the limit. See [events](events.md).

Portable policy and loopback transfer tests cover pacing/changes. Server/proxy buffering affects observed throughput; allowance controls client payload scheduling.
