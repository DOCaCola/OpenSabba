# Accounts, connection editing and logout

Use `opensabba --connect --address NAS_HOST --username USER` to authenticate and register. Passwords are prompted without echo; quiet operation requires explicit credentials. See [authentication](authentication.md).

`--reload` edits address, port, CA and proxy settings while retaining account, device identity and current token. NAS identity is checked before committing. A rejected edit preserves the saved session. Different configured usernames are rejected; use `--connect` for password authentication.

The running service checks the caller's UID through its configuration-specific local endpoint, merges settings into the latest token-bearing session under its writer lock, interrupts workers, commits and reconnects. Durable work resumes normally. An empty proxy username removes saved proxy authentication.

Use the service user and `XDG_CONFIG_HOME`; the package uses `/var/lib`. `systemctl reload opensabba` sends HUP and stops the daemon. Use `opensabba --reload` to reconnect its workers while the daemon survives. There is no `service reload` command.

`service start` double-forks and detaches; parents exit before initialization finishes. The daemon writes its PID plus newline to `/run/opensabba.pid`, mode 0644, before initializing state/control. `service run` stays foreground without that PID file. The unit uses `Type=forking`, `KillMode=process`, `Restart=on-failure`, HUP for reload and QUIT for stop. HUP, INT, QUIT and TERM stop the agent.

`--logout` requests confirmation and NAS administrator authorization, stops the service, waits for its lock, reconciles/cancels exactly owned jobs, releases snapshots and sends `unlink_connection`. Local cleanup follows unlink failure. Unknown ownership or lock timeout preserves credentials without delayed deletion. Device identity, trust and recovery records remain. Unlink does not imply token revocation or backup deletion.
