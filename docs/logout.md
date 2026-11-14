# Logout

`opensabba --logout` requests confirmation and NAS administrator authorization. Quiet mode requires explicit credentials; descriptor and OTP behavior follows [authentication](authentication.md). Administrator secrets are never saved.

Logout requests service shutdown through the UID-checked endpoint, waits for its lock, reconciles/cancels exactly owned jobs, releases snapshots and sends `unlink_connection`.

Failed unlink allows local cleanup. Unknown ownership or lock timeout preserves credentials/journals without deferred deletion. Device identity, trust and recovery records remain. Unlink does not imply token revocation or backup deletion. See [operational CLI](operational-cli.md) and [recovery](job-recovery.md).
