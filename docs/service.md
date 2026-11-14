# Connection and backup service

`opensabba service run` runs foreground after registration; the system unit uses detached `service start`. See [usage](usage.md).

The service saves replacement tokens atomically before further requests, sends heartbeats every 5–7 seconds, refreshes task/job observations and waits for events. Network failures retry after 1, 2, 4 and up to 60 seconds. Authentication rejection, changed NAS identity, malformed replies and TLS verification errors stop the process. Lost token-auth replies may require new login.

One service owns the session writer lock. A second is rejected. Status uses local control. Stop before direct login or registration changes; [operational CLI](operational-cli.md) describes cooperative reload/logout.

Each automatic backup discovers current storage, applies task selection, acquires snapshots and uploads selected images. Supported origins retain tracking between jobs. NAS-pushed file/directory restores dispatch independently with exact run/version/result identity, private journals, partial-file checkpoints, pending acknowledgments and result reconciliation. Heartbeats and cancellation continue during work.

A separate worker owns the durable inbox during capture, upload, cache replay and file restore. It handles policy/observations without writing transfer journals. See [events](events.md), [capture](machine-capture.md) and [tracking](persistent-machine-cbt.md).

The one-second local tick makes no network request itself. Long polling lasts for the connection lifetime; events are pulled after positive notification. Authentication repeats after 60 seconds; timezone checks align to 180-second boundaries. Unsupported events stay pending. Socket waits check cancellation every 100 ms; operating-system DNS remains synchronous.
