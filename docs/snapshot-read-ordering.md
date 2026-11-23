# Snapshot read ordering

A snapshot can expose newly written origin bytes if the driver releases an origin write before its saved data/COW mapping become visible. Status can remain healthy with no error; user-space checks cannot detect this race.

The correction belongs to the separate [synosnap fork](https://github.com/DOCaCola/abb-linux-agent), whose `master` branch contains it. Deploy that revision and validate the exact kernel.

Dropping the read clone's final tracing reference immediately after queueing releases the original write while COW mapping is pending. A concurrent unmapped snapshot read can race with that write; later reads may appear correct once COW processing catches up.

The corrected lifetime retains the reference until the COW worker processes/frees the clone. Snapshot reads and mapping updates share that worker, making the saved mapping available before origin write release. Cleanup owns reference release on success/error; queue tracing occurs before ownership transfer.

Renewal starts the new worker before tracer installation and filesystem thaw. Thaw can synchronously write metadata; deferring that write with a parked worker can deadlock.

A regression uses a disposable filesystem, known block pattern, concurrent scattered writes and repeated full-snapshot comparisons. Reads bypass/invalidate only that owned snapshot cache so cached pages cannot hide errors. Existing host caches must not be targeted. Transitions and failure cleanup need separate checks.

This establishes an ordering requirement, not power-loss durability or universal filesystem/kernel support. Portable user-space tests do not replace kernel-driver validation.
