# Startup and boot identity

Linux packaging installs agent/driver units, an initramfs hook and premount script, and a shutdown helper. Driver code is maintained separately; the agent does not itself load or unload it.

The service uses private `/var/lib/opensabba` state through `XDG_CONFIG_HOME=/var/lib`, mode 0700. Register there before enabling it. The unit runs `service check` before startup and requires the driver service. See [usage](usage.md).

Boot identity distinguishes process restart from a new kernel boot. Retained captures bind exact source, snapshot, COW and generation identities. Startup validates ownership/topology before reopening sources and never substitutes the mounted origin for a missing snapshot.

Tracking records under `/etc/synosnap` use literal block-device basenames. The initramfs script restores root tracking before writes; the driver unit reloads nonroot origins and shutdown prepares reloadable state. Root tracking requires regenerated initramfs after installation or reload-record changes.

Missing snapshots permit recapture only with an empty NAS upload checkpoint. A nonempty checkpoint requires the original source; unavailable source reports 7021. Unknown ownership, changed topology and ambiguous server state preserve journals. See [recovery](job-recovery.md) and [tracking](persistent-machine-cbt.md).
