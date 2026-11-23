# Changelog

## [1.0.0]

- Experimental command-line client and background service for Synology Active Backup for Business, targeting Debian 12 and 64-bit Raspberry Pi OS (Debian 12) on arm64, with amd64 as a secondary target.
- Authentication and registration, task discovery, full and incremental machine backup, snapshot tracking, and durable upload resume and recovery.
- NAS events, regular-file and directory restore, HTTP CONNECT proxy support, bandwidth policy, and diagnostic export.
- Debian packages and Linux archives with documentation, licenses, systemd units, and initramfs integration. The Debian package enables the service and starts it once a confirmed session exists, stops it across upgrades, refreshes the initramfs through the initramfs-tools trigger, and removes its state on purge.
- OpenSabba does not self-update: agent update requests from the NAS are acknowledged and ignored.
- Snapshots require the separate [synosnap driver fork](https://github.com/DOCaCola/abb-linux-agent), built for the running kernel from its `master` branch, which contains the read-ordering fix described in the documentation. Driver sources and modules are not bundled.
- Storage layouts, kernels, snapshot consistency, and unattended recovery require deployment-specific validation. Machine capture requires Linux and normally root in the host mount namespace; Windows is for development and portable tests. This release does not establish compatibility with every NAS, kernel, or storage layout.
