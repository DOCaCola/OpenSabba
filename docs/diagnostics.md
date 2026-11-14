# Diagnostic export

`opensabba --export-log --output-file diagnostic.zip` creates an offline archive using the invoking user's private state. Use `XDG_CONFIG_HOME=/var/lib` for system-service state. No NAS connection is needed.

Exports contain allowlisted journal summaries, retained activities and bounded system diagnostics. They omit tokens, passwords/OTPs, proxy secrets, script bodies and unrestricted events. Redaction removes recognizable credential lines and authenticated URLs. Remaining host/storage details can still be private.

ZIP/ZIP64 structures use CRC checks and bounded entries. Output has private permissions; failed generation does not claim completeness. Independent tests inspect archive structure and synthetic redaction cases.

Diagnostics/status do not prove server success or source consistency; [recovery](job-recovery.md) uses ownership journals and NAS results.
