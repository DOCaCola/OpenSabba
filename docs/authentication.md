# Authentication and saved sessions

```sh
opensabba --connect --address NAS_HOST --username USER
opensabba --connect --address NAS_HOST --username USER --ca-file /path/to/nas-ca.pem
opensabba --status
```

The password prompt disables echo. `--password` and `--otp` accept explicit values. Without OTP the first request sends an empty code. Responses 4101/4102 permit one interactive retry; Enter cancels. Password failures, 4103 and a second OTP rejection stop. Failure preserves the saved session/device identity.

`--password-fd N` and optional `--otp-fd N` consume one line each, bounded to 4096 bytes without NUL, from caller-owned nonterminal descriptors. Shared input supplies password then OTP. This mode does not open a terminal or retry. Quiet connect requires address, username and password.

```sh
opensabba --connect --address NAS_HOST --username USER --password-fd 3 --quiet 3< /private/password
```

Connect confirms the selected registration template. Registration uses `temp_device.backup_type`, `task_template.id` or zero, and connection type `backup`. Driver readiness is advertised only after local preflight.

The store defaults to `~/.config/opensabba`; absolute `XDG_CONFIG_HOME` replaces the base. `identity.pstream` retains the device UUID; `session.pstream` holds endpoint, account, token, NAS identity and registration policy. NAS passwords/OTPs are never saved. [Proxy](proxy.md) credentials may be retained for unattended use.

Directory mode is 0700 and file mode 0600, owned by the effective user. Reads reject symlinks, nonregular files and multiple links. Atomic replacement and synchronization protect writes. Concurrent writers fail. Tokens are unencrypted and rely on permissions; status/diagnostics omit them.

Interactive certificate approval displays subject, issuer, reason and SHA-256 fingerprint. Quiet initial connect accepts and pins the certificate. Later CA-verified renewal is accepted; untrusted replacements need interactive review. Explicit CA policy stays strict. Token authentication verifies NAS identity first; changed identity or malformed replies cannot replace the session.

The service saves rotated tokens before continuing. A lost reply may require password login if the old token was retired. [Logout](logout.md) authorizes an administrator and resolves owned work before deleting the session.
