# Command-line reference

Run `opensabba --help` for all installed options and short forms.

| Operation | Interface |
| --- | --- |
| Authenticate/register | `--connect --address NAS_HOST --username USER` |
| Edit settings/reconnect | `--reload` with connection options |
| Local service status | `--status` |
| Administrator-authorized unlink | `--logout` |
| Offline diagnostics | `--export-log --output-file diagnostic.zip` |
| Version/help | `--version`, `--help` |
| Foreground/detached agent | `service run`, `service start` |
| Startup preflight | `service check` |

Quiet mode suppresses ordinary text/prompts; errors remain on stderr. Quiet connect/logout require credentials. Descriptors avoid passwords in process arguments. Proxy options include endpoint, credentials and explicit NTLM settings. See [authentication](authentication.md) and [proxy](proxy.md).

Normal jobs derive sources/cache/incremental policy from NAS tasks. Fixture mutation/inspection commands live only in optional `opensabba-lab`, built with testing and never installed.

Full/incremental backup, checkpoint resume, event handling and regular-file/directory restore remain experimental. Kernel/recovery compatibility depends on storage layout. See [usage](usage.md), [service](service.md) and [policy](task-policy.md).
