# Using OpenSabba

OpenSabba is experimental. Machine backup needs the separately installed synosnap
driver with the read-ordering fix documented in the source repository. The agent
and driver must have access to the disks and mounted filesystems being protected.

For the packaged Linux system service, register using its private state location:

```sh
sudo env XDG_CONFIG_HOME=/var/lib opensabba --connect --address NAS --username USER
sudo systemctl enable --now opensabba
sudo env XDG_CONFIG_HOME=/var/lib opensabba --status
```

Connect prompts for the password, any required OTP, certificate approval and the
NAS registration template. The confirmation prompt defaults to yes. `--quiet`
requires supplied credentials and confirms registration without prompting.

Assign and configure backup tasks on the NAS. The service discovers current disks
and volumes for each job, applies the assigned entire-device, system-volume or
custom-volume selection, and chooses its retained base automatically. It needs no
local disk, image-name, COW-directory, COW-size or incremental setting.

```sh
sudo env XDG_CONFIG_HOME=/var/lib opensabba --reload
sudo env XDG_CONFIG_HOME=/var/lib opensabba --export-log --output-file diagnostic.zip
sudo env XDG_CONFIG_HOME=/var/lib opensabba --logout
```

Logout asks for NAS administrator authorization and stops the service before
retiring owned work and removing the local token. Connection settings and device
identity are private to the effective user. The system service uses
`/var/lib/opensabba`; foreground operation uses the invoking user's private state
location, normally `~/.config/opensabba`.

`opensabba service run` runs the same agent in the foreground. `service start`
starts its detached form. The packaged units load the separate driver; the agent
does not load or unload it. To stop the system service without logging out:

```sh
sudo systemctl stop opensabba
```

The shipped command flags are `--connect`, `--reload`, `--logout`, `--status`,
`--export-log`, `--version` and `--help`, with official agent short forms and options.
Proxy settings use `--proxy-address`, `--proxy-port`, `--proxy-username` and
`--proxy-password`. Use `opensabba --help` for the complete installed surface.
