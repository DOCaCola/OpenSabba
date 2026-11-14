"""The installed parser cannot reach lab commands or extension options."""
import subprocess
import sys

exe = sys.argv[1]
def run(*args):
    return subprocess.run([exe, *args], input='', text=True, capture_output=True, timeout=5)

help_result = run('--help')
assert help_result.returncode == 0, help_result.stderr
for forbidden in ('--port', '--ca-file', '--timeout', 'password-fd', 'NTLM', 'machine plan',
                  'backup image', 'image-stream', 'configure-machine', 'configure-origin', 'boot-hold'):
    assert forbidden not in help_result.stdout, forbidden
for command in ('inspect', 'query-info', 'probe', 'reconnect', 'heartbeat', 'tasks', 'events',
                'image-stream', 'image-layout', 'image-spec', 'machine', 'snapshot', 'backup', 'restore',
                '__boot-lease-supervisor'):
    result = run(command)
    assert result.returncode != 0 and 'unknown command' in result.stderr, (command, result)
for command in ('bind-machine', 'source', 'configure-machine', 'machine', 'bind-snapshot', 'configure-origin',
                'origin', 'cleanup-cows', 'recover-boot', 'reboot-policy', 'reload'):
    result = run('service', command)
    assert result.returncode != 0 and 'unknown command' in result.stderr, (command, result)
for option in ('--port', '--ca-file', '--timeout', '--password-fd', '--otp-fd', '--proxy-password-fd',
               '--proxy-auth', '--proxy-domain', '--proxy-workstation', '--proxy-ntlm-version', '--yes',
               '--task', '--image-name', '--cow-dir', '--cow-mib', '--incremental', '--boot-hold-seconds'):
    result = run('--connect', option, '1')
    assert result.returncode != 0 and 'unknown option' in result.stderr, (option, result)
assert run('--status', '--online').returncode != 0
assert run('--status', '--json').returncode != 0
version = run('-qv')
assert version.returncode == 0 and version.stdout.startswith('OpenSabba '), version
print('Installed command and option boundary passed')
