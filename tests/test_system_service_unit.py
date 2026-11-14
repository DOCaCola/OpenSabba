"""The installed system unit implements the required process lifecycle."""
import configparser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
unit = configparser.ConfigParser(interpolation=None)
unit.read(ROOT / 'packaging/system/opensabba.service.in')
for key, expected in {
    'Type': 'forking',
    'ExecReload': '/bin/kill -HUP $MAINPID',
    'ExecStop': '/bin/kill -QUIT $MAINPID',
    'KillMode': 'process',
    'Restart': 'on-failure',
}.items():
    assert unit['Service'][key] == expected, key
assert unit['Install']['WantedBy'] == 'multi-user.target'
assert unit['Service']['PIDFile'] == '/run/opensabba.pid'
assert unit['Service']['ExecStart'] == '"@CMAKE_INSTALL_FULL_BINDIR@/opensabba" service start'
assert 'TimeoutStopSec' not in unit['Service']
assert 'RestartSec' not in unit['Service']
print('system service lifecycle contract passed')
