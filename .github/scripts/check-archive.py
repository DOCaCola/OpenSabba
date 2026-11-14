"""Check the unpacked product archive, including all local documentation links."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlsplit

archive, version = sys.argv[1:]
with tempfile.TemporaryDirectory(prefix='opensabba-package-') as directory:
    root = Path(directory)
    subprocess.run(['tar', '-xzf', archive, '-C', directory], check=True)
    binaries = sorted(path.relative_to(root).as_posix() for path in (root / 'usr/bin').iterdir())
    assert binaries == ['usr/bin/opensabba'], binaries
    result = subprocess.check_output([str(root / 'usr/bin/opensabba'), '--version'], text=True)
    assert result.strip() == f'OpenSabba {version}', result
    docs = root / 'usr/share/doc/opensabba'
    for name in ['README.md', 'LICENSE', 'LICENSES/Unicode-3.0.txt', 'docs/usage.md']:
        assert (docs / name).is_file(), name
    for path in docs.rglob('*.md'):
        for target in re.findall(r'\]\(([^)]+)\)', path.read_text()):
            link = urlsplit(target)
            if not link.scheme and link.path:
                resolved = (path.parent / unquote(link.path)).resolve()
                assert resolved.is_relative_to(docs), (path, target)
                assert resolved.is_file(), (path, target)
    for name in ['lib/systemd/system/opensabba.service',
                 'lib/systemd/system/opensabba-driver.service',
                 'lib/systemd/system-shutdown/opensabba.shutdown',
                 'share/initramfs-tools/hooks/opensabba',
                 'share/initramfs-tools/scripts/init-premount/opensabba']:
        assert (root / 'usr' / name).is_file(), name
    assert not list(root.rglob('*lab*')), 'Diagnostic executable leaked into product archive'
print(f'Archive payload, version {version}, and documentation links verified')
