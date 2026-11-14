"""Read-only release-artifact boundary check after a BUILD_TESTING=OFF install."""
from pathlib import Path
import sys

build, prefix = map(Path, sys.argv[1:3])
cache = (build/'CMakeCache.txt').read_text()
assert 'BUILD_TESTING:BOOL=OFF' in cache
manifest = [Path(line) for line in (build/'install_manifest.txt').read_text().splitlines()]
assert manifest and all(path.exists() for path in manifest)
files = [path for path in prefix.rglob('*') if path.is_file()]
binaries = [path.name for path in files if path.parent == prefix/'bin']
assert binaries in (['opensabba'], ['opensabba.exe']), binaries
assert not any('lab' in path.name.lower() or 'fixture' in path.name.lower() for path in files), files
allowed_docs = {'README.md', 'LICENSE', 'Unicode-3.0.txt', 'usage.md'}
assert all(path.name in allowed_docs for path in files if 'doc' in path.parts), files
assert not (build/'opensabba-lab').exists() and not (build/'opensabba-lab.exe').exists()
print(f'Product-only build/install verified: {len(files)} files, one executable')
