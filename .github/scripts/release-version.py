"""Validate the release ref and require a changelog section before building."""
import os
from pathlib import Path
import re

text = Path('CMakeLists.txt').read_text()
match = re.search(r'project\(OpenSabba VERSION (\d+\.\d+\.\d+)\b', text)
if not match:
    raise SystemExit('CMake project version missing')
version = match[1]
if os.environ.get('GITHUB_REF_TYPE') == 'tag':
    if os.environ['GITHUB_REF_NAME'] != f'v{version}':
        raise SystemExit(f'Tag must equal CMake version v{version}')
elif os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
    raise SystemExit('A release requires a version tag or manual dispatch')
elif os.environ.get('DRY_RUN') != 'true':
    raise SystemExit('Publishing requires dispatch from the matching version tag; branch dispatch is dry-run only')
changelog = Path('CHANGELOG.md').read_text()
section = re.search(rf'^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## |\Z)',
                    changelog, re.MULTILINE | re.DOTALL)
if not section or not section[1].strip():
    raise SystemExit(f'CHANGELOG.md section [{version}] missing or empty')
Path(os.environ.get('RUNNER_TEMP', '.')).joinpath('release-notes.md').write_text(section[1].strip() + '\n')
with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
    output.write(f'version={version}\ntag=v{version}\n')
