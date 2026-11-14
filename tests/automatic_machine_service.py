"""Exercise automatic service acquisition; never manufacture service/catalog state.

The fixture executable replaces only OS discovery/acquisition. Task/event provisioning,
handshake, local snapshot IDs, NAS version mapping and source publication all
run through the same session.cpp as the shipped executable.
"""
from test_backup_cli import Reader
from test_login import value
from test_probe import check


def load(path):
    return value(Reader(path.read_bytes()))


def provide_capture(env, sources, capture, selection):
    """Supply only OS acquisition; the daemon derives its task and base itself."""
    from pathlib import Path
    from test_probe import wire
    private = Path(env['XDG_CONFIG_HOME'])/'opensabba'
    parent = private/'captures'
    parent.mkdir(mode=0o700, exist_ok=True)
    destination = parent/capture.name
    old, new = str(capture), str(destination)
    capture.rename(destination)
    def relocate(record):
        if isinstance(record, dict):
            for key, entry in record.items():
                record[key] = relocate(entry)
        elif isinstance(record, list):
            record[:] = [relocate(entry) for entry in record]
        elif isinstance(record, str) and record.startswith(old):
            return new+record[len(old):]
        return record
    journal = relocate(sources.previous)
    journal['plan']['selection'] = selection
    sources.snapshot_files = {key: Path(str(path).replace(old, new))
                              for key, path in sources.snapshot_files.items()}
    sources.manifest.write_text(sources.manifest.read_text().replace(old, new))
    (destination/'capture.pstream').write_bytes(wire(journal))
    env['OPENSABBA_MACHINE_CAPTURE_FIXTURE'] = str(destination/'capture.pstream')
    check(not (private/'service-machine.pstream').exists(), 'test supplied obsolete machine configuration')
    return destination


def no_snapshot_before_handshake(config_home, run):
    path = config_home/'opensabba'/'machine-snapshots.pstream'
    if path.exists():
        check(all(row['running_task_id'] != run for row in load(path)['snapshots']),
              'fixture supplied a snapshot row before the product acquisition pipeline')


def catalog_snapshot(config_home, run, version, base_version=0, task_uuid="fixture-task"):
    catalog = load(config_home/'opensabba'/'machine-snapshots.pstream')
    rows = catalog['snapshots']
    current = [row for row in rows if row['task_uuid'] == task_uuid and row['running_task_id'] == run]
    check(len(current) == 1, 'automatic event did not reserve exactly one local snapshot ID')
    current = current[0]
    check(current['version_id'] == version and current['capture']['phase'] == 'ready',
          'successful acquisition did not update its catalog placeholder')
    if base_version:
        base = [row for row in rows if row['task_uuid'] == task_uuid and row['version_id'] == base_version]
        check(len(base) == 1 and current['base_snapshot_id'] == base[0]['id'] and current['id'] > base[0]['id'],
              'NAS version did not resolve through the preceding completed local snapshot')
    else:
        check(current['base_snapshot_id'] == 0, 'initial full event invented a local base')
    return current
