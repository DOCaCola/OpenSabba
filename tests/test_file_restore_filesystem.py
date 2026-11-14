"""Native Linux results for the official agent file-restore object's support boundary."""
import argparse
import base64
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import tempfile

from test_file_restore import Server
from test_probe import check, wire


class FilesystemServer(Server):
    def __init__(self, root, cert, key, mode):
        super().__init__(root, cert, key, mode, metadata=True)
        if mode in ('skip-types', 'parent-skip'):
            self.running['file_restore_task']['conflict_handle'] = 'skip'
        self.types, self.before = {}, {}
        self.bound_socket = None
        if mode in ('overwrite-types', 'skip-types', 'unsupported'):
            self.create_types()

    def create_types(self):
        target = self.root / 'link-target'
        target.mkdir()
        (target / 'sentinel').write_bytes(b'outside restore')
        os.symlink(target, self.destination / 'symlink')
        os.symlink(self.root / 'absent', self.destination / 'dangling')
        os.mkfifo(self.destination / 'fifo', 0o600)
        self.bound_socket = socket.socket(socket.AF_UNIX)
        self.bound_socket.bind(str(self.destination / 'socket'))
        if os.geteuid() == 0:
            os.mknod(self.destination / 'character', stat.S_IFCHR | 0o600, os.makedev(1, 3))
            os.mknod(self.destination / 'block', stat.S_IFBLK | 0o600, os.makedev(7, 0))
        for path in self.destination.iterdir():
            os.utime(path, (1500000001, 1500000002), follow_symlinks=False)
            info = path.lstat()
            self.types[path.name] = stat.S_IFMT(info.st_mode)
            self.before[path.name] = (info.st_ino, info.st_mode, info.st_mtime_ns, info.st_rdev)

    def extended(self, record):
        # NAS xattrs are a map of full names to PStream binary buffers.
        # POSIX ACL xattrs have Linux v2 header/entries, unlike `acl`, which
        # contains a Base64 Synology raw ACL and its separate byte count.
        acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', tag, perm, identifier)
            for tag, perm, identifier in ((1, 7, 0xffffffff), (2, 4, 12345),
                                          (4, 0, 0xffffffff), (16, 4, 0xffffffff),
                                          (32, 0, 0xffffffff)))
        record.update(acl=base64.b64encode(b'Synology opaque ACL').decode(),
                      acl_size=20, acl_archive=7,
                      xattrs={'user.restore-source': b'\x00opaque\xff',
                              'user.zero-length': b'',
                              'system.posix_acl_access': acl,
                              'security.capability': struct.pack('<IIIII', 0x02000001, 1, 0, 0, 0),
                              'security.selinux': b'unconfined_u:object_r:user_tmp_t:s0\x00',
                              'trusted.restore-source': b'privileged'})
        if record['file_type'] == 1:
            record['xattrs']['system.posix_acl_default'] = acl
        return record

    def transfer(self, peer, request):
        self.downloads.append(request)
        if self.mode == 'extended-metadata':
            directory = self.destination / 'existing'
            directory.mkdir()
            os.setxattr(directory, 'user.existing', b'preserved')
            self.first_name = 'first-ä"\\\n'
            existing = directory / self.first_name
            existing.write_bytes(b'old content')
            os.setxattr(existing, 'user.old', b'discarded with old inode')
            os.link(existing, self.root / 'old-hardlink')
            self.send_file(peer, self.extended(self.file(71, 'existing', 1)))
            for identifier, name in ((72, self.first_name), (73, 'second')):
                record = self.file(identifier, 'existing/' + name, data=b'same hard-linked source bytes')
                # chown must precede chmod or it would clear these bits.
                record['mode'] = 0o6750
                self.send_file(peer, self.extended(record))
        elif self.mode in ('overwrite-types', 'skip-types', 'unsupported'):
            for identifier, name in enumerate(self.types, 81):
                record = self.file(identifier, name, kind=9999 if self.mode == 'unsupported' else 0,
                                   data=None if self.mode == 'unsupported' else b'restored regular')
                self.send_file(peer, self.extended(record))
            # A directory can replace a symlink without touching its target.
            if self.mode == 'overwrite-types':
                os.symlink(self.root / 'link-target', self.destination / 'directory-link')
                self.send_file(peer, self.file(99, 'directory-link', 1))
        elif self.mode in ('parent-overwrite', 'parent-skip'):
            (self.destination / 'parent-file').write_bytes(b'keep parent')
            os.symlink(self.root, self.destination / 'parent-link')
            for identifier, name in enumerate(('missing', 'parent-file', 'parent-link'), 101):
                record = self.file(identifier, name + '/child', data=b'not installed')
                self.expected[identifier] = 0 if self.mode == 'parent-skip' else 1
                self.send_file(peer, record)
        elif self.mode == 'metadata-failure':
            # The ACK handler below removes this empty directory after content
            # success but before the final deferred directory metadata pass.
            self.send_file(peer, self.file(111, 'removed-before-metadata', 1))
            self.send_file(peer, self.file(112, 'after-directory', data=b'continue'))
            check(self.ack_started.wait(8), 'directory ACK waited for stream completion')
        elif self.mode == 'owner-failure':
            record = self.file(121, 'foreign-owner', data=b'content succeeds')
            record.update(uid=os.getuid() + 1, mode=0o4750)
            self.send_file(peer, record)
        elif self.mode == 'write-failure':
            self.destination.chmod(0o500)
            record = self.file(131, 'no-write-access', data=b'not installed')
            self.expected[131] = 1
            self.send_file(peer, record)
        peer.sendall(wire(dict(has_more=0)))

    def record(self):
        result = super().record()
        if self.mode == 'metadata-failure':
            # This runs while validating the pending ACK, before replying.
            directory = self.destination / 'removed-before-metadata'
            if directory.exists():
                check(int(directory.stat().st_mtime) != 1600000002,
                      'directory metadata applied before its content ACK')
                directory.rmdir()
                self.ack_started.set()
        return result

    def close(self):
        if self.bound_socket:
            self.bound_socket.close()
        super().close()


def run_case(driver, root, cert, key, mode):
    root.mkdir()
    server = FilesystemServer(root, cert, key, mode)
    running, journal = root / 'running.pstream', root / 'journal.pstream'
    running.write_bytes(wire(server.running))
    try:
        result = subprocess.run([driver, str(server.port), str(cert), str(running), str(journal)],
                                capture_output=True, text=True, timeout=25)
        check(result.returncode == 0 and result.stdout.strip() == 'complete',
              f'{mode}: {result.stdout}{result.stderr}; {server.errors}')
        record = server.record()
        check(server.acknowledged == server.expected, f'{mode}: record ACKs differ')
        check(not record['pending_logs'], 'restore activity reports were not drained')
        check(not record['directories'], 'directory metadata journal was not drained')
        expected_logs = {
            'extended-metadata': [6003, 6005, 6003],
            'overwrite-types': [6005] * (len(server.types) + 1),
            'skip-types': [6004] * len(server.types),
            'unsupported': [6011] * len(server.types),
            'parent-overwrite': [6015, 6016, 6016],
            'parent-skip': [6004, 6004, 6004],
            'metadata-failure': [6003, 6003, 6019],
            'owner-failure': [6019, 6003],
            'write-failure': [6006],
        }[mode]
        check([kind for kind, _ in server.activity] == expected_logs,
              f'{mode}: official agent log types/order differ: {server.activity}')
        for kind, parameters in server.activity:
            check(set(parameters) == {'id', 'running_task_id', 'task_id', 'task_uuid', 'result_id', 'path'} |
                  ({'parent_path'} if kind in (6015, 6016) else set()),
                  f'{kind}: restore activity fields differ')
        if mode == 'extended-metadata':
            directory = server.destination / 'existing'
            first, second = directory / server.first_name, directory / 'second'
            check(server.activity[1][1]['path'] == str(first),
                  'UTF-8, quote, backslash or control bytes changed in activity JSON')
            check(first.stat().st_ino != second.stat().st_ino, 'restored hard-link paths share an inode')
            check((root / 'old-hardlink').read_bytes() == b'old content', 'overwrite modified another hard link')
            check(os.getxattr(directory, 'user.existing') == b'preserved', 'existing directory xattr removed')
            for path in (directory, first, second):
                attrs = os.listxattr(path)
                check(not any(name in attrs for name in ('user.restore-source', 'user.zero-length',
                    'security.capability', 'security.selinux', 'trusted.restore-source',
                    'system.posix_acl_access', 'system.posix_acl_default', 'user.old')),
                    f'{path}: ignored source xattr was applied: {attrs}')
                info = path.stat()
                check(stat.S_IMODE(info.st_mode) == (0o750 if path == directory else 0o6750),
                      f'{path}: ownership/mode application order differs')
                check(int(info.st_atime) == 1600000001 and int(info.st_mtime) == 1600000002,
                      f'{path}: timestamps differ')
            check(first.read_bytes() == second.read_bytes() == b'same hard-linked source bytes',
                  'independent hard-link source paths lost content')
        elif mode in ('overwrite-types', 'skip-types', 'unsupported'):
            check((root / 'link-target/sentinel').read_bytes() == b'outside restore',
                  'destination symlink target was changed')
            for name in server.types:
                path = server.destination / name
                info = path.lstat()
                if mode == 'overwrite-types':
                    check(stat.S_ISREG(info.st_mode) and path.read_bytes() == b'restored regular',
                          f'{name}: existing special object was not replaced')
                else:
                    check((info.st_ino, info.st_mode, info.st_mtime_ns, info.st_rdev) == server.before[name],
                          f'{name}: skipped/unsupported object or symlink timestamp changed')
            if mode == 'overwrite-types':
                check((server.destination / 'directory-link').is_dir() and
                      not (server.destination / 'directory-link').is_symlink(),
                      'directory restore failed to replace destination symlink')
        elif mode in ('parent-overwrite', 'parent-skip'):
            check(not (server.destination / 'missing').exists(), 'missing parent was invented')
            check((server.destination / 'parent-file').read_bytes() == b'keep parent',
                  'conflicting parent was replaced')
            check((server.destination / 'parent-link').is_symlink() and not (root / 'child').exists(),
                  'restore followed parent symlink')
        elif mode == 'metadata-failure':
            check('last_metadata_error' in record and 'last_record_error' not in record,
                  'metadata failure was not reported separately')
            check((server.destination / 'after-directory').read_bytes() == b'continue',
                  'metadata failure interrupted subsequent content')
        elif mode == 'owner-failure':
            path = server.destination / 'foreign-owner'
            check('last_metadata_error' in record and path.read_bytes() == b'content succeeds',
                  'ownership failure lost content or metadata diagnostic')
            check(stat.S_IMODE(path.stat().st_mode) == 0o600 and int(path.stat().st_mtime) != 1600000002,
                  'metadata continued after failed chown')
        elif mode == 'write-failure':
            check(not (server.destination / 'no-write-access').exists() and
                  'last_record_error' in record, 'failed write created destination or lost diagnostic')
    finally:
        server.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('driver')
    parser.add_argument('openssl')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='opensabba-restore-types-') as directory:
        root = Path(directory)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, capture_output=True)
        cases = ['extended-metadata', 'overwrite-types', 'skip-types', 'unsupported',
                 'parent-overwrite', 'parent-skip', 'metadata-failure']
        if os.geteuid() != 0:
            cases += ['owner-failure', 'write-failure']
        for mode in cases:
            run_case(str(Path(args.driver).resolve()), root / mode, cert, key, mode)
            print(f'{mode}: passed')


if __name__ == '__main__':
    main()
