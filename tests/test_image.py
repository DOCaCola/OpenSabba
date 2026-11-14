"""Independent raw-image data receiver; no NAS or real credentials are used."""
import argparse
import hashlib
import io
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading

from test_login import value
from test_probe import check, wire
from lz4_receiver import decode_block
from pstream_peer import upload_value


class Reader:
    def __init__(self, stream):
        self.stream = stream
    def recv(self, length):
        return self.stream.read(length)


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(65536):
            result.update(block)
    return result.digest()


def receive_blocks(peer, image, restored, drop=False, compressed=False):
    offset = 0
    blocks = 0
    performance = {}
    with restored.open('wb') as destination:
        while True:
            block = upload_value(peer, performance)
            if 'close' in block:
                check(block == {'close': 1}, 'invalid close record')
                break
            keys = {'image_name', 'offset', 'length', 'used', 'changed', 'is_interval_cbt', 'buffer'}
            check(set(block) == keys | ({'compressed'} if compressed else set()), 'unexpected data keys')
            check(block['image_name'] == 'test-image', 'wrong image name')
            check(block['offset'] == offset, 'gap, overlap, or reordered block')
            check(block['used'] == 1 and block['changed'] == 1 and block['is_interval_cbt'] == 0,
                  'wrong full-image flags')
            payload = block['buffer']
            if compressed:
                check(block['compressed'] == 1, 'missing LZ4 marker')
                payload = decode_block(payload, block['length'])
            check(isinstance(payload, bytes) and
                  len(payload) == block['length'] and 0 < block['length'] <= 4194304,
                  'invalid raw payload')
            destination.write(payload)
            offset += block['length']
            blocks += 1
            if drop:
                return
    check(offset == image.stat().st_size and blocks > 0, 'wrong reconstructed size')
    check(digest(image) == digest(restored), 'independent reconstruction mismatch')
    if not isinstance(peer, Reader):
        check(set(performance) == {'read_disk', 'send'}, 'source statistics missing')
        check(all(v['size'] == offset and v['time'] > 0 for v in performance.values()),
              'source statistics counted framing or compressed bytes')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    parser.add_argument('driver')
    parser.add_argument('openssl')
    args = parser.parse_args()
    executable, driver = str(Path(args.executable).resolve()), str(Path(args.driver).resolve())
    with tempfile.TemporaryDirectory(prefix='opensabba-image-') as directory:
        root = Path(directory)
        image = root / 'source.img'
        image.write_bytes(bytes(range(256)) * (3 * 4096 + 2)) # Three MiB plus one sector.
        cert, key = root / 'cert.pem', root / 'key.pem'
        for specimen, data in [('zeros', bytes(1048576+512)),
                               ('random', os.urandom(4194304+512))]:
            compressed_image = root / f'{specimen}.img'
            compressed_image.write_bytes(data)
            for block_size in (512, 1048576, 4194304):
                output = root / f'{specimen}-{block_size}.pstream'
                result = subprocess.run([executable, 'image-stream', str(compressed_image), str(output),
                                         '--image-name', 'test-image', '--block-size', str(block_size),
                                         '--compression', 'lz4'],
                                        capture_output=True, text=True, timeout=20)
                check(result.returncode == 0, result.stderr)
                with output.open('rb') as stream:
                    receive_blocks(Reader(stream), compressed_image, root/'lz4-restored.img', compressed=True)
                    check(stream.read() == b'', 'trailing compressed stream bytes')
                with output.open('rb') as stream:
                    first = value(Reader(stream))
                    check((len(first['buffer']) > first['length']) == (specimen == 'random'),
                          'incompressible block unexpectedly sent raw or truncated')
        subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-noenc',
                        '-days', '1', '-keyout', str(key), '-out', str(cert),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, capture_output=True)
        for block_size in (512, 1048576, 4194304):
            output = root / f'frame-{block_size}'
            result = subprocess.run([executable, 'image-stream', str(image), str(output),
                                     '--image-name', 'test-image', '--block-size', str(block_size)],
                                    capture_output=True, text=True, timeout=15)
            check(result.returncode == 0, result.stderr)
            with output.open('rb') as stream:
                receive_blocks(Reader(stream), image, root / 'restored.img')
                check(stream.read() == b'', 'trailing stream bytes')
            before = digest(output)
            result = subprocess.run([executable, 'image-stream', str(image), str(output)],
                                    capture_output=True, timeout=5)
            check(result.returncode != 0 and digest(output) == before, 'output overwritten')
        for option in (['--block-size', '513'], ['--block-size', '0'],
                       ['--image-name', '../escape'], ['--image-name', 'a/b']):
            output = root / 'invalid-output'
            result = subprocess.run([executable, 'image-stream', str(image), str(output), *option],
                                    capture_output=True, timeout=5)
            check(result.returncode != 0 and not output.exists(), 'invalid options emitted data')
        for content in (b'', b'x' * 513):
            invalid = root / 'invalid.img'
            invalid.write_bytes(content)
            result = subprocess.run([executable, 'image-stream', str(invalid), str(root / 'bad-stream')],
                                    capture_output=True, timeout=5)
            check(result.returncode != 0, 'unaligned or empty image accepted')
        link = root / 'symlink.img'
        link.symlink_to(image)
        result = subprocess.run([executable, 'image-stream', str(link), str(root / 'bad-stream')],
                                capture_output=True, timeout=5)
        check(result.returncode != 0, 'source symlink accepted')
        for mode in ('mutate', 'cancel'):
            source = root / f'{mode}.img'
            source.write_bytes(b'A' * 2048)
            result = subprocess.run([driver, mode, str(source)], capture_output=True, text=True, timeout=5)
            check(result.returncode == 1 and ('changed' if mode == 'mutate' else 'cancelled') in result.stderr,
                  f'{mode} did not abort')

        for mode in ('success', 'reject', 'false-success', 'wrong-identity', 'drop', 'lost-close', 'false-close'):
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listener.settimeout(8)
            port = listener.getsockname()[1]
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            errors = []
            def server():
                try:
                    for stage in range(1 if mode == 'wrong-identity' else 2):
                        peer, _ = listener.accept()
                        with peer:
                            peer.settimeout(8)
                            upgrade = value(peer)
                            check(set(upgrade) == {'action', 'agent'} and upgrade['action'] == 'encrypt_channel',
                                  'plaintext credentials')
                            peer.sendall(wire({}))
                            with context.wrap_socket(peer, server_side=True) as secured:
                                request = value(secured)
                                if stage == 0:
                                    check(request['action'] == 'query_server_info', 'identity not verified first')
                                    secured.sendall(wire({'ds_id': 'other-nas' if mode == 'wrong-identity' else 'test-nas'}))
                                    continue
                                check(request['action'] == 'backup' and request['subaction'] == 'upload_block' and
                                      request['running_task_id'] == 27 and request['token'] == 'test-token' and
                                      request['ds_id'] == 'test-nas' and request['resume'] == 0 and request['is_cache'] == 0,
                                      'wrong upload initialization')
                                if mode == 'reject':
                                    secured.sendall(wire({'error': {'code': 4106}}))
                                    return
                                if mode == 'false-success':
                                    secured.sendall(wire({'success': 0}))
                                    return
                                secured.sendall(wire({'type': 'keep_alive'}) + wire({'success': 1, 'backup_bandwidth': 0}))
                                receive_blocks(secured, image, root / f'restored-{mode}.img', drop=mode == 'drop')
                                if mode in ('drop', 'lost-close'):
                                    return
                                secured.sendall(wire({'close': 0 if mode == 'false-close' else 1}))
                except Exception as exc:
                    errors.append(exc)
            thread = threading.Thread(target=server, daemon=True)
            thread.start()
            result = subprocess.run([driver, str(port), str(cert), str(image), 'test-image'],
                                    capture_output=True, text=True, timeout=15)
            thread.join(10)
            listener.close()
            check(not thread.is_alive() and not errors, f'{mode}: receiver errors {errors}')
            check(result.returncode == (0 if mode == 'success' else 1), f'{mode}: {result.stderr}')
            check('test-token' not in result.stdout + result.stderr, 'token leaked')
            print(f'image transfer {mode}: passed')
        print('offline framing, reconstruction, source stability, cancellation, output protection: passed')


if __name__ == '__main__':
    main()
