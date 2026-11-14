"""Portable independent PStream reader shared by loopback fixtures."""
import io
import os

from test_probe import check, exact


class Reader(io.BytesIO):
    recv = io.BytesIO.read


def open_snapshot(path):
    """Read an atomically replaced journal without denying the writer rename."""
    if os.name != 'nt':
        return open(path, 'rb')
    import ctypes
    from ctypes import wintypes
    import msvcrt
    create = ctypes.windll.kernel32.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    # Python's ordinary open omits FILE_SHARE_DELETE, which prevents atomic
    # replacement while the fake NAS inspects the preceding durable snapshot.
    handle = create(os.fspath(path), 0x80000000, 1 | 2 | 4, None, 3, 0x80, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError()
    descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    return os.fdopen(descriptor, 'rb')


def value(peer, tag=None):
    if tag is None:
        tag = exact(peer, 1)[0]
    if tag == 0:
        check(exact(peer, 1) == b"\0", "bad null")
        return None
    if tag == 1:
        return int.from_bytes(exact(peer, exact(peer, 1)[0]), "big")
    if tag == 16:
        return exact(peer, int.from_bytes(exact(peer, 2), "big")).decode()
    if tag == 32:
        return exact(peer, int.from_bytes(exact(peer, 4), "big"))
    if tag == 65:
        result = []
        while True:
            first = exact(peer, 1)[0]
            if first == 64:
                return result
            result.append(value(peer, first))
    if tag == 66:
        result = {}
        while True:
            first = exact(peer, 1)
            if first == b"\x40":
                return result
            check(first == b"\x10", "expected map key")
            key = exact(peer, int.from_bytes(exact(peer, 2), "big")).decode()
            result[key] = value(peer)
    raise AssertionError(f"unsupported mock tag {tag}")


def upload_value(peer, performance=None):
    """Validate interleaved official agent counters; return the next data/close record."""
    while True:
        record = value(peer)
        if 'performance' not in record:
            return record
        check(set(record) == {'performance'} and record['performance'], 'invalid performance message')
        for component, counters in record['performance'].items():
            check(component in ('snapshot', 'read_disk', 'send'), 'invented performance component')
            check(set(counters) == {'size', 'time'} and
                  all(isinstance(n, int) and n >= 0 for n in counters.values()),
                  'invalid performance counter units or shape')
            if component == 'snapshot':
                check(counters['size'] == 0, 'snapshot has a byte count')
            if performance is not None:
                total = performance.setdefault(component, {'size': 0, 'time': 0, 'messages': 0})
                total['size'] += counters['size']
                total['time'] += counters['time']
                total['messages'] += 1
