"""Independent LZ4 block decoder for the wire oracle; no client code or liblz4."""
from test_probe import check


def literal_block(data):
    """Construct a valid raw LZ4 block without a dependency on liblz4."""
    extra = len(data) - 15
    extension = bytearray()
    if extra >= 0:
        while extra >= 255:
            extension.append(255)
            extra -= 255
        extension.append(extra)
    encoded = bytes([min(len(data), 15) << 4]) + bytes(extension) + data
    check(decode_block(encoded, len(data)) == data, 'invalid fixture LZ4 block')
    return encoded


def decode_block(data, expected):
    check(isinstance(data, bytes) and 0 < expected <= 4194304, 'invalid LZ4 block extent')
    at = 0
    output = bytearray()

    def length(initial):
        nonlocal at
        result = initial
        if initial == 15:
            while True:
                check(at < len(data), 'truncated LZ4 length')
                extra = data[at]
                at += 1
                result += extra
                if extra != 255:
                    break
        return result

    while at < len(data):
        token = data[at]
        at += 1
        literals = length(token >> 4)
        check(at+literals <= len(data) and len(output)+literals <= expected, 'invalid LZ4 literals')
        output.extend(data[at:at+literals])
        at += literals
        if at == len(data):
            break
        check(at+2 <= len(data), 'truncated LZ4 offset')
        distance = int.from_bytes(data[at:at+2], 'little')
        at += 2
        check(0 < distance <= len(output), 'invalid LZ4 match distance')
        count = length(token & 15) + 4
        check(len(output)+count <= expected, 'LZ4 match exceeds block')
        pattern = output[-distance:]
        output.extend((pattern * ((count+distance-1)//distance))[:count])
    check(len(output) == expected, 'wrong LZ4 decoded length')
    return bytes(output)
