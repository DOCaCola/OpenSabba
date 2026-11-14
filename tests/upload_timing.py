"""Independent upload pacing oracle for fixture time budgets."""
from test_probe import wire

MIB = 1024*1024


def record_timing(record, rate):
    size = len(wire(record))
    if not rate:
        return dict(wire_bytes=size, rate=0, writes=1, arrival_us=0, complete_us=0)
    full, remainder = divmod(size, rate)
    writes = full + bool(remainder)
    # Each full-rate write costs one second, including its post-write sleep.
    # The last byte arrives before the final write's post-write sleep.
    return dict(wire_bytes=size, rate=rate, writes=writes,
                arrival_us=(writes-1)*1000000,
                complete_us=full*1000000+remainder*1000000//rate)


def full_record(name, offset, length, used=True):
    block = dict(image_name=name, offset=offset, length=length,
                 used=int(used), changed=1, is_interval_cbt=0)
    if used:
        block['buffer'] = bytes(length)
    else:
        block['changed_length'] = 0
    return block


def full_image_records(name, size, unused=()):
    at = 0
    while at < size:
        end = min(size, at+MIB)
        used = True
        for first, last in unused:
            if first <= at < last:
                used = False
                end = min(end, last)
            elif at < first:
                end = min(end, first)
        yield full_record(name, at, end-at, used)
        at = end
