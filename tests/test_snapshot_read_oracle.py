"""Portable negative controls for the service fixture's snapshot-read oracle."""
import unittest
import struct

from snapshot_service_fixture import ext4_context_metadata_reads, verify_snapshot_read_coverage

MIB = 1024 * 1024
BLOCK = 65536


def row(path, offset, length):
    return f"snap {path} {offset} {length}"


class SnapshotReadOracleTests(unittest.TestCase):
    def test_changed_replays_and_compulsory_boundaries(self):
        path = "/dev/synosnap2"
        expected = {path: [(0, MIB), (4*MIB, BLOCK), (7*MIB, MIB)]}
        reads = [row(path, 0, 512), row(path, 1024, 1024)]
        for start, size in expected[path]:
            reads.extend(row(path, at, BLOCK) for at in range(start, start+size, BLOCK))
        reads.extend([row(path, 4*MIB, BLOCK)] * 200)
        self.assertEqual(verify_snapshot_read_coverage(reads, expected), len(reads))

    def test_one_inherited_sector_is_rejected_despite_small_total(self):
        path = "/dev/synosnap2"
        expected = {path: [(4*MIB, BLOCK)]}
        with self.assertRaisesRegex(AssertionError, "inherited payload"):
            verify_snapshot_read_coverage([row(path, 4*MIB, BLOCK), row(path, 2*MIB, 512)], expected)

    def test_a_read_crossing_an_inherited_gap_is_rejected(self):
        path = "/dev/synosnap2"
        with self.assertRaisesRegex(AssertionError, "inherited payload"):
            verify_snapshot_read_coverage([row(path, 4*MIB, 3*BLOCK)],
                {path: [(4*MIB, BLOCK), (4*MIB+2*BLOCK, BLOCK)]})

    def test_each_origin_and_required_changed_range_is_checked(self):
        expected = {"/dev/synosnap2": [(2*MIB, BLOCK)], "/dev/synosnap3": [(3*MIB, BLOCK)]}
        with self.assertRaisesRegex(AssertionError, "incomplete"):
            verify_snapshot_read_coverage([row("/dev/synosnap2", 2*MIB, BLOCK)] * 100, expected)
        with self.assertRaisesRegex(AssertionError, "inherited payload"):
            verify_snapshot_read_coverage([row("/dev/synosnap4", 2*MIB, BLOCK)], expected)

    def test_missing_base_requires_unique_full_filesystem_coverage(self):
        path = "/dev/synosnap3"
        expected = {path: [(0, 16*MIB)]}
        with self.assertRaisesRegex(AssertionError, "incomplete"):
            verify_snapshot_read_coverage([row(path, 0, MIB)] * 17, expected)
        complete = [row(path, offset, BLOCK) for offset in range(0, 16*MIB, BLOCK)]
        verify_snapshot_read_coverage(complete + complete[:20], expected)

    def test_ext4_metadata_probes_do_not_authorize_nearby_payload(self):
        path = "/dev/synosnap2"
        expected = {path: [(4*MIB, BLOCK)]}
        verify_snapshot_read_coverage([row(path, 0, 512), row(path, 1024, 1024),
            row(path, 4*MIB, BLOCK)], expected)
        with self.assertRaisesRegex(AssertionError, "inherited payload"):
            verify_snapshot_read_coverage([row(path, 2048, 512)], expected)

    def test_official_context_metadata_uses_specimen_addresses_and_exact_read_shapes(self):
        data = bytearray(16*MIB)
        sb = 1024
        for at, value in ((4, 4096), (0x18, 2), (0x20, 32768),
                          (0x24, 32768), (0x60, 0x80)):
            struct.pack_into('<I', data, sb+at, value)
        struct.pack_into('<H', data, sb+0x38, 0xef53)
        struct.pack_into('<H', data, sb+0xfe, 64)
        struct.pack_into('<I', data, 4096, 12)  # group-0 allocation bitmap
        struct.pack_into('<I', data, 4096+8, 20)  # inode table
        reads = ext4_context_metadata_reads(data)
        self.assertEqual(reads, [(0, 512), (1024, 1024), (4096, 4096),
                                 (49152, 4096), (81920, 128)])
        path = '/dev/synosnap2'
        expected, metadata = {path: [(4*MIB, BLOCK)]}, {path: reads}
        complete = [row(path, 4*MIB, BLOCK)]
        verify_snapshot_read_coverage(complete+[row(path, at, size) for at, size in reads]*2,
                                      expected, metadata)
        for at, size in ((4096, 512), (8192, 512), (49152, 4097),
                         (81920, 129), (81920+128, 512)):
            with self.subTest(at=at, size=size), self.assertRaisesRegex(AssertionError, 'inherited payload'):
                verify_snapshot_read_coverage(complete+[row(path, at, size)], expected, metadata)

    def test_uninitialized_group_bitmap_and_nonempty_bad_inode_need_explicit_oracles(self):
        data = bytearray(16*MIB)
        for at, value in ((4, 4096), (0x18, 2), (0x20, 32768),
                          (0x24, 32768), (0x60, 0x80), (0x64, 0x400)):
            struct.pack_into('<I', data, 1024+at, value)
        struct.pack_into('<H', data, 1024+0x38, 0xef53)
        struct.pack_into('<H', data, 1024+0xfe, 64)
        struct.pack_into('<I', data, 4096, 12)
        struct.pack_into('<I', data, 4096+8, 20)
        struct.pack_into('<H', data, 4096+18, 2)
        self.assertEqual(ext4_context_metadata_reads(data),
                         [(0, 512), (1024, 1024), (4096, 4096), (81920, 128)])
        struct.pack_into('<I', data, 81920+40, 100)
        with self.assertRaisesRegex(AssertionError, 'bad-block tree oracle'):
            ext4_context_metadata_reads(data)


if __name__ == "__main__":
    unittest.main()
