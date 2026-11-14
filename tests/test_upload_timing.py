"""Exact wire/framing and end-to-end budgets, without wall-clock sleeps."""
import unittest
from upload_timing import MIB, full_record, full_image_records, record_timing


class Timelines(unittest.TestCase):
    def test_queue_policy_cases(self):
        block = full_record('rate-test',0,4096)
        self.assertEqual(record_timing(block,512), dict(wire_bytes=4206, rate=512,
            writes=9, arrival_us=8000000, complete_us=8214843))
        self.assertEqual(record_timing(block,0)['complete_us'],0)
        self.assertLess(record_timing(block,512)['complete_us']/1e6+6,15)

    def test_service_policy_witness_and_finish(self):
        first = record_timing(full_record('reload-test',0,MIB),128*1024)
        second = record_timing(full_record('reload-test',MIB,MIB),104869)
        self.assertEqual(first,dict(wire_bytes=1048690,rate=131072,writes=9,
                                   arrival_us=8000000,complete_us=8000869))
        self.assertEqual(second,dict(wire_bytes=1048693,rate=104869,writes=11,
                                    arrival_us=10000000,complete_us=10000028))
        # Visibility + the zero-policy ACK finish before record2's last byte.
        self.assertLess(3+3.5,second['arrival_us']/1e6-.25)
        # No record3 may retain a positive rate: ACK is proven inside record2.
        self.assertEqual(record_timing(full_record('reload-test',2*MIB,MIB),0)['complete_us'],0)
        self.assertLess((first['complete_us']+second['complete_us'])/1e6,19)

    def test_bulk_rate_must_be_retired(self):
        records = list(full_image_records('reload-test',31*MIB,[(27*MIB,31*MIB)]))
        records += list(full_image_records('reload-test-disk-1',24*MIB,[(18*MIB,22*MIB)]))
        self.assertEqual(len(records),55)
        self.assertEqual(sum(len(block.get('buffer',b'')) for block in records),47*MIB)
        old = sum(record_timing(block,128*1024 if i==0 else 256*1024)['complete_us']
                  for i,block in enumerate(records))
        self.assertGreater(old/1e6,192)
        corrected = sum(record_timing(block,128*1024 if i==0 else 104869 if i==1 else 0)['complete_us']
                        for i,block in enumerate(records))
        self.assertLess(corrected/1e6,19)
        print(f'full multi-image timeline: records={len(records)}, wire={sum(record_timing(b,0)["wire_bytes"] for b in records)}, '
              f'old_us={old}, corrected_us={corrected}')


if __name__ == '__main__':
    unittest.main()
