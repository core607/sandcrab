import os
import unittest

if os.name == 'posix':
    from footprint import cost


@unittest.skipUnless(os.name == 'posix', 'Native footprint imports Linux host APIs')
class FootprintTests(unittest.TestCase):
    def test_shared_cache_releases_remain_negative_and_shmem_is_not_double_counted(self):
        def row(total, daemon, pids, file, shmem):
            return {'memoryCurrentBytes': total, 'daemonRssBytes': daemon, 'pidsCurrent': pids,
                    'memoryStat': {'anon': 100, 'file': file, 'shmem': shmem, 'kernel': 50}}

        before = [row(1000, 500, 2, 600, 200)] * 5
        after = [row(900, 510, 6, 400, 100)] * 4 + [row(5000, 4000, 100, 4000, 1000)]
        value = cost(before, after, 2)
        self.assertEqual(value['memoryCurrentBytes'], -50)
        self.assertEqual(value['daemonRssBytes'], 5)
        self.assertEqual(value['pidsCurrent'], 2)
        self.assertEqual(value['memoryStat']['file'], -100)
        self.assertEqual(value['memoryStat']['shmem'], -50)


if __name__ == '__main__':
    unittest.main()
