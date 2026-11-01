import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

if os.name == 'posix':
    from page_cache import reader, residency
    from workload import create


@unittest.skipUnless(os.name == 'posix', 'Page-cache observations require Linux')
class PageCacheTests(unittest.TestCase):
    def test_reader_verifies_all_bytes_and_mincore_observes_real_pages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = create(root, 73, 8)
            value = json.loads(subprocess.check_output(['bash', '-c', reader(root)], text=True))
            self.assertEqual(value['files'], 8)
            self.assertEqual(value['sha256'], manifest['corpusSha256'])
            observed = residency([root], 8)
            self.assertEqual(observed['distinctInodes'], 8)
            self.assertEqual(observed['files'], 8)
            self.assertEqual(observed['payloadBytes'], value['bytes'])
            self.assertEqual(observed['residentPages'], observed['pages'])
            self.assertEqual(observed['residentBytes'], observed['pages'] * os.sysconf('SC_PAGE_SIZE'))
            with self.assertRaisesRegex(RuntimeError, 'reuses an inode'):
                residency([root, root], 8)


if __name__ == '__main__':
    unittest.main()
