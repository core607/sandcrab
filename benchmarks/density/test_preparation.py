import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

if os.name == 'posix':
    from preparation import corpus, writer
    from page_cache import reader, residency


@unittest.skipUnless(os.name == 'posix', 'Cache and command verification require Linux')
class PreparationTests(unittest.TestCase):
    def test_reader_and_writer_are_independently_verified_with_stable_file_identities(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'source'
            expected, changed = corpus(source, 4)
            actual = json.loads(subprocess.check_output(['bash', '-c', reader(source)], text=True))
            self.assertEqual(actual, expected)
            self.assertNotEqual(expected['sha256'], changed['sha256'])
            before = residency([source], 4)
            self.assertEqual(before['distinctInodes'], 4)
            # The benchmark commands use /workspace. Replace only their readback
            # path for this unprivileged temporary-tree unit test.
            command = writer().replace('/workspace', str(source))
            actual = json.loads(subprocess.check_output(['bash', '-c', command], cwd=source, text=True))
            self.assertEqual(actual, changed)
            self.assertEqual(residency([source], 4)['distinctInodes'], 4)


if __name__ == '__main__':
    unittest.main()
