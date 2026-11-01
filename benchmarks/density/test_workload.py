import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from workload import AgentWorkload, create


class WorkloadTests(unittest.TestCase):
    def test_same_seed_reproduces_corpus_and_git_commit_and_other_seed_changes_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            roots = [Path(temporary) / name for name in ('first', 'second', 'different')]
            for root in roots:
                root.mkdir()
            first, second, different = [create(root, seed, files=400) for root, seed in zip(roots, (73, 73, 74))]
            self.assertEqual(first, second)
            self.assertNotEqual(first['corpusSha256'], different['corpusSha256'])
            self.assertNotEqual(first['gitCommit'], different['gitCommit'])
            self.assertEqual(len(list((roots[0] / 'corpus').rglob('*.md'))), 400)
            tracked = subprocess.run(['git', '-C', str(roots[0] / 'small-repo'), 'ls-files'],
                                     check=True, text=True, capture_output=True).stdout.splitlines()
            self.assertEqual(len(tracked), 32)

    def test_occupied_root_and_ambient_git_redirects_cannot_overwrite_other_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'corpus'
            other = Path(temporary) / 'unrelated'
            root.mkdir()
            other.mkdir()
            sentinel = other / 'keep'
            sentinel.write_bytes(b'preserved')
            with self.assertRaises(ValueError):
                create(other, 73)
            with patch.dict(os.environ, {'GIT_DIR': str(other), 'GIT_WORK_TREE': str(other),
                                        'GIT_INDEX_FILE': str(other / 'index'),
                                        'GIT_OBJECT_DIRECTORY': str(other / 'objects')}):
                create(root, 73, files=64)
            self.assertEqual(list(other.iterdir()), [sentinel])
            self.assertEqual(sentinel.read_bytes(), b'preserved')

    def test_agent_sequences_repeat_and_each_think_precedes_one_mix_command(self):
        first, second = AgentWorkload(91, 2), AgentWorkload(91, 2)
        rows = [first.next() for _ in range(1000)]
        self.assertEqual(rows, [second.next() for _ in range(1000)])
        self.assertEqual(set(row['kind'] for row in rows), {'rg', 'read', 'edit', 'list', 'git', 'python'})
        self.assertTrue(all(3 <= row['thinkSeconds'] <= 10 for row in rows))
        self.assertNotEqual(rows[0], AgentWorkload(91, 3).next())

    @unittest.skipUnless(os.name == 'posix', 'Actual command mix requires Linux tools')
    def test_every_command_kind_executes_against_the_generated_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            create(root, 73, files=400)
            workload = AgentWorkload(91, 0, files=400)
            seen = set()
            for _ in range(100):
                row = workload.next()
                if row['kind'] in seen:
                    continue
                result = subprocess.run(['bash', '-c', row['command']], cwd=root,
                                        capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertLessEqual(len(result.stdout) + len(result.stderr), 65_536)
                seen.add(row['kind'])
                if len(seen) == 6:
                    break
            self.assertEqual(len(seen), 6)
            changed = [p for p in (root / 'small-repo').glob('*.md') if not p.read_text().startswith('revision=0\n')]
            self.assertEqual(len(changed), 1)


if __name__ == '__main__':
    unittest.main()
