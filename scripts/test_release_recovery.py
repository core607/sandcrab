import hashlib
from pathlib import Path
import tempfile
import unittest

from release_recovery import tag_source, verify_release


class RecoveryTests(unittest.TestCase):
    def test_only_a_completed_first_party_tag_run_that_published_the_service_can_resume(self):
        repo = 'example/sandcrab'
        run = {'head_branch': 'v0.4.0', 'event': 'push', 'status': 'completed',
               'path': '.github/workflows/publish-sdks.yml', 'head_repository': {'full_name': repo},
               'head_sha': 'a' * 40}
        jobs = [{'name': n, 'conclusion': 'success'} for n in ('build', 'service / publish')]
        self.assertEqual(tag_source(run, jobs, repo), ('v0.4.0', run['head_sha']))
        for change in [{'event': 'workflow_dispatch'}, {'event': 'pull_request'}, {'head_branch': 'main'},
                       {'path': 'another.yml'}, {'head_repository': {'full_name': 'a/fork'}}, {'status': 'in_progress'}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                tag_source({**run, **change}, jobs, repo)
        with self.assertRaises(ValueError):
            tag_source(run, jobs[:1], repo)

    def test_recovery_requires_identical_assets_from_the_same_public_stable_tag(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / 'package.tgz'
            archive.write_bytes(b'released')
            asset = {'name': archive.name, 'size': 8, 'digest': 'sha256:' + hashlib.sha256(b'released').hexdigest()}
            release = {'tag_name': 'v0.4.0', 'draft': False, 'prerelease': False, 'assets': [asset]}
            revision = 'b' * 40
            verify_release('v0.4.0', revision, revision, release, [archive])
            for change in [{'draft': True}, {'prerelease': True}, {'assets': []}, {'tag_name': 'v0.4.1'}]:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    verify_release('v0.4.0', revision, revision, {**release, **change}, [archive])
            with self.assertRaises(ValueError):
                verify_release('v0.4.0', revision, 'c' * 40, release, [archive])
            archive.write_bytes(b'mismatch')
            with self.assertRaises(ValueError):
                verify_release('v0.4.0', revision, revision, release, [archive])
