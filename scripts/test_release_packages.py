"""Exercise partial registry publication and immutable asset reconciliation offline."""
import base64
import hashlib
from pathlib import Path
import tempfile
import unittest

from release_assets import pending
from release_packages import missing, version


class ReleaseRecovery(unittest.TestCase):
    def test_cutover_excludes_historical_and_non_identical_version_formats(self):
        self.assertEqual(version('v0.3.2'), '0.3.2')
        for tag in ('v0.3.1', 'v0.0.0-stage', '0.3.2', 'v0.3.02', 'v0.3.2-rc1'):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                version(tag)

    def test_existing_wheel_is_checked_before_only_the_missing_source_is_uploaded(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / 'sandcrab-0.3.2-py3-none-any.whl'
            source = Path(directory) / 'sandcrab-0.3.2.tar.gz'
            wheel.write_bytes(b'accepted wheel')
            source.write_bytes(b'accepted source')
            wheels = {'info': {'name': 'sandcrab', 'version': '0.3.2'}, 'urls': [
                {'filename': wheel.name, 'digests': {'sha256': hashlib.sha256(wheel.read_bytes()).hexdigest()}}]}
            self.assertEqual(missing('pypi', '0.3.2', [wheel, source], wheels), [source])
            wheels['urls'].append({'filename': source.name, 'digests': {'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}})
            self.assertEqual(missing('pypi', '0.3.2', [wheel, source], wheels), [])
            wheel.write_bytes(b'different')
            with self.assertRaisesRegex(ValueError, 'Published bytes differ'):
                missing('pypi', '0.3.2', [wheel, source], wheels)

    def test_npm_retry_checks_the_packed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sandcrab-0.3.2.tgz'
            path.write_bytes(b'accepted package')
            sri = 'sha512-' + base64.b64encode(hashlib.sha512(path.read_bytes()).digest()).decode()
            metadata = {'name': 'sandcrab', 'version': '0.3.2', 'dist': {'integrity': sri}}
            self.assertEqual(missing('npm', '0.3.2', [path], None), [path])
            self.assertEqual(missing('npm', '0.3.2', [path], metadata), [])
            path.write_bytes(b'another package')
            with self.assertRaisesRegex(ValueError, 'differs'):
                missing('npm', '0.3.2', [path], metadata)

    def test_github_release_retries_only_missing_or_identical_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / 'linux.zip'
            absent = Path(directory) / 'checksums'
            existing.write_bytes(b'accepted')
            absent.write_bytes(b'checksums')
            asset = {'name': existing.name, 'size': 8, 'digest': 'sha256:' + hashlib.sha256(b'accepted').hexdigest()}
            self.assertEqual(pending('v0.3.2', {'assets': [asset]}, [existing, absent]), [absent])
            existing.write_bytes(b'replaced')
            with self.assertRaisesRegex(ValueError, 'Existing release asset differs'):
                pending('v0.3.2', {'assets': [asset]}, [existing, absent])
