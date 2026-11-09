"""Pin the operator command count and the release installer's ownership boundary."""
from contextlib import ExitStack
import importlib.util
from io import BytesIO
import os
from pathlib import Path
import hashlib
import shutil
import stat
import tempfile
import unittest
from zipfile import ZipFile

from quickstart import README, recipe


class ReadmeRecipe(unittest.TestCase):
    def test_editor_or_extra_command_cannot_pass_as_three_unassisted_steps(self):
        readme = README.read_text(encoding='utf-8')
        self.assertEqual(len(recipe(readme)), 3)
        install = 'python3 -I sandcrab-linux-x86_64.zip'
        for changed in ('vi /etc/sandcrab/config.toml', install + '\nvi /etc/sandcrab/config.toml',
                        install + ' && vi /etc/sandcrab/config.toml'):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                recipe(readme.replace(install, changed))


@unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'requires a protected Linux fixture')
class BundleFiles(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('release_entrypoint', Path(__file__).with_name('__main__.py'))
        self.entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.entry)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir='/var/lib')))
        self.release = self.root / 'release'
        self.archive = self.stack.enter_context(ZipFile(BytesIO(), 'w'))
        for name in [*self.entry.FILES, '__main__.py']:
            self.archive.writestr(name, name.encode())

    def test_reinstall_preserves_matching_files_and_refuses_a_modified_release(self):
        self.entry.install_files(self.archive, self.release)
        for name, mode in self.entry.FILES.items():
            path = self.release / name
            self.assertEqual(path.read_bytes(), name.encode())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
        binary = self.release / 'sandcrab'
        original = binary.stat().st_ino
        self.entry.install_files(self.archive, self.release)
        self.assertEqual(binary.stat().st_ino, original)
        binary.write_bytes(b'operator-owned')
        with self.assertRaisesRegex(RuntimeError, 'differs'):
            self.entry.install_files(self.archive, self.release)
        self.assertEqual(binary.read_bytes(), b'operator-owned')

    def test_real_packager_delivers_the_project_license_and_threat_model_offline(self):
        repository = Path(__file__).resolve().parents[3]
        spec = importlib.util.spec_from_file_location('release_package', repository / 'scripts/package.py')
        package = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(package)
        payload = self.root / 'payload'
        payload.mkdir()
        for name in ('sandcrab', 'bwrap', 'bwrap-notices.txt', 'bwrap-source.tar.xz'):
            (payload / name).write_bytes(name.encode())
        for name in ('LICENSE', 'THREAT-MODEL.md'):
            shutil.copyfile(repository / name, payload / name)
        package.package(payload, Path(__file__).with_name('__main__.py'))
        with ZipFile(payload / 'sandcrab-linux-x86_64.zip') as archive:
            self.entry.install_files(archive, self.release)
        for name in ('LICENSE', 'THREAT-MODEL.md'):
            self.assertEqual((self.release / name).read_bytes(), (repository / name).read_bytes())
            self.assertEqual(stat.S_IMODE((self.release / name).stat().st_mode), 0o644)
        rows = [line.split('  ', 1) for line in (payload / 'SHA256SUMS').read_text().splitlines()]
        self.assertEqual(len(rows), len({name for _, name in rows}))
        self.assertEqual({name for _, name in rows}, {*self.entry.FILES, 'sandcrab-linux-x86_64.zip'})
        for expected, name in rows:
            self.assertEqual(expected, hashlib.sha256((payload / name).read_bytes()).hexdigest())

    def test_foreign_directory_link_and_unexpected_archive_member_are_refused(self):
        other = self.root / 'other'
        other.mkdir()
        self.release.symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'protected'):
            self.entry.install_files(self.archive, self.release)
        self.assertEqual(list(other.iterdir()), [])
        self.release.unlink()
        self.archive.writestr('../outside', b'extra')
        with self.assertRaises(ValueError):
            self.entry.install_files(self.archive, self.release)
        self.assertFalse(self.release.exists())

    def test_a_prior_release_missing_documents_gets_upgrade_guidance_without_replacement(self):
        self.entry.install_files(self.archive, self.release)
        binary = self.release / 'sandcrab'
        original = binary.stat().st_ino
        (self.release / 'LICENSE').unlink()
        with self.assertRaisesRegex(RuntimeError, 'custom installation procedure'):
            self.entry.install_files(self.archive, self.release)
        self.assertEqual(binary.stat().st_ino, original)
        self.assertFalse((self.release / 'LICENSE').exists())


if __name__ == '__main__':
    unittest.main()
