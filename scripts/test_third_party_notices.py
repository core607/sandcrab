from pathlib import Path
import tempfile
import unittest

from third_party_notices import render


class DependencyNotices(unittest.TestCase):
    def test_preserves_every_alternative_and_required_notice(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = {'name':'example', 'version':'1.2.3', 'source':'registry+example',
                       'manifest_path':str(root / 'Cargo.toml'), 'license':'(MIT OR Apache-2.0) AND Unicode-3.0'}
            texts = {'LICENSE-MIT':'Copyright Example\nPermission text\n', 'LICENSE-UNICODE':'Unicode terms\n',
                     'NOTICE':'Required attribution\n', 'LICENSE-APACHE':'Apache terms\n'}
            for name, text in texts.items():
                (root / name).write_text(text)
            result = render({'packages':[package]})
            self.assertIn('example 1.2.3', result)
            for text in texts.values():
                self.assertIn(text, result)

    def test_missing_empty_or_outside_notice_stops_packaging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'crate'
            source.mkdir()
            package = {'name':'example', 'version':'1', 'source':'registry+example', 'manifest_path':str(source / 'Cargo.toml')}
            with self.assertRaises(ValueError):
                render({'packages':[package]})
            (source / 'LICENSE').write_text('')
            with self.assertRaises(ValueError):
                render({'packages':[package]})
            (source / 'LICENSE').write_text('Local terms')
            (root / 'foreign').write_text('Operator material')
            package['license_file'] = '../foreign'
            with self.assertRaises(ValueError):
                render({'packages':[package]})


if __name__ == '__main__':
    unittest.main()
