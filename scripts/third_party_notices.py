"""Collect original notices from the locked Cargo dependency sources used by the build."""
import json
from pathlib import Path
import sys


def render(metadata):
    sections = ['Sandcrab Cargo dependency notices\n'
                'Registry dependencies from the locked Linux build, including build-time tools.\n'
                'Original license and notice text follows each package identity.\n']
    packages = sorted((p for p in metadata['packages'] if p.get('source')), key=lambda p: (p['name'], p['version']))
    for package in packages:
        directory = Path(package['manifest_path']).parent.resolve(strict=True)
        paths = set()
        for entry in directory.iterdir():
            if entry.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT', 'NOTICE', 'UNLICENSE')):
                if entry.is_dir():
                    paths.update(path for path in entry.rglob('*') if path.is_file())
                else:
                    paths.add(entry)
        if package.get('license_file'):
            paths.add(directory / package['license_file'])
        if not paths:
            raise ValueError('Missing upstream notices: ' + package['name'])
        sections.append(f"\n===== {package['name']} {package['version']} =====\nSPDX: {package.get('license') or 'See license file'}\n")
        for path in sorted(paths):
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(directory) or not resolved.is_file():
                raise ValueError('Notice escapes dependency source: ' + package['name'])
            text = resolved.read_text(encoding='utf-8')
            if not text.strip():
                raise ValueError('Empty upstream notice: ' + package['name'])
            sections.append('\n--- ' + path.relative_to(directory).as_posix() + ' ---\n' + text.rstrip('\n') + '\n')
    if not packages:
        raise ValueError('No locked dependency metadata')
    return ''.join(sections)


if __name__ == '__main__':
    metadata = json.loads(Path(sys.argv[1]).read_text())
    Path(sys.argv[2]).write_text(render(metadata), encoding='utf-8', newline='\n')
