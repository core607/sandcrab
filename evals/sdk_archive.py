"""Trusted export program, executed inside a sandbox after closing its producing shell."""

SOURCE = r'''
import hashlib, json, os, stat, sys, tarfile

destination = sys.argv[1]
limit = 2 * 1024 * 1024

class Bounded:
    def __init__(self, file):
        self.file, self.count = file, 0
    def write(self, data):
        if self.count + len(data) > limit:
            raise ValueError('Artifact exceeds 2 MiB')
        count = self.file.write(data)
        self.count += count
        return count

with open(destination, 'xb') as output:
    with tarfile.open(fileobj=Bounded(output), mode='w|', format=tarfile.PAX_FORMAT, dereference=False) as archive:
        count = 0
        for directory, dirs, files in os.walk('.', followlinks=False):
            dirs.sort()
            for entry in sorted(dirs + files):
                name = os.path.join(directory, entry)[2:]
                if name == destination:
                    continue
                count += 1
                if count > 1024:
                    raise ValueError('Artifact exceeds 1024 entries')
                mode = os.lstat(name).st_mode
                if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                    raise ValueError('Artifact contains a special file')
                archive.add(name, arcname=name, recursive=False)
    output.flush()
    os.fsync(output.fileno())
with open(destination, 'rb') as source:
    raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Artifact exceeds 2 MiB')
print(json.dumps({'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}))
'''
