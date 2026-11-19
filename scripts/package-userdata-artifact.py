"""Compress and encrypt a raw userdata image in independently recoverable chunks."""
import gzip
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def package(source, recipient, output):
    report = json.loads((source / 'userdata-root.json').read_text())
    output.mkdir()
    digest = hashlib.sha256()
    chunks = []
    with (source / 'userdata-root.img').open('rb') as image:
        while data := image.read(64 * 1024 * 1024):
            digest.update(data)
            name = f'userdata-{len(chunks):04d}.gz.cms'
            subprocess.run(['openssl', 'cms', '-encrypt', '-binary', '-aes-256-cbc', '-outform', 'DER',
                            '-out', str(output / name), str(recipient)],
                           input=gzip.compress(data, compresslevel=1, mtime=0), check=True)
            chunks.append(name)
        if image.tell() != report['image_bytes'] or digest.hexdigest() != report['image_sha256']:
            raise ValueError('userdata image differs from the build report')
    manifest = {key: report[key] for key in ('image_bytes', 'image_sha256', 'manifest_sha256', 'windows')}
    manifest['chunks'] = chunks
    (output / 'userdata-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    package(*map(Path, sys.argv[1:]))
