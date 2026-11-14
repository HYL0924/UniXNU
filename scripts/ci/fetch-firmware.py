#!/usr/bin/env python3
"""Fetch a manifest's firmware from a pinned HTTPS source, verifying every byte."""
import argparse
import hashlib
import json
from pathlib import Path
import time
import urllib.request


def fetch(manifest, base, destination):
    if not base.startswith('https://'):
        raise ValueError('firmware source must use HTTPS')
    for name, expected in json.loads(manifest.read_text())['files'].items():
        if Path(name).name != name or name in ('.', '..') or not 0 < expected['bytes'] <= 32 * 1024 * 1024:
            raise ValueError('invalid firmware manifest entry')
        target = destination / name
        if target.is_file():
            data = target.read_bytes()
            if len(data) == expected['bytes'] and hashlib.sha256(data).hexdigest() == expected['sha256']:
                print(f'verified {name}', flush=True)
                continue
        for attempt in range(3):
            try:
                with urllib.request.urlopen(base.rstrip('/') + '/' + name, timeout=60) as response:
                    data = response.read(expected['bytes'] + 1)
                break
            except OSError:
                if attempt == 2:
                    raise
                time.sleep(2)
        if len(data) != expected['bytes'] or hashlib.sha256(data).hexdigest() != expected['sha256']:
            raise ValueError(f'{name}: firmware size or SHA-256 differs from the device manifest')
        destination.mkdir(parents=True, exist_ok=True)
        partial = target.with_suffix(target.suffix + '.partial')
        partial.write_bytes(data)
        partial.replace(target)
        print(f'verified {name}: {len(data)} bytes', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    fetch(args.manifest, args.base_url, args.output)
