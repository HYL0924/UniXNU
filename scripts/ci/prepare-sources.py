#!/usr/bin/env python3
"""Prepare exact Git revisions and sparse file patterns from a component lock.

The component's fetch/check command subsequently validates its required files
and source archives. Patterns may name individual files and begin with '/';
these require Git's non-cone sparse checkout mode.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess


def prepare(lock, root):
    for name, source in json.loads(lock.read_text()).items():
        if not isinstance(source, dict) or 'commit' not in source or 'paths' not in source:
            continue
        if (not re.fullmatch(r'[A-Za-z0-9_-]+', name)
                or not re.fullmatch(r'[0-9a-f]{40}', source['commit'])
                or not source['url'].startswith('https://')):
            raise ValueError(f'invalid Git source identity: {name}')
        directory = root / name

        def git(*args, **kwargs):
            return subprocess.run(['git', '-C', str(directory), *args], check=True, **kwargs)

        if not directory.exists():
            directory.mkdir(parents=True)
            git('init', '-q')
            git('remote', 'add', 'origin', source['url'])
            git('config', 'remote.origin.promisor', 'true')
            git('config', 'remote.origin.partialclonefilter', 'blob:none')
            git('fetch', '--depth', '1', '--filter=blob:none', 'origin', source['commit'])
            git('sparse-checkout', 'set', '--no-cone', '--stdin',
                input='\n'.join(source['paths']) + '\n', text=True)
            git('checkout', '--detach', 'FETCH_HEAD')
        revision = subprocess.check_output(['git', '-C', str(directory), 'rev-parse', 'HEAD'], text=True).strip()
        if revision != source['commit']:
            raise ValueError(f'{name}: preserve the existing checkout; it differs from the source lock')
        git('sparse-checkout', 'set', '--no-cone', '--stdin',
            input='\n'.join(source['paths']) + '\n', text=True)
        print(f'{name}: exact revision {revision}, non-cone sparse checkout', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.lock, args.output)
