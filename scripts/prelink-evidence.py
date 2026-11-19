"""Describe regression targets using source symbol names and function fingerprints."""
import json
import sys
from bisect import bisect_left
from pathlib import Path

from unixnu.cli import parser
from unixnu.config import Context
from unixnu.kernel import prelink_gaps


def main(profile):
    ctx = Context(parser().parse_args(['prelink', '--os', profile]))
    spec = ctx.board['kernel']['prelink']
    report = ctx.work / 'kernel/kernel.failed.json'
    mapping = ctx.work / 'kernel/kernel.map.json'
    if not report.is_file() or not mapping.is_file() or not spec.get('regression_policy'):
        return
    policy = json.loads((ctx.tree / spec['regression_policy']).read_text())
    gaps = list(prelink_gaps(json.loads(report.read_text()), policy))
    if not gaps:
        return
    sys.path.insert(0, str(ctx.tree / 'kits/XnuPrelink'))
    from kc_image import Image
    from fileset_match import Side, match_images
    cache = Image((ctx.out_root / 'ipsw' / ctx.board['ipsw']['build'] / 'kernelcache.decompressed').read_bytes())
    args = spec.get('extra_args', [])
    if '--fileset-reference' not in args:
        return
    ref = ctx.tree / args[args.index('--fileset-reference') + 1]
    names = match_images(cache.data, ref.read_bytes(), pure_leaves=False)['functions']
    native = json.loads(mapping.read_text())['functions']
    entry = Image(cache.data, cache.entries['com.apple.kernel'][1])
    original = Side(entry, cache.fixups(), entry.mapped())
    starts = sorted(original.functions)

    def label(address):
        key = hex(address)
        return [key, names.get(key, {}).get('name'), native.get(key, {}).get('name')]

    with (ctx.logs / 'prelink-evidence.log').open('w') as stream:
        for kind, owner, key, count, allowed in gaps:
            address = int(key, 16)
            index = bisect_left(starts, address)
            fn = original.functions.get(address, {})
            row = dict(kind=kind, owner=owner, target=label(address), sites=count, allowed=allowed,
                       digest=fn.get('digest'), length=fn.get('length'),
                       neighbors=[label(a) for a in starts[max(0, index-5):index+6]],
                       calls=[label(a) for a in sorted(original.callees.get(address, ()))],
                       callers=[label(a) for a in sorted(original.callers.get(address, ()))[:30]])
            print(json.dumps(row), file=stream)


if __name__ == '__main__':
    main(sys.argv[1])
