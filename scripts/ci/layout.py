#!/usr/bin/env python3
"""Measure the retained-code gap using a cached native kernel and pinned IPSW."""
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'kits/XnuPrelink')]
from unixnu import cli, ipsw
from unixnu.config import Context
from kc_image import Image
from fileset_emit import dependency_closure
from fileset_layout import align

ctx = Context(cli.parser().parse_args(['build', 'kernel', '--os', '27']))
spec = ctx.board['kernel']['prelink']
native_path = ctx.tree / spec['kernel']
cache_path = ipsw.kernelcache(ctx, ipsw.Ipsw(ctx))
native, cache = Image(native_path.read_bytes()), Image(cache_path.read_bytes())
closure = dependency_closure(cache, spec['roots'])
roots = {segment['name']: segment for segment in cache.segments}
code = roots['__TEXT_EXEC']
occupied = []
for name, (_, offset) in cache.entries.items():
    if name == 'com.apple.kernel' or name not in closure:
        continue
    for segment in Image(cache.data, offset).segments:
        if segment['size'] and segment['name'] != '__LINKEDIT' and code['va'] <= segment['va'] < code['va'] + code['size']:
            occupied.append({'entry': name, 'name': segment['name'], 'begin': segment['va'],
                             'end': segment['va'] + segment['size']})
begin = align(max([code['va']] + [item['end'] for item in occupied]))
text = next(segment for segment in native.segments if segment['name'] == '__TEXT_EXEC')
kld = next(segment for segment in native.segments if segment['name'] == '__KLD')
end = align(begin + text['size']) + kld['size']
floor = roots['__DATA']['va']
report = {'available_code_bytes': floor - begin, 'required_code_bytes': end - begin,
          'overflow_bytes': max(0, end - floor), 'native_segments': native.segments,
          'native_sections': native.sections, 'roots': roots,
          'last_retained_segments': sorted(occupied, key=lambda item: item['end'])[-12:]}
target = ROOT / 'layout-inputs'
target.mkdir(exist_ok=True)
for path, name in [(native_path, 'native-kernel.macho'), (cache_path, 'kernelcache.decompressed')]:
    shutil.copyfile(path, target / name)
(target / 'roots.json').write_text(json.dumps(spec['roots'], indent=2))
(target / 'layout.json').write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
