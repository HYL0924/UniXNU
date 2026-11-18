"""Report the native-code budget without changing the fileset or its placement policy."""
import sys

from unixnu.cli import parser
from unixnu.config import Context


def main(profile):
    ctx = Context(parser().parse_args(['prelink', '--os', profile]))
    spec = ctx.board['kernel']['prelink']
    raw = ctx.out_root / 'ipsw' / ctx.board['ipsw']['build'] / 'kernelcache.decompressed'
    native = ctx.tree / spec['kernel']
    if not raw.is_file() or not native.is_file():
        print('Layout not measured: build did not produce both inputs')
        return
    sys.path.insert(0, str(ctx.tree / 'kits/XnuPrelink'))
    from kc_image import Image
    from fileset_emit import dependency_closure
    from fileset_layout import align

    cache, image = Image(raw.read_bytes()), Image(native.read_bytes())
    if cache.kind != 12:
        return
    roots = {s['name']: s for s in cache.segments}
    native_sizes = {s['name']: s['size'] for s in image.segments}
    closure = dependency_closure(cache, spec.get('roots', []))
    code = roots['__TEXT_EXEC']
    ends = [(code['va'], '(none)')]
    for name, (_, offset) in cache.entries.items():
        if name == 'com.apple.kernel' or closure is not None and name not in closure:
            continue
        for s in Image(cache.data, offset).segments:
            if s['size'] and s['name'] != '__LINKEDIT' and code['va'] <= s['va'] < code['va'] + code['size']:
                ends.append((s['va'] + s['size'], name))
    last, owner = max(ends)
    start = align(last)
    end = align(start + native_sizes['__TEXT_EXEC']) + native_sizes['__KLD']
    limit = roots['__DATA']['va']
    print(f'Last retained: {owner}; native start={start:#x}, end={end:#x}, __DATA={limit:#x}')
    print(f'Available={limit - start} bytes; required={end - start} bytes; margin={limit - end} bytes')


if __name__ == '__main__':
    main(sys.argv[1])
