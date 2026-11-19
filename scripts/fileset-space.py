"""Report native code and writable-data budgets without changing fileset placement."""
import struct
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
    data = roots['__DATA']
    first = (data['va'] + data['size'], '(end of root)', '__DATA')
    ends = [(code['va'], '(none)')]
    for name, (_, offset) in cache.entries.items():
        if name == 'com.apple.kernel' or closure is not None and name not in closure:
            continue
        for s in Image(cache.data, offset).segments:
            if (s['name'] != '__LINKEDIT' and s['size'] and
                    s['va'] < data['va'] + data['size'] and s['va'] + s['size'] > data['va']):
                first = min(first, (max(s['va'], data['va']), name, s['name']))
            if s['size'] and s['name'] != '__LINKEDIT' and code['va'] <= s['va'] < code['va'] + code['size']:
                ends.append((s['va'] + s['size'], name))
    last, owner = max(ends)
    start = align(last)
    end = align(start + native_sizes['__TEXT_EXEC']) + native_sizes['__KLD']
    limit = roots['__DATA']['va']
    print(f'Last retained: {owner}; native start={start:#x}, end={end:#x}, __DATA={limit:#x}')
    print(f'Available={limit - start} bytes; required={end - start} bytes; margin={limit - end} bytes')
    for s in cache.segments:
        prot = struct.unpack_from('<ii', cache.data, s['command_offset'] + 56)
        print(f'Root {s["name"]}: va={s["va"]:#x} size={s["size"]:#x} '
              f'fileoff={s["fileoff"]:#x} filesize={s["filesize"]:#x} max/init prot={prot}')
    native_data = next(s for s in image.segments if s['name'] == '__DATA')
    room = first[0] - data['va']
    print(f'Native __DATA: vmsize={native_data["size"]}, filesize={native_data["filesize"]}; '
          f'available={room}, deficit={max(0, native_data["size"] - room)}; '
          f'first limit={first[1]}:{first[2]} at {first[0]:#x}')
    symbols = image.symbols()
    gaps = []
    for section in image.sections:
        if section['segment'] != '__DATA' or not section['size']:
            continue
        va, size = section['va'], section['size']
        print(f'Native __DATA,{section["name"]}: offset={va-native_data["va"]:#x} size={size}')
        starts = sorted(x for x in symbols if va <= x < va + size)
        for a, b in zip(starts, starts[1:] + [va + size]):
            gaps.append((b - a, section['name'], symbols[a][0]))
    for span, section, symbol in sorted(gaps, reverse=True)[:30]:
        print(f'Native writable symbol (span to next symbol or section end): {span} {section} {symbol}')


if __name__ == '__main__':
    main(sys.argv[1])
