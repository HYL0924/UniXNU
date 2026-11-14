#!/usr/bin/env python3
"""Prepare authenticated userdata and package the matching GKI boot images.

Run on the macOS builder, with UNIXNU_DEVICE and UNIXNU_UEFI set. No device
is flashed. The selected board and OS profiles supply the root identities.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from unixnu import bootimg, cli, firmware, userdata, vendor_boot
from unixnu.config import Context
from unixnu.util import Error, sha256_file


def context(os_profile):
    return Context(cli.parser().parse_args(['build', 'kernel', '--os', os_profile]))


def prepare(ctx):
    """Sign the exact raw windows and include their authenticated tables in userdata."""
    cli.prepare(ctx, ['kernel'])
    source = userdata.Ipsw(ctx)
    scratch = ctx.work / 'ci-roots'
    scratch.mkdir(parents=True, exist_ok=True)
    policy_dir = ctx.device / 'scripts/policies' / ctx.work.parent.name
    command = [sys.executable, ROOT / 'scripts/make-root-policies.py',
               '--tree', ctx.tree, '--output', policy_dir]
    objects = []
    try:
        for window in ctx.board['userdata']['windows']:
            name = window['name']
            try:
                source.member(window['component'])
            except Error:
                if window.get('optional'):
                    continue
                raise
            image = source.disk_image(window['component'])
            raw = scratch / f'{name}.raw'
            digest = hashlib.sha256()
            size = userdata.image_size(image)
            with raw.open('wb') as target:
                with contextlib.closing(userdata.disk_blocks(image, size)) as blocks:
                    for block in blocks:
                        target.write(block)
                        digest.update(block)
            expected = ctx.board['root'][f'{name.lower()}_image_sha256']
            if raw.stat().st_size != size or digest.hexdigest() != expected:
                raise Error(f'{name}: raw window differs from the selected OS profile')
            volume = ctx.board['root'][f'{name.lower()}_volume_uuid']
            command += ['--window', f'{name}={raw}:{volume}']
            objects.append(f'{name}.vroot={ctx.tree}/build/verified-root-{name}/hashes.bin')
        subprocess.run([str(item) for item in command], check=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    # prepare() copies the newly generated signed headers into the assembled
    # tree before the kernel links their public trust anchor.
    ctx.args.object = objects
    userdata.build(ctx)


def pack(ctx, stock, address):
    """Keep the GKI boot ramdisk empty; carry the FAT payload in vendor_boot."""
    stock_data = stock.read_bytes()
    parts = vendor_boot.parse(stock_data)
    rebuilt, _ = vendor_boot.pack(parts, parts['ramdisk'], parts['ramdisk_address'])
    if rebuilt != stock_data:
        raise Error('stock vendor_boot does not round-trip')
    image_options = ctx.board.setdefault('bootimg', {}).setdefault('image', {})
    image_options.update(header_version=4, pagesize=4096, append_dtb=False)
    boot = bootimg.build(ctx, ctx.option('uefi', 'UNIXNU_UEFI'),
                         firmware.fd_path(ctx, ctx.option('uefi', 'UNIXNU_UEFI'), ctx.args.target), None)
    payload = ctx.work / 'payload/payload.img'
    vendor = vendor_boot.build(stock, payload, ctx.work / 'boot/vendor_boot.img',
                               ramdisk_address=address, verify_against=True)
    data = vendor_boot.parse(vendor.read_bytes())
    if data['ramdisk'] != payload.read_bytes() or data['dtb'] != parts['dtb']:
        raise Error('vendor_boot payload or device tree differs from its inputs')
    # The DTB address is a u64 at 2104 in vendor_boot v4. Compare the load
    # windows before an image can be uploaded.
    dtb_address = struct.unpack_from('<Q', parts['header'], 2104)[0]
    if address < dtb_address + len(parts['dtb']) and dtb_address < address + payload.stat().st_size:
        raise Error('vendor ramdisk overlaps the device tree load address')
    boot_data = boot.read_bytes()
    if struct.unpack_from('<I', boot_data, 12)[0] != 0:
        raise Error('GKI boot.img must have an empty ramdisk')
    root = ctx.work / 'userdata/userdata-root.img'
    root_report = json.loads(root.with_suffix('.json').read_text())
    if sha256_file(root) != root_report['image_sha256']:
        raise Error('userdata differs from its build report')
    names = {item['name'] for item in root_report['objects']}
    if any(f'{window["name"]}.vroot' not in names for window in root_report['windows']):
        raise Error('userdata is missing a verified-root block table')
    payload_report = json.loads((ctx.work / 'payload/payload.json').read_text())

    def read_fat(name):
        return subprocess.check_output(['mtype', '-i', str(payload), f'::EFI/UniXNU/{name}'])

    if sha256_file(payload) != payload_report['payload_sha256']:
        raise Error('payload differs from its build report')
    for filename, key in [('kernel.macho', 'payload_kernel_sha256'), ('kernel.macho.adt', 'adt_sha256'),
                          ('kernel.macho.trustcache', 'trust_cache_sha256'),
                          ('kernel.macho.gpuaddon', 'gpu_addon_sha256'), ('scratch-data.img', 'data_ramdisk_sha256')]:
        expected = payload_report.get(key)
        if not expected or hashlib.sha256(read_fat(f'Payloads/{filename}')).hexdigest() != expected:
            raise Error(f'FAT payload dependency missing or corrupted: {filename}')
    config = tomllib.loads(read_fat('unixnu.toml').decode())
    entry = next(item for item in config['entry'] if item['id'] == 'xnu')
    if (entry['args'] != payload_report['kernel_args'] or entry['path'] != 'Payloads/kernel.macho'
            or entry.get('initrd') != 'Payloads/scratch-data.img'):
        raise Error('packed boot entry differs from the kernel/runtime configuration')
    policies = read_fat('Payloads/kernel.macho.vroot')
    if policies[:8] != b'VROOTB01' or struct.unpack_from('<Q', policies, 16)[0] != len(root_report['windows']):
        raise Error('packed root-policy bundle does not cover the userdata windows')
    for index, window in enumerate(root_report['windows']):
        offset, length = struct.unpack_from('<QQ', policies, 32 + 16 * index)
        header = policies[offset:offset + length]
        if len(header) != 544 or header[56:88].hex() != window['sha256']:
            raise Error(f'{window["name"]}: packed signed root policy differs from userdata')
    target = ctx.work / 'downloads'
    target.mkdir(exist_ok=True)
    manifest = {'device': ctx.name, 'os_profile': ctx.work.parent.name,
                'configuration': ctx.config_name, 'hardware_tested': False,
                'source_commit': subprocess.check_output(['git', '-C', ROOT, 'rev-parse', 'HEAD'], text=True).strip(),
                'device_commit': subprocess.check_output(['git', '-C', ctx.device, 'rev-parse', 'HEAD'], text=True).strip(),
                'uefi_commit': subprocess.check_output(['git', '-C', ctx.option('uefi', 'UNIXNU_UEFI'), 'rev-parse', 'HEAD'], text=True).strip(),
                'images': {}}
    checksums = []
    for path in (boot, vendor, root):
        digest = sha256_file(path)
        shutil.move(str(path), target / path.name)
        manifest['images'][path.name] = {'bytes': (target / path.name).stat().st_size, 'sha256': digest}
        checksums.append(f'{digest}  {path.name}\n')
    (target / 'SHA256SUMS').write_text(''.join(checksums))
    (target / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    for report in (ctx.work / 'boot/boot.json', ctx.work / 'boot/vendor_boot.json',
                   ctx.work / 'userdata/userdata-root.json', ctx.work / 'payload/payload.json'):
        shutil.copyfile(report, target / report.name)
    print(json.dumps(manifest, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['prepare', 'pack'])
    parser.add_argument('--os', required=True)
    parser.add_argument('--stock-vendor-boot', type=Path)
    parser.add_argument('--ramdisk-addr', type=lambda value: int(value, 0))
    args = parser.parse_args()
    ctx = context(args.os)
    if args.stage == 'prepare':
        prepare(ctx)
    else:
        if args.stock_vendor_boot is None or args.ramdisk_addr is None:
            parser.error('pack needs --stock-vendor-boot and --ramdisk-addr')
        pack(ctx, args.stock_vendor_boot, args.ramdisk_addr)


if __name__ == '__main__':
    main()
