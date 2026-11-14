"""GKI packaging must preserve vendor_boot's DTB and keep boot ramdisk empty."""
import gzip
import struct
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from unixnu import bootimg


class GkiBoot(unittest.TestCase):
    def test_v4_without_an_appended_dtb_or_ramdisk(self):
        with TemporaryDirectory() as directory:
            work = Path(directory)
            fd = work / 'firmware.fd'
            fd.write_bytes(b'firmware')
            ctx = SimpleNamespace(work=work, board={'bootimg': {'image': {
                'header_version': 4, 'pagesize': 4096, 'append_dtb': False}}})
            uefi = work / 'uefi'
            (uefi / 'Resources/Scripts').mkdir(parents=True)
            (uefi / 'Resources/Scripts/mkbootimg.py').touch()

            def mkbootimg(command, **kwargs):
                kernel = Path(command[command.index('--kernel') + 1]).read_bytes()
                header = bytearray(4096)
                header[:8] = b'ANDROID!'
                struct.pack_into('<4I', header, 8, len(kernel), 0, 0, 1584)
                struct.pack_into('<I', header, 40, 4)
                Path(command[command.index('-o') + 1]).write_bytes(header + kernel)

            settings = ({'header_version': 4, 'pagesize': 4096, 'append_dtb': False},
                        0xA7100000, len(fd.read_bytes()), True, {})
            with patch.object(bootimg, 'settings', return_value=settings), \
                 patch.object(bootimg, 'compile_shim', return_value=b'shim'), \
                 patch.object(bootimg, 'run', side_effect=mkbootimg):
                output = bootimg.build(ctx, uefi, fd, None)
            data = output.read_bytes()
            self.assertEqual(struct.unpack_from('<I', data, 12)[0], 0)
            self.assertEqual(gzip.decompress(data[4096:]), b'shimfirmware')


if __name__ == '__main__':
    unittest.main()
