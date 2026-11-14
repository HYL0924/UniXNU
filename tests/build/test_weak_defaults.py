"""Static kernel diagnostic fallbacks must cover complete weak declarations."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('source_storage', ROOT / 'scripts/build-sheng-source-storage.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

DECLARATIONS = '''#include <stdint.h>
extern uint64_t wall[2] __attribute__((weak_import)), cpu[2] __attribute__((weak_import)),
    bytes[2] __attribute__((weak_import)), ticks __attribute__((weak_import));
extern int optional_query(unsigned) __attribute__((weak_import));
'''


class WeakDefaults(unittest.TestCase):
    def test_multiline_counters_are_defined_and_real_providers_win(self):
        compiler = shutil.which('clang')
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            source = work / 'diagnostic.c'
            source.write_text(DECLARATIONS)
            defaults = module.weak_defaults(source)
            self.assertIn('bytes[2]', defaults)
            self.assertIn('ticks', defaults)
            self.assertNotIn('weak_import', defaults)
            if compiler is None:
                return  # Declaration coverage still runs on hosts without a C compiler.
            (work / 'defaults.c').write_text(defaults)
            main = '#include <stdint.h>\nextern uint64_t wall[2],cpu[2],bytes[2],ticks;\nextern int optional_query(unsigned);\n'
            (work / 'main.c').write_text(main + 'int main(void){return wall[0] || cpu[0] || bytes[1] || ticks || optional_query(0)!=-1;}\n')
            binary = work / 'fallback'
            subprocess.run([compiler, '-fno-common', work / 'defaults.c', work / 'main.c', '-o', binary], check=True)
            subprocess.run([binary], check=True)
            (work / 'provider.c').write_text('#include <stdint.h>\nuint64_t wall[2]={7,0},cpu[2]={8,0},bytes[2]={0,9},ticks=10;\nint optional_query(unsigned n){return 11;}\n')
            (work / 'main.c').write_text(main + 'int main(void){return wall[0]!=7 || cpu[0]!=8 || bytes[1]!=9 || ticks!=10 || optional_query(0)!=11;}\n')
            subprocess.run([compiler, '-fno-common', work / 'defaults.c', work / 'provider.c', work / 'main.c', '-o', binary], check=True)
            subprocess.run([binary], check=True)


if __name__ == '__main__':
    unittest.main()
