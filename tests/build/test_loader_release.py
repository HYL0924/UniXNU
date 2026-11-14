"""Exercise the actual added kernel preflight against a protection-call fixture."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class LoaderRelease(unittest.TestCase):
    def test_only_valid_whole_aperture_pages_can_be_released(self):
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('requires a host C compiler')
        patch = ROOT / 'profiles/os/ipados-27.0.1-24A446/patches/xnu-12377/loader-memory-release-preflight.patch'
        added = '\n'.join(line[1:] for line in patch.read_text().splitlines()
                          if line.startswith('+') and not line.startswith('+++'))
        prefix = '''#include <stdbool.h>
#include <stdint.h>
typedef uintptr_t vm_offset_t;
typedef uintptr_t vm_size_t;
#define PAGE_SIZE 4096UL
#define PAGE_MASK (PAGE_SIZE-1)
#define trunc_page(n) ((n)&~PAGE_MASK)
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define KERN_SUCCESS 0
static uint64_t physmap_base=0x100000;
static unsigned calls;
static vm_size_t protected_size;
static int failure;
static int ml_static_protect(vm_offset_t address,vm_size_t size,unsigned flags){
    ++calls; protected_size=size; return failure || flags!=3;
}
'''
        main = '''
int main(void){
    if(ml_static_mfree_prepare(0x100001,4096))return 1;
    if(ml_static_mfree_prepare(0xff000,4096))return 2;
    if(ml_static_mfree_prepare(0x100000,0))return 3;
    if(ml_static_mfree_prepare(UINTPTR_MAX&~PAGE_MASK,8192))return 4;
    if(calls)return 5;
    if(!ml_static_mfree_prepare(0x100000,8193)||calls!=1||protected_size!=8192)return 6;
    failure=1;
    if(ml_static_mfree_prepare(0x100000,4096))return 7;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            source = work / 'preflight.c'
            source.write_text(prefix + added + main)
            binary = work / 'preflight'
            subprocess.run([compiler, '-std=c11', source, '-o', binary], check=True)
            subprocess.run([binary], check=True)


if __name__ == '__main__':
    unittest.main()
