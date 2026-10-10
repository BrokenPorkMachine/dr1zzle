"""Host validation, linker rejection, and real QEMU boots for both budgets."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, capture_output=True, text=True, **kwargs)


class Profiles(unittest.TestCase):
    def test_wifi_transport_state_machine(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = str(Path(temp) / 'wifi')
            run([os.environ.get('HOST_CC', 'cc'), '-std=c11', '-Wall', '-Wextra',
                 '-Werror', '-fsanitize=address,undefined', '-Iinclude', '-I.',
                 'net/wifi.c', 'tests/wifi_test.c', '-o', binary])
            run([binary])

    def test_mmio_accessors(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = str(Path(temp) / 'mmio')
            run([os.environ.get('HOST_CC', 'cc'), '-std=c11', '-Wall', '-Wextra',
                 '-Werror', '-fsanitize=address,undefined', '-Iinclude',
                 'src/arch/arm64/mmio.c', 'tests/mmio_host_test.c', '-o', binary])
            run([binary])

    def test_validator(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = str(Path(temp) / 'profiles')
            run([os.environ.get('HOST_CC', 'cc'), '-std=c11', '-Wall', '-Wextra',
                 '-Werror', '-fsanitize=address,undefined', '-Iinclude', '-I.',
                 'kernel/hardware.c', 'boards/qemu_virt.c',
                 'tests/hardware_profile_test.c', '-o', binary])
            run([binary])

    def test_build_boot_and_link_limits(self):
        qemu = os.environ.get('QEMU', 'qemu-system-aarch64')
        self.assertTrue(shutil.which(qemu), 'QEMU required for boot verification')
        for profile, heap in [('small', 32768), ('monitor', 65536)]:
            with self.subTest(profile=profile):
                run(['make', '-f', 'boards/Makefile', f'PROFILE={profile}', '-j4'])
                build = ROOT / 'build/profiles' / profile
                process = subprocess.Popen(
                    [qemu, '-machine', 'virt', '-cpu', 'cortex-a53', '-m', '128M',
                     '-nographic', '-monitor', 'none', '-kernel', str(build / 'monitor.elf')],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True)
                try:
                    output, _ = process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    output, _ = process.communicate(timeout=5)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
                self.assertIn(f'profile=qemu-virt-{profile} heap={heap} bytes', output)
                self.assertIn('target=qemu-virt status=ready', output)
                # Prove the link fails if the same image has a one-byte budget.
                with tempfile.TemporaryDirectory() as temp:
                    script = Path(temp) / 'limit.ld'
                    import re
                    text = (build / 'layout.ld').read_text()
                    text, count = re.subn(r'(__heap_start - __image_start <=)[^,]+',
                                          r'\1 1', text)
                    self.assertEqual(count, 1)
                    script.write_text(text)
                    linked = subprocess.run(
                        [os.environ.get('PROFILE_LD', 'ld.lld'), '-T', str(script),
                         *map(str, sorted(build.rglob('*.o'))), '-o', str(Path(temp) / 'bad.elf')],
                        capture_output=True, text=True)
                    self.assertNotEqual(linked.returncode, 0)
                    self.assertIn('profile image budget exceeded', linked.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
