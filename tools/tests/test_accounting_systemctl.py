#!/usr/bin/python3
"""Exercise systemctl file operations against disposable synthetic roots only."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which('systemctl'), 'systemctl unavailable')
class RuntimeMaskTests(unittest.TestCase):
    def test_failed_batch_mask_can_create_other_masks_without_stopping_services(self):
        # --root confines systemctl to these files and never contacts PID1.
        # A conflicting runtime file reproduces a normal exit-code-1 refusal
        # after other requested masks have already been installed.
        with tempfile.TemporaryDirectory(prefix='localpin-mask-fixture-') as directory:
            root = Path(directory)
            runtime = root / 'run/systemd/system'
            vendor = root / 'usr/lib/systemd/system'
            runtime.mkdir(parents=True)
            vendor.mkdir(parents=True)
            unit = '[Service]\nExecStart=/usr/bin/true\n'
            (vendor / 'synthetic.service').write_text(unit)
            conflict = runtime / 'conflict.service'
            conflict.write_text(unit)

            result = subprocess.run(
                [shutil.which('systemctl'), '--root', str(root), 'mask', '--runtime',
                 'synthetic.service', 'conflict.service', 'nonexistent.service'],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
                env={'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C'})

            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual((runtime / 'synthetic.service').readlink(), Path('/dev/null'))
            self.assertEqual((runtime / 'nonexistent.service').readlink(), Path('/dev/null'))
            self.assertFalse(conflict.is_symlink())
            self.assertEqual(conflict.read_text(), unit)


if __name__ == '__main__':
    unittest.main()
