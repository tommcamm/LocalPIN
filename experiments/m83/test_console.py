#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('m83_console', Path(__file__).with_name('console_recovery.py'))
console = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(console)


class OriginTests(unittest.TestCase):
    def test_free_local_vt_is_bound_to_dedicated_sudo_user(self):
        self.assertTrue(console.valid_origin('/dev/tty4', 'tty4', '21061', 'lp61test'))
        for values in [('/dev/pts/4', 'pts/4', '21061', 'lp61test'),
                       ('/dev/tty4', 'tty3', '21061', 'lp61test'),
                       ('/dev/tty4', 'tty4', '0', 'root'),
                       ('/dev/tty1', 'tty1', '21061', 'lp61test')]:
            self.assertFalse(console.valid_origin(*values))


if __name__ == '__main__':
    unittest.main()
