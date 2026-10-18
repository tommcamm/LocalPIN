# SPDX-License-Identifier: MIT OR Apache-2.0
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('flexible_console', Path(__file__).with_name('console.py'))
console = importlib.util.module_from_spec(spec)
spec.loader.exec_module(console)


class KeyboardTests(unittest.TestCase):
    def test_every_printable_ascii_character_has_one_physical_key_mapping(self):
        self.assertEqual(set(console.KEYS), {chr(value) for value in range(32, 127)})
        self.assertTrue(all(len(event) in (1, 2) and all(1 <= code <= 57 for code in event)
                            for event in console.KEYS.values()))

    def test_leading_trailing_spaces_and_case_are_preserved(self):
        events = console.keyboard_events(' Abc! ')
        self.assertEqual(events, [(57,), (42, 30), (48,), (46,), (42, 2), (57,)])
        self.assertEqual(len(console.keyboard_events('x' * 64)), 64)

    def test_controls_unicode_and_overlong_values_are_refused(self):
        for value in ['123', 'x' * 65, 'pass\nword', 'pass\0word', 'pass\tword', 'café passcode']:
            with self.assertRaises(RuntimeError):
                console.keyboard_events(value)


if __name__ == '__main__':
    unittest.main()
