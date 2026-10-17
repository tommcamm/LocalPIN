#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Pure observation/classifier checks; no VM, PAM or authentication operations."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('m83_observer', Path(__file__).with_name('observe.py'))
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)


class ObservationTests(unittest.TestCase):
    def test_soft_wrapped_known_confirmation_is_reassembled(self):
        heading = next(value for value, identifier in observer.base_module().CONFIRMATIONS.items()
                       if identifier == 'prior-console-recovery')
        text = (heading.replace('final/current', 'final/cur\nrent')
                + '\n  1. Yes\n  2. No / pause\nChoose a number (q to cancel): ')
        self.assertEqual(observer.terminal_prompt(text)['id'], 'prior-console-recovery')

    def test_only_explicit_installed_setup_processes_match(self):
        self.assertTrue(observer.is_setup_process(b'/usr/bin/localpin\0setup\0'))
        for value in (b'localpin setup\0', b'/tmp/localpin\0setup\0',
                      b'/usr/bin/localpin\0status\0', b'/usr/bin/localpin\0setup\0extra\0'):
            self.assertFalse(observer.is_setup_process(value))

    def test_maintenance_confirmation_is_exact_and_sanitized(self):
        text = (observer.MAINTENANCE_CONFIRMATION + '\n  1. Yes\n  2. No / pause\n'
                'Choose a number (q to cancel): ')
        result = observer.terminal_prompt(text + '\n\n')
        self.assertEqual(result['id'], 'accounting-maintenance-confirmation')
        self.assertEqual(result['answers'], {'1': 'yes', '2': 'pause', 'q': 'cancel'})
        self.assertNotIn('text', result)
        self.assertIsNone(observer.terminal_prompt(text.replace('No / pause', 'Continue'))['id'])

    def test_existing_private_prompts_are_classified_without_values(self):
        result = observer.terminal_prompt('Existing account password: \n\n')
        self.assertEqual(result['id'], 'account-password')
        self.assertEqual(result['secret_selector'], 'password')
        self.assertNotIn('password_value', result)

    def test_an_old_confirmation_cannot_label_unrecognized_next_prompt(self):
        text = (observer.MAINTENANCE_CONFIRMATION + '\n  1. Yes\n  2. No / pause\n'
                'Choose a number (q to cancel): 1\nUnknown new operation?\n'
                '  1. Yes\n  2. No / pause\nChoose a number (q to cancel): ')
        self.assertIsNone(observer.terminal_prompt(text)['id'])


if __name__ == '__main__':
    unittest.main()
