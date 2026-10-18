#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Pure observation/classifier checks; no VM, PAM or authentication operations."""
import importlib.util
from pathlib import Path
import textwrap
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

    def test_maintenance_with_renderer_wraps_ansi_and_missing_trailing_space(self):
        question = textwrap.fill(observer.MAINTENANCE_CONFIRMATION, width=38)
        text = ('\x1b[1;36m' + question + '\x1b[0m\r\n'
                '  1. Yes\r\n  2. No / pause\r\nChoose a number (q to cancel):\r\n\r\n')
        self.assertEqual(observer.terminal_prompt(text)['id'],
                         'accounting-maintenance-confirmation')
        self.assertIsNone(observer.terminal_prompt(text.replace('No / pause', 'No, proceed'))['id'])

    def test_new_policy_review_choices_are_observed_without_approving_them(self):
        text = ('Review proposed policy changes\n'
                '  1. View policy diff\n  2. Continue to apply\n     confirmation\n'
                '  3. Pause setup\nChoose a number (q to cancel): ')
        result = observer.terminal_prompt(text)
        self.assertEqual(result['id'], 'policy-preview')
        self.assertEqual(result['answers'],
                         {'1': 'view', '2': 'continue', '3': 'pause', 'q': 'cancel'})

    def test_soft_wraps_do_not_skip_unknown_words_or_reuse_a_previous_question(self):
        known = (observer.MAINTENANCE_CONFIRMATION + '\n  1. Yes\n  2. No / pause\n'
                 'Choose a number (q to cancel): ')
        for current in (
                'Unknown new question?\n  1. Yes\n  2. No / pause\n'
                'Choose a number (q to cancel): ',
                'Do not ' + known,
                known.replace('services', 'unreviewed services'),
                known.replace('No / pause', 'Continue'),
                known + '1\nUnrecognized password request: '):
            self.assertIsNone(observer.terminal_prompt(known + '1\n' + current)['id'])

    def test_pending_restoration_choices_survive_ansi_and_both_kinds_of_wrap(self):
        text = ('\x1b[1;36mRecheck readiness or\nexit setup?\x1b[0m\n'
                '  1. Recheck readi\nness\n  2. Exit setup\n'
                'Choose a number (q to cancel):\n\n')
        result = observer.terminal_prompt(text)
        self.assertEqual(result['id'], 'restoration-readiness')
        self.assertEqual(result['answers'], {'1': 'recheck', '2': 'exit', 'q': 'cancel'})

    def test_restoration_question_and_options_cannot_be_reinterpreted_as_retry_approval(self):
        known = ('Recheck readiness or exit setup?\n'
                 '  1. Recheck readiness\n  2. Exit setup\n'
                 'Choose a number (q to cancel): ')
        for current in (
                known.replace('Recheck readiness or exit setup?', 'Approve maintenance retry?'),
                known.replace('1. Recheck readiness', '1. Retry maintenance'),
                known.replace('2. Exit setup', '2. Continue setup'),
                'Unknown new question?\n  1. Recheck readiness\n  2. Exit setup\n'
                'Choose a number (q to cancel): '):
            self.assertIsNone(observer.terminal_prompt(known + '1\n' + current)['id'])


if __name__ == '__main__':
    unittest.main()
