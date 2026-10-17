# SPDX-License-Identifier: MIT OR Apache-2.0
"""Pure transcript-classifier tests; no VM, account, sudo, PAM or TPM use."""
import unittest

import wizard


class PromptTests(unittest.TestCase):
    def test_every_confirmation_requires_current_unanswered_prompt(self):
        for heading, identifier in wizard.CONFIRMATIONS.items():
            transcript = (heading + '\r\n  1. Yes\r\n  2. No / pause\r\n' + wizard.CHOICE).encode()
            result = wizard.prompt(transcript)
            self.assertEqual(result['id'], identifier)
            self.assertEqual(result['answers'], {'1': 'yes', '2': 'pause', 'q': 'cancel'})
            self.assertIsNone(wizard.prompt(transcript + b'1\r\n')['id'])

    def test_most_recent_heading_and_private_prompt_win(self):
        transcript = ('Check system readiness with administrator access?\n' + wizard.CHOICE
                      + '1\nPIN protection\n'
                      + '  1. TPM 2.0 — hardware bound; requires a separately validated TPM deployment\n'
                      + '  2. Software — no TPM binding; copied verifier data can be guessed offline\n'
                      + wizard.CHOICE).encode()
        self.assertEqual(wizard.prompt(transcript)['id'], 'backend')
        self.assertEqual(wizard.prompt(transcript + b'1\r\nNew six-digit PIN: ')['id'], 'new-pin')
        self.assertEqual(wizard.prompt(transcript + b'1\r\nNew six-digit PIN: ')['secret_selector'], 'pin')

    def test_all_private_prompts_return_only_fixed_identifiers(self):
        for suffix, (identifier, selector) in wizard.PRIVATE_PROMPTS.items():
            result = wizard.prompt(('unrelated earlier text\r\n' + suffix).encode())
            self.assertEqual(result['id'], identifier)
            self.assertEqual(result['secret_selector'], selector)
            self.assertNotIn(suffix, str(result))

    def test_unknown_prompt_and_menu(self):
        self.assertIsNone(wizard.prompt(b'Unexpected privileged question: ')['id'])
        menu = ('What would you like to do?\n  1. Set up or resume setup\n  2. Check status\n'
                '  3. Diagnose a problem\n  4. Change my PIN\n  5. Switch PIN protection\n'
                '  6. Disable my PIN\n  7. Exit\n')
        self.assertEqual(wizard.prompt((menu + wizard.CHOICE).encode())['id'], 'menu')
        previous = ('Check system readiness with administrator access?\n  1. Yes\n'
                    '  2. No / pause\n' + wizard.CHOICE + '1\n')
        unknown = 'A changed question?\n  1. Yes\n  2. No / pause\n' + wizard.CHOICE
        self.assertIsNone(wizard.prompt((previous + unknown).encode())['id'])

    def test_ansi_and_script_exit(self):
        transcript = b'\x1b[1;36mLocalPIN\x1b[0m\r\nCheck system readiness with administrator access?\r\n'
        self.assertEqual(wizard.prompt(transcript + b'  1. Yes\r\n  2. No / pause\r\n' + wizard.CHOICE.encode())['id'], 'readiness')
        self.assertIsNone(wizard.exit_code(b'Script started on a date [COMMAND="/usr/bin/localpin setup"]'))
        self.assertEqual(wizard.exit_code(b'\nScript done on a date [COMMAND_EXIT_CODE="1"]\n'), 1)


if __name__ == '__main__':
    unittest.main()
