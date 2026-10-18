# SPDX-License-Identifier: MIT OR Apache-2.0
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('flexible_host', Path(__file__).with_name('host.py'))
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


def result():
    return {'phase': 'flexible-installed-case', 'passed': True, 'case': 'software8',
            'candidate': 'test.evr', 'kind': 'numeric-pin', 'backend': 'software', 'length': 8,
            'policy_version': 1, 'credential_version': 2, 'mutation': 'change',
            'credential_committed': True, 'postcommit_availability': 'available',
            'verification_pending': False, 'observation_only': False,
            'production_broker_verified': True, 'separate_native_failure_history_preserved': True,
            'fresh_bounded_trial_open': True, 'selinux': 'Enforcing',
            'installed_cli_pty': {'operation': 'change', 'kind': 'numeric-pin', 'length': 8,
                'actual_installed_cli': True, 'real_controlling_terminal': True,
                'preparation_before_password': True, 'masked_new_input_observed': True,
                'secret_echo_absent': True, 'private_prompt_count': 5, 'exit_success': True}}


class PublicResults(unittest.TestCase):
    def test_only_expected_public_success_facts_are_accepted(self):
        value = result()
        self.assertEqual(host.public_result(value, 'software8', 'test.evr'), value)

    def test_cooldown_preserves_commit_without_claiming_verification(self):
        value = result()
        value.update(passed=False, postcommit_availability='cooldown', verification_pending=True,
                     production_broker_verified=False, fresh_bounded_trial_open=False)
        self.assertEqual(host.public_result(value, 'software8', 'test.evr'), value)
        value['passed'] = True
        with self.assertRaises(RuntimeError):
            host.public_result(value, 'software8', 'test.evr')

    def test_unknown_secret_fields_and_untrusted_success_values_are_refused(self):
        for location, field, value in [
            ('root', 'secret', 'synthetic'), ('terminal', 'transcript', 'synthetic'),
            ('root', 'passed', 'synthetic'), ('terminal', 'secret_echo_absent', 1),
            ('root', 'candidate', 'another.evr'), ('root', 'length', 10),
        ]:
            item = copy.deepcopy(result())
            target = item if location == 'root' else item['installed_cli_pty']
            target[field] = value
            with self.assertRaises(RuntimeError):
                host.public_result(item, 'software8', 'test.evr')


if __name__ == '__main__':
    unittest.main()
