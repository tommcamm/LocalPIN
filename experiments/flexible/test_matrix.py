# SPDX-License-Identifier: MIT OR Apache-2.0
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('flexible_matrix', Path(__file__).with_name('matrix.py'))
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


class FixtureCandidates(unittest.TestCase):
    def test_cases_avoid_each_advisory_pattern_including_wrapping_sequences(self):
        for value in ['0000', '0123', '0987', '78901234', '12121212', 'abcabcabc',
                      'aB4$aB4$', 'PASSWORD1', 'qwertyuiop', 'localpin']:
            self.assertTrue(matrix.predictable(value))
        for value in ['0739', '  synthetic words  ', 'aB4$aB4%']:
            self.assertFalse(matrix.predictable(value))

    def test_numeric_generation_rejects_a_sequence_before_using_the_case(self):
        with mock.patch.object(matrix.secrets, 'choice', side_effect=list('123739')):
            self.assertEqual(matrix.numeric(4), '0739')


if __name__ == '__main__':
    unittest.main()
