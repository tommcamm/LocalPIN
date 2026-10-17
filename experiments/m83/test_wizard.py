import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

SPEC = importlib.util.spec_from_file_location('m83_wizard', Path(__file__).with_name('wizard.py'))
wizard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wizard)


class StartGuards(unittest.TestCase):
    def invoke(self, status):
        invoked = []
        def require(value, message):
            if not value:
                raise RuntimeError(message)
        module = SimpleNamespace(m=SimpleNamespace(bus=lambda operation: status), require=require)
        return invoked, lambda: wizard.unlocked_start(module, lambda args: invoked.append(args), 'case')

    def test_locked_desktop_cannot_start_keyboard_fixture(self):
        invoked, run = self.invoke(b'b true')
        with self.assertRaises(RuntimeError):
            run()
        self.assertEqual(invoked, [])

    def test_unlocked_desktop_allows_the_fixed_start(self):
        invoked, run = self.invoke(b'b false')
        run()
        self.assertEqual(invoked, ['case'])
