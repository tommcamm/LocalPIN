#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Run the reviewed M8.2 actual-Konsole observer with the M8.3 fixed prompt.

Stage this file, observe.py and the unchanged M8.2 wizard as wizard_base.py
beside the guarded M8 guest helpers. No input or product mutation is added.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from observe import base_module

def unlocked_start(module, start, args):
    module.require(module.m.bus('GetActive') == b'b false',
                   'unlocked actual KDE session required before starting keyboard fixture')
    return start(args)


if __name__ == '__main__':
    module = base_module()
    # The installed M8.2 fixture's guard resolves the same sibling run/guard.
    original_start = module.start
    module.start = lambda args: unlocked_start(module, original_start, args)
    module.main()
