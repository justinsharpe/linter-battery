#!/usr/bin/env python3
"""Standalone runner for linter-battery's self-test suite.

Runs with no linters installed by design: the tests exercise the skip path,
the normalized JSON schema, and argument parsing without invoking any linter.
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import linter_battery  # noqa: E402


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(linter_battery.SelfTest)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
