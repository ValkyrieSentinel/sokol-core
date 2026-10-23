#!/usr/bin/env python3
"""The gate's ast_dump prints a class decorator as Python 3.9-3.12 do, on any interpreter.
From 3.13 ast.dump leaves out empty lists, so `@unittest.skipUnless(...)` hashed differently on
a newer Python and the witnesses of such a class failed against pins made on 3.9/3.12."""
import ast
import importlib.util
import sys
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("witness_pin", Path(__file__).resolve().parent / "witness-pin.py")
WP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WP)

SAMPLES = [
    "unittest.skipUnless(os.environ.get('X'), 'set X')",
    "unittest.skip('reason')",
    "dataclass(frozen=True)",
    "staticmethod",
    "f(*a, **k)",
]


class AstDumpStable(unittest.TestCase):
    def test_empty_lists_are_printed_on_every_version(self):
        node = ast.parse(SAMPLES[0], mode="eval").body
        self.assertIn("keywords=[]", WP.ast_dump(node))

    @unittest.skipIf(sys.version_info >= (3, 13), "ast.dump changed its format in 3.13")
    def test_the_format_is_that_of_ast_dump_before_3_13(self):
        for code in SAMPLES:
            node = ast.parse(code, mode="eval").body
            self.assertEqual(WP.ast_dump(node), ast.dump(node), code)


if __name__ == "__main__":
    unittest.main()
