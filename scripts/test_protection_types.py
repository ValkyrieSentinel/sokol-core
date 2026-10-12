#!/usr/bin/env python3
"""Check actual production type guards with rustc; compile failures require named diagnostics.

The positive controls compile the same source with an explicit role decision. This
checks exhaustiveness and production string admission, not correctness of a new role.
"""
import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'orchestrator/src/protection.rs'


class ProtectionTypes(unittest.TestCase):
    def compile(self, source, harness=None):
        with tempfile.TemporaryDirectory(prefix='sokol-protection-type-') as directory:
            path = pathlib.Path(directory)
            (path / 'protection.rs').write_text(source)
            if harness is None:
                main = path / 'protection.rs'
            else:
                main = path / 'main.rs'
                main.write_text('#[allow(dead_code)]\nmod protection;\n' + harness)
            result = subprocess.run(['rustc','--edition=2021','--crate-type=lib','--emit=metadata',
                '--error-format=json',str(main),'-o',str(path/'proof.rmeta')],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertLessEqual(len(result.stdout) + len(result.stderr), 2 * 1024 * 1024)
            diagnostics = [json.loads(line) for line in result.stderr.splitlines() if line.startswith(b'{')]
            return result.returncode, diagnostics

    def test_a_new_reason_requires_a_source_role_decision(self):
        source = SOURCE.read_text()
        code, diagnostics = self.compile(source)
        self.assertEqual(code, 0, diagnostics)
        mutant = source.replace('pub enum ProtectionReason {', 'pub enum ProtectionReason {\n    FutureProtection,', 1)
        marker = "pub const fn description(self) -> &'static str {\n        match self {"
        self.assertEqual(mutant.count(marker), 1)
        mutant = mutant.replace(marker, marker + '\n            Self::FutureProtection => "future protection",', 1)
        code, diagnostics = self.compile(mutant)
        self.assertNotEqual(code, 0)
        start = mutant[:mutant.index('pub const fn source_role')].count('\n') + 1
        end = mutant[:mutant.index('pub const fn description')].count('\n') + 1
        matching = [d for d in diagnostics if (d.get('code') or {}).get('code') == 'E0004'
                    and 'FutureProtection' in d['message']
                    and any(s['is_primary'] and start <= s['line_start'] < end for s in d['spans'])]
        self.assertEqual(len(matching), 1, diagnostics)
        for role in ('ProtectedOther', 'LocalSide'):
            fixed = mutant.replace('match self {', f'match self {{\n            Self::FutureProtection => SourceRole::{role},', 1)
            code, diagnostics = self.compile(fixed)
            self.assertEqual(code, 0, diagnostics)
        self.assertEqual(SOURCE.read_text(), source, 'source changed during type check')

    def test_production_diagnostic_strings_cannot_construct_protection(self):
        source = SOURCE.read_text()
        code, diagnostics = self.compile(source, 'pub fn probe() { let _: protection::ProtectionReason = protection::ProtectionReason::LocalAddress.into(); }')
        self.assertEqual(code, 0, diagnostics)
        code, diagnostics = self.compile(source, 'pub fn probe() { let _: protection::ProtectionReason = "address of this node".into(); }')
        self.assertNotEqual(code, 0)
        self.assertTrue(any((d.get('code') or {}).get('code') == 'E0277' and 'From<&str>' in d['message'] for d in diagnostics), diagnostics)
        self.assertEqual(SOURCE.read_text(), source, 'source changed during type check')


if __name__ == '__main__': unittest.main()
