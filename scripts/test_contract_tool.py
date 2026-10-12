"""scripts/contract.py and the gate's generated mode: a row changes only through its contract.

Each case builds a small repository whose two invariant rows are generated from contracts and
pinned by an owner key, then changes something and runs the gate with the owner's signers.

    python3 scripts/test_contract_tool.py
"""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
DECLARATION = ('<!-- Every invariant row is generated from docs/contracts/<ID>.shadow.json; '
               'change a contract with scripts/contract.py, never this table by hand. -->')

RUST = '''\
#[cfg(test)]
mod tests {
    #[test]
    fn a_refusal_creates_no_cooldown() {
        assert_eq!(gate(), 0);
    }

    #[test]
    fn an_unknown_reply_keeps_the_obligation() {
        assert!(kept());
    }

    #[test]
    fn a_late_ack_retires_the_obligation() {
        assert!(retired());
    }
}
'''


def contract(rid, statement, witnesses):
    return {'profile': 'sokol.contract-shadow.v1', 'id': rid, 'statement': statement,
            'evidence_text': ', '.join(f'`{w}`' for w in witnesses), 'witnesses': witnesses,
            'annotations': {'status': 'UNSIGNED_EXPLANATORY_DRAFT', 'answer': 'draft'}}


def run(cwd, *cmd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)


class ContractTool(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        for sub in ('scripts', 'docs/contracts', '.github', 'src'):
            (self.dir / sub).mkdir(parents=True)
        for name in ('witness-pin.py', 'contract.py'):
            shutil.copy(HERE / name, self.dir / 'scripts' / name)
        (self.dir / 'src/gate.rs').write_text(RUST)
        self.contracts = {
            'T-1': contract('T-1', 'A refusal creates no cooldown.', ['a_refusal_creates_no_cooldown']),
            'T-2': contract('T-2', 'An unknown reply keeps the obligation.', ['an_unknown_reply_keeps_the_obligation']),
        }
        for rid, c in self.contracts.items():
            self.write_contract(c)
        (self.dir / 'docs/INVARIANTS.md').write_text(
            DECLARATION + '\n\n| ID | Invariant | Evidence |\n|---|---|---|\n'
            '| T-1 | x | `a_refusal_creates_no_cooldown` |\n'
            '| T-2 | x | `an_unknown_reply_keeps_the_obligation` |\n')
        self.key = str(self.dir.parent / f'{self.dir.name}-owner')
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', self.key], check=True)
        self.signers = self.dir.parent / f'{self.dir.name}-signers'
        self.signers.write_text(f'owner namespaces="sokol-witness" {Path(self.key + ".pub").read_text()}')
        shutil.copy(self.signers, self.dir / '.github/witness-signers')
        run(self.dir, 'git', 'init', '-q')
        run(self.dir, 'git', 'add', '-A')
        self.assertEqual(self.tool('regenerate').returncode, 0)
        self.assertEqual(run(self.dir, 'python3', 'scripts/witness-pin.py', 'sign', '--key', self.key).returncode, 0)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)
        for p in self.dir.parent.glob(f'{self.dir.name}-*'):
            p.unlink()

    def write_contract(self, c):
        (self.dir / f"docs/contracts/{c['id']}.shadow.json").write_text(json.dumps(c, indent=2) + '\n')

    def read_contract(self, rid):
        return json.loads((self.dir / f'docs/contracts/{rid}.shadow.json').read_text())

    def tool(self, *args):
        return run(self.dir, 'python3', 'scripts/contract.py', *args)

    def check(self):
        return run(self.dir, 'python3', 'scripts/witness-pin.py', 'check', '--signers', str(self.signers))

    def assert_refused(self, needle):
        r = self.check()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(needle, r.stdout + r.stderr)

    def invariants(self):
        return (self.dir / 'docs/INVARIANTS.md').read_text()

    def test_a_generated_and_pinned_tree_passes(self):
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn('| T-1 | A refusal creates no cooldown. |', self.invariants())

    def test_a_hand_edited_row_is_refused_and_regenerate_restores_it(self):
        p = self.dir / 'docs/INVARIANTS.md'
        p.write_text(p.read_text().replace('creates no cooldown.', 'usually creates no cooldown.'))
        self.assert_refused('T-1 is stale')
        self.assertEqual(self.tool('regenerate').returncode, 0)
        self.assertEqual(self.check().returncode, 0)

    def test_a_row_moved_into_a_comment_is_refused(self):
        p = self.dir / 'docs/INVARIANTS.md'
        text = p.read_text()
        real = next(line for line in text.splitlines() if line.startswith('| T-2 |'))
        p.write_text(text.replace(real + '\n', '') + '\n<!--\n' + real + '\n-->\n')
        self.assert_refused('A row is hidden in a comment or code block: T-2')

    def test_a_row_moved_into_a_code_block_is_refused(self):
        p = self.dir / 'docs/INVARIANTS.md'
        text = p.read_text()
        real = next(line for line in text.splitlines() if line.startswith('| T-2 |'))
        p.write_text(text.replace(real + '\n', '') + '\n```\n' + real + '\n```\n')
        self.assert_refused('A row is hidden in a comment or code block: T-2')

    def test_a_weaker_lookalike_in_front_of_a_hidden_row_is_refused(self):
        p = self.dir / 'docs/INVARIANTS.md'
        text = p.read_text()
        real = next(line for line in text.splitlines() if line.startswith('| T-2 |'))
        p.write_text(text.replace(real, '|T-2| Usually keeps the obligation. | `an_unknown_reply_keeps_the_obligation` |')
                     + '\n<!--\n' + real + '\n-->\n')
        self.assert_refused('A table line names T-2 but is not a row')

    def test_a_table_line_that_names_a_row_but_is_not_one_is_refused(self):
        p = self.dir / 'docs/INVARIANTS.md'
        p.write_text(p.read_text() + '| T\u20112 | Lookalike with a non-breaking hyphen. | `a_refusal_creates_no_cooldown` |\n')
        self.assert_refused('A table line names T-2 but is not a row')

    # Retiring a row: the contract stays as the tombstone (ADR-0024, retiring a row).

    def retire(self, rid, *args, key=True):
        r = self.tool('propose', rid, *args)
        self.assertEqual(r.returncode, 0, r.stdout)
        name = r.stdout.strip()
        return self.tool('accept', name, *(['--key', self.key] if key else []))

    def test_a_superseded_row_leaves_the_table_and_keeps_its_tombstone(self):
        r = self.retire('T-2', '--retire', 'SUPERSEDED', '--replacement', 'T-1',
                        '--loss', 'the obligation of an unknown reply is no longer stated on its own',
                        '--because', 'T-1 now covers it')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn('| T-2 |', self.invariants())
        c = self.read_contract('T-2')
        self.assertEqual((c['status'], c['retirement']['mode'], c['retirement']['replacement']),
                         ('retired', 'SUPERSEDED', 'T-1'))
        self.assertEqual(c['decisions'][-1]['because'], 'T-1 now covers it')
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout)
        listed = self.tool('list', '--retired').stdout
        self.assertIn('T-2 SUPERSEDED by T-1 | lost: the obligation', listed)

    def test_a_retirement_without_the_owner_signature_is_refused(self):
        self.retire('T-2', '--retire', 'WITHDRAWN', '--loss', 'x', '--because', 'y', key=False)
        self.assert_refused('T-2: pinned invariant row was removed')

    def test_a_retirement_names_what_is_lost(self):
        r = self.tool('propose', 'T-2', '--retire', 'ARCHIVED', '--because', 'old')
        self.assertEqual(r.returncode, 1)
        self.assertIn('non-empty loss', r.stdout)
        c = self.read_contract('T-2')
        c.update(status='retired', retirement={'mode': 'ARCHIVED', 'loss': [' '], 'replacement': None,
                                               'counterexamples': []})
        self.write_contract(c)
        self.assert_refused('T-2: a retirement names what is lost')

    def test_superseded_needs_an_active_replacement(self):
        r = self.tool('propose', 'T-2', '--retire', 'SUPERSEDED', '--loss', 'x', '--because', 'y')
        self.assertEqual(r.returncode, 1)
        r = self.tool('propose', 'T-2', '--retire', 'SUPERSEDED', '--replacement', 'T-404', '--loss', 'x',
                      '--because', 'y')
        self.assertEqual(r.returncode, 1)
        self.assertIn('--replacement T-404 is not an active row', r.stdout)
        self.assertEqual(self.retire('T-2', '--retire', 'SUPERSEDED', '--replacement', 'T-1', '--loss', 'x',
                                     '--because', 'y').returncode, 0)
        r = self.tool('propose', 'T-1', '--retire', 'WITHDRAWN', '--loss', 'x', '--because', 'y')
        self.assertEqual(r.returncode, 1)
        self.assertIn('T-1 replaces a retired row', r.stdout)

    def test_refuted_needs_existing_counterexamples_and_pins_them(self):
        r = self.tool('propose', 'T-2', '--retire', 'REFUTED', '--loss', 'x', '--because', 'y')
        self.assertEqual(r.returncode, 1)
        self.assertIn('REFUTED, and only REFUTED, names its counterexample tests', r.stdout)
        r = self.tool('propose', 'T-2', '--retire', 'REFUTED', '--counterexample', 'a_test_that_is_not_there',
                      '--loss', 'x', '--because', 'y')
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.retire('T-2', '--retire', 'REFUTED', '--counterexample',
                                     'a_late_ack_retires_the_obligation', '--loss', 'x',
                                     '--because', 'a late ACK shows the claim was wrong').returncode, 0)
        self.assertEqual(self.check().returncode, 0)
        src = self.dir / 'src/gate.rs'
        src.write_text(src.read_text().replace('assert!(retired());', 'let _ = retired();'))
        self.assert_refused('witness a_late_ack_retires_the_obligation changed')

    def test_a_retired_row_cannot_come_back_by_hand(self):
        self.retire('T-2', '--retire', 'WITHDRAWN', '--loss', 'x', '--because', 'y')
        p = self.dir / 'docs/INVARIANTS.md'
        p.write_text(p.read_text() + '| T-2 | x | `an_unknown_reply_keeps_the_obligation` |\n')
        self.assert_refused('Retired T-2 still has a row')
        r = self.tool('propose', 'T-2', '--statement', 'Back.', '--because', 'z')
        self.assertEqual(r.returncode, 1)
        self.assertIn('T-2 is retired; a new row needs a new ID', r.stdout)

    def test_a_hand_written_tombstone_is_checked_like_a_proposed_one(self):
        good = {'mode': 'SUPERSEDED', 'loss': ['x'], 'replacement': 'T-1', 'counterexamples': []}
        for bad, needle in (({'mode': 'FORGOTTEN'}, 'retirement mode must be one of'),
                            ({'replacement': 'T-404'}, 'superseded by T-404, which is not an active row'),
                            ({'replacement': 'T-2'}, 'superseded by T-2, which is not an active row'),
                            ({'extra': 1}, 'exactly mode, loss, replacement, counterexamples')):
            with self.subTest(bad):
                c = self.read_contract('T-2')
                c.update(status='retired', retirement={**good, **bad})
                self.write_contract(c)
                p = self.dir / 'docs/INVARIANTS.md'
                p.write_text(''.join(l for l in p.read_text().splitlines(keepends=True) if not l.startswith('| T-2 |')))
                self.assert_refused(needle)

    def test_an_unsigned_change_to_a_tombstone_is_refused(self):
        self.retire('T-2', '--retire', 'WITHDRAWN', '--loss', 'the real loss', '--because', 'y')
        c = self.read_contract('T-2')
        c['retirement']['loss'] = ['nothing much']
        self.write_contract(c)
        self.assert_refused('T-2: contract statement, witnesses or decision history changed')

    def test_a_row_without_a_contract_is_refused(self):
        p = self.dir / 'docs/INVARIANTS.md'
        p.write_text(p.read_text() + '| T-3 | Hand written. | `a_refusal_creates_no_cooldown` |\n')
        self.assert_refused('T-3 has no contract source')

    def test_a_per_row_marker_cannot_be_mixed_with_the_declaration(self):
        p = self.dir / 'docs/INVARIANTS.md'
        p.write_text(p.read_text() + '<!-- Generated T-2 from docs/contracts/T-2.shadow.json; '
                     'edit the contract, then regenerate. -->\n')
        self.assert_refused('one declaration and no per-row markers')

    def test_an_open_proposal_changes_nothing_and_is_noted(self):
        r = self.tool('propose', 'T-1', '--statement', 'A refusal never creates a cooldown.',
                      '--because', 'reworded after review')
        self.assertEqual(r.returncode, 0, r.stdout)
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn('open proposal T-1-', r.stdout)
        self.assertIn('| T-1 | A refusal creates no cooldown. |', self.invariants())

    def test_acceptance_without_the_owner_signature_is_refused(self):
        name = self.tool('propose', 'T-1', '--statement', 'Weaker.', '--because', 'pressure').stdout.strip()
        self.assertEqual(self.tool('accept', name).returncode, 0)
        self.assertIn('| T-1 | Weaker. |', self.invariants())
        self.assert_refused('T-1: invariant statement changed')

    def test_the_owner_accepts_and_the_history_records_why(self):
        name = self.tool('propose', 'T-2', '--witness', 'an_unknown_reply_keeps_the_obligation',
                         '--witness', 'a_late_ack_retires_the_obligation',
                         '--because', 'counterexample: a late ACK was never retired').stdout.strip()
        r = self.tool('accept', name, '--key', self.key)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.check().returncode, 0)
        c = self.read_contract('T-2')
        self.assertEqual(c['decisions'][-1]['because'], 'counterexample: a late ACK was never retired')
        self.assertEqual(c['witnesses'], ['a_late_ack_retires_the_obligation', 'an_unknown_reply_keeps_the_obligation'])
        self.assertFalse(list((self.dir / 'docs/contracts/proposals').glob('*.proposal.json')))

    def test_an_added_witness_keeps_the_existing_evidence_prose(self):
        c = self.read_contract('T-2')
        c['evidence_text'] = '`an_unknown_reply_keeps_the_obligation`, overflow test above.'
        self.write_contract(c)
        name = self.tool('propose', 'T-2', '--witness', 'an_unknown_reply_keeps_the_obligation',
                         '--witness', 'a_late_ack_retires_the_obligation', '--because', 'x').stdout.strip()
        proposal = json.loads((self.dir / name).read_text())
        self.assertEqual(proposal['evidence_text'], '`an_unknown_reply_keeps_the_obligation`, overflow test '
                         'above, `a_late_ack_retires_the_obligation`')

    def test_a_rewritten_decision_history_is_refused(self):
        name = self.tool('propose', 'T-1', '--statement', 'Stronger.', '--because', 'real reason').stdout.strip()
        self.assertEqual(self.tool('accept', name, '--key', self.key).returncode, 0)
        c = self.read_contract('T-1')
        c['decisions'][-1]['because'] = 'a nicer story'
        self.write_contract(c)
        self.assert_refused('T-1: contract statement, witnesses or decision history changed')

    def test_an_unsigned_explanation_may_change(self):
        c = self.read_contract('T-1')
        c['annotations']['answer'] = 'a better draft'
        self.write_contract(c)
        self.assertEqual(self.check().returncode, 0)

    def test_a_stale_proposal_is_refused(self):
        first = self.tool('propose', 'T-1', '--statement', 'First.', '--because', 'one').stdout.strip()
        second = self.tool('propose', 'T-1', '--statement', 'Second.', '--because', 'two').stdout.strip()
        self.assertEqual(self.tool('accept', second, '--key', self.key).returncode, 0)
        r = self.tool('accept', first)
        self.assertEqual(r.returncode, 1)
        self.assertIn('stale proposal', r.stdout)

    def test_a_proposal_needs_existing_witnesses_and_a_reason(self):
        r = self.tool('propose', 'T-1', '--witness', 'a_witness_that_does_not_exist', '--because', 'x')
        self.assertEqual(r.returncode, 1)
        self.assertIn('witnesses must be existing tests', r.stdout)
        r = self.tool('propose', 'T-1', '--statement', 'S.', '--because', '  ')
        self.assertEqual(r.returncode, 1)

    def test_a_new_invariant_after_a_missing_row_is_refused_when_proposed(self):
        r = self.tool('propose', 'T-8', '--statement', 'S.', '--witness', 'a_late_ack_retires_the_obligation',
                      '--after', 'T-404', '--because', 'x')
        self.assertEqual(r.returncode, 1)
        self.assertIn('--after T-404 is not a row', r.stdout)
        self.assertFalse(list((self.dir / 'docs/contracts/proposals').glob('*.proposal.json')))

    def test_a_new_invariant_is_placed_after_an_existing_row(self):
        name = self.tool('propose', 'T-9', '--statement', 'A late ACK retires the obligation.',
                         '--witness', 'a_late_ack_retires_the_obligation', '--after', 'T-1',
                         '--because', 'new boundary').stdout.strip()
        self.assertEqual(self.tool('accept', name).returncode, 0)
        lines = self.invariants().splitlines()
        self.assertTrue(lines[lines.index(next(x for x in lines if x.startswith('| T-1 |'))) + 1].startswith('| T-9 |'))
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn('T-9: contract is not pinned yet', r.stdout)


if __name__ == '__main__':
    unittest.main()
