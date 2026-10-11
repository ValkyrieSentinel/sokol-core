"""scripts/witness-pin.py: a pinned witness cannot be weakened without the owner's signature.

check-claims.sh accepts a witness whose body no longer asserts anything, as long as the name
is still in the test list. Each case below builds a small repository, pins it with an owner key,
makes one change and runs the check with the owner's signers file, as CI does from the base.

    python3 scripts/test_witness_pin.py
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent

INVARIANTS = '''\
| ID | Invariant and reason | Executable evidence |
|---|---|---|
| T-1 | A refusal creates no cooldown. | `a_refusal_creates_no_cooldown` |
| T-2 | Recovery keeps the cursor. | `RecoveryTests.test_recovery_keeps_the_cursor` |
'''

RUST = '''\
#[cfg(test)]
mod tests {
    #[test]
    fn a_refusal_creates_no_cooldown() {
        // The URL keeps its slashes: "http://x" is a string, not a comment.
        let url = "http://x";
        assert_eq!(gate(url), 0);
    }
}
'''

PY = '''\
import unittest


class RecoveryTests(unittest.TestCase):
    def test_recovery_keeps_the_cursor(self):
        self.assertEqual(cursor(), 7)
'''


def run(cwd, *cmd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)


class WitnessPin(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "scripts").mkdir()
        (self.dir / "docs").mkdir()
        (self.dir / ".github").mkdir()
        (self.dir / "src").mkdir()
        shutil.copy(HERE / "witness-pin.py", self.dir / "scripts/witness-pin.py")
        (self.dir / "docs/INVARIANTS.md").write_text(INVARIANTS)
        (self.dir / "src/gate.rs").write_text(RUST)
        (self.dir / "scripts/test_recovery.py").write_text(PY)
        self.key = self.keypair("owner")
        self.signers = self.dir.parent / f"{self.dir.name}-signers"
        self.signers.write_text(f'owner namespaces="sokol-witness" {Path(self.key + ".pub").read_text()}')
        shutil.copy(self.signers, self.dir / ".github/witness-signers")
        run(self.dir, "git", "init", "-q")
        run(self.dir, "git", "add", "-A")
        self.assertEqual(self.pin(self.key).returncode, 0)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)
        for p in self.dir.parent.glob(f"{self.dir.name}-*"):
            p.unlink()

    def keypair(self, name):
        path = str(self.dir.parent / f"{self.dir.name}-{name}")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path], check=True)
        return path

    def pin(self, key):
        return run(self.dir, "python3", "scripts/witness-pin.py", "sign", "--key", key)

    def check(self):
        return run(self.dir, "python3", "scripts/witness-pin.py", "check", "--signers", str(self.signers))

    def edit(self, rel, old, new):
        p = self.dir / rel
        text = p.read_text()
        self.assertIn(old, text)
        p.write_text(text.replace(old, new))

    def assert_refused(self, needle):
        r = self.check()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(needle, r.stdout)

    def test_a_pinned_tree_passes(self):
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("2 invariant rows and 2 witnesses", r.stdout)

    def test_comments_and_line_breaks_do_not_count(self):
        self.edit("src/gate.rs", "        // The URL", "        // A reworded note.\n        // The URL")
        self.edit("src/gate.rs", "assert_eq!(gate(url), 0);", "assert_eq!(\n            gate(url),\n            0\n        );")
        self.assertEqual(self.check().returncode, 0)

    def test_a_weakened_rust_witness_is_refused(self):
        self.edit("src/gate.rs", "assert_eq!(gate(url), 0);", "let _ = gate(url);")
        self.assert_refused("witness a_refusal_creates_no_cooldown changed")

    def test_a_changed_string_is_not_taken_for_a_comment(self):
        self.edit("src/gate.rs", 'let url = "http://x";', 'let url = "http://y";')
        self.assert_refused("witness a_refusal_creates_no_cooldown changed")

    def test_a_weakened_python_witness_is_refused(self):
        self.edit("scripts/test_recovery.py", "self.assertEqual(cursor(), 7)", "cursor()")
        self.assert_refused("witness RecoveryTests.test_recovery_keeps_the_cursor changed")

    def test_rust_literal_whitespace_is_not_formatting(self):
        self.edit("src/gate.rs", 'let url = "http://x";', 'let url = "http:// x";')
        self.assert_refused("witness a_refusal_creates_no_cooldown changed")

    def test_python_literal_whitespace_is_not_formatting(self):
        self.edit("scripts/test_recovery.py", "self.assertEqual(cursor(), 7)", 'self.assertEqual(cursor("a b"), 7)')
        self.assertEqual(self.pin(self.key).returncode, 0)
        self.edit("scripts/test_recovery.py", 'cursor("a b")', 'cursor("a  b")')
        self.assert_refused("witness RecoveryTests.test_recovery_keeps_the_cursor changed")

    def test_python_fstring_whitespace_is_not_formatting(self):
        self.edit("scripts/test_recovery.py", "self.assertEqual(cursor(), 7)", 'self.assertEqual(cursor(f"a {7} b"), 7)')
        self.assertEqual(self.pin(self.key).returncode, 0)
        self.edit("scripts/test_recovery.py", 'f"a {7} b"', 'f"a  {7} b"')
        self.assert_refused("witness RecoveryTests.test_recovery_keeps_the_cursor changed")

    def test_literal_braces_cannot_hide_following_assertions(self):
        self.edit("src/gate.rs", 'let url = "http://x";', 'let url = "}";')
        self.assertEqual(self.pin(self.key).returncode, 0)
        self.edit("src/gate.rs", "assert_eq!(gate(url), 0);", "let _ = gate(url);")
        self.assert_refused("witness a_refusal_creates_no_cooldown changed")

    def test_raw_literal_whitespace_is_not_formatting(self):
        self.edit("src/gate.rs", 'let url = "http://x";', 'let url = r#"a b"#;')
        self.assertEqual(self.pin(self.key).returncode, 0)
        self.edit("src/gate.rs", 'r#"a b"#', 'r#"a  b"#')
        self.assert_refused("witness a_refusal_creates_no_cooldown changed")

    def test_python_comments_and_indentation_do_not_count(self):
        self.edit("scripts/test_recovery.py", "        self.assertEqual(cursor(), 7)",
                  "        # The cursor survives a restart.\n        self.assertEqual(cursor(), 7)  # seven")
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_a_dropped_witness_is_refused(self):
        self.edit("docs/INVARIANTS.md", "`a_refusal_creates_no_cooldown`", "code review")
        self.assert_refused("T-1: witness a_refusal_creates_no_cooldown was dropped")

    def test_a_reworded_invariant_is_refused(self):
        self.edit("docs/INVARIANTS.md", "creates no cooldown.", "usually creates no cooldown.")
        self.assert_refused("T-1: invariant statement changed")

    def test_a_removed_row_is_refused(self):
        self.edit("docs/INVARIANTS.md", "| T-2 | Recovery keeps the cursor. | `RecoveryTests.test_recovery_keeps_the_cursor` |\n", "")
        self.assert_refused("T-2: pinned invariant row was removed")

    def test_a_renamed_witness_is_refused(self):
        self.edit("src/gate.rs", "fn a_refusal_creates_no_cooldown", "fn a_refusal_creates_no_cooldown_any_more")
        run(self.dir, "git", "add", "-A")
        self.assert_refused("witness a_refusal_creates_no_cooldown is cited but no test function has that name")

    def test_a_new_row_is_noted_not_refused(self):
        p = self.dir / "docs/INVARIANTS.md"
        p.write_text(p.read_text() + "| T-3 | New. | `a_refusal_creates_no_cooldown` |\n")
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("T-3: new invariant row, not pinned yet", r.stdout)

    def test_a_new_row_is_refused_on_main_where_every_pin_is_required(self):
        p = self.dir / "docs/INVARIANTS.md"
        p.write_text(p.read_text() + "| T-3 | New. | `a_refusal_creates_no_cooldown` |\n")
        r = run(self.dir, "python3", "scripts/witness-pin.py", "check", "--signers", str(self.signers), "--every-pin")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("FAIL T-3: new invariant row, not pinned yet", r.stdout)
        self.assertEqual(self.pin(self.key).returncode, 0)
        r = run(self.dir, "python3", "scripts/witness-pin.py", "check", "--signers", str(self.signers), "--every-pin")
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_re_signing_with_another_key_is_refused(self):
        self.edit("src/gate.rs", "assert_eq!(gate(url), 0);", "let _ = gate(url);")
        intruder = self.keypair("intruder")
        (self.dir / ".github/witness-signers").write_text(
            f'owner namespaces="sokol-witness" {Path(intruder + ".pub").read_text()}')
        self.assertEqual(self.pin(intruder).returncode, 0)
        self.assert_refused("is not signed by a key in")

    def test_the_owner_can_accept_a_change(self):
        self.edit("src/gate.rs", "assert_eq!(gate(url), 0);", "assert_eq!(gate(url), 1);")
        self.assertEqual(self.check().returncode, 1)
        self.assertEqual(self.pin(self.key).returncode, 0)
        self.assertEqual(self.check().returncode, 0)


if __name__ == "__main__":
    unittest.main()
