"""scripts/witness-pin.py: a pinned witness cannot be weakened without the owner's signature.

check-claims.sh accepts a witness whose body no longer asserts anything, as long as the name
is still in the test list. Each case below builds a small repository, pins it with an owner key,
makes one change and runs the check with the owner's signers file, as CI does from the base.

    python3 scripts/test_witness_pin.py
"""
import os
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
| H-1 | A helper keeps its verdict. | `a_helper_keeps_its_verdict` |
| H-2 | Generated cases keep their count. | `generated_cases_keep_their_count` |
| H-3 | A restart keeps the start. | `RecoveryTests.test_restart_keeps_the_start` |
'''

HELPERS = '''\
pub fn production(x: u32) -> u32 {
    x
}

#[cfg(test)]
mod tests {
    fn unrelated() -> u32 {
        1
    }

    const LIMIT: u32 = 7;

    fn verdict() -> u32 {
        super::production(LIMIT)
    }

    use verdict as judged;

    trait Seven {
        fn seven(&self) -> u32;
    }

    struct Probe;

    impl self::Seven for Probe {
        fn seven(&self) -> u32 {
            7
        }
    }

    #[test]
    fn a_helper_keeps_its_verdict() {
        assert_eq!(judged(), Probe.seven());
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]
        #[test]
        fn an_unpinned_generated_case(x in 0u32..9) {
            assert!(x < 9);
        }

        #[test]
        fn generated_cases_keep_their_count(x in 0u32..9) {
            assert!(x < 9);
        }
    }
}
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

START = 7


def cursor(*_):
    return 7


def expected():
    return START


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.base = 0

    def test_recovery_keeps_the_cursor(self):
        self.assertEqual(cursor(), 7)

    def test_restart_keeps_the_start(self):
        self.assertEqual(expected() + self.base, 7)
'''

CARGO = '''\
[package]
name = "fixture"
version = "0.1.0"

[lib]
path = "src/lib.rs"
'''

LIB = '''\
mod gate;
mod helpers;
'''

LOG = '''\
running 4 tests
test tests::a_refusal_creates_no_cooldown ... ok
test helpers::tests::a_helper_keeps_its_verdict ... ok
test helpers::tests::generated_cases_keep_their_count ... ok
test other::tests::an_unpinned_test ... ignored
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
        (self.dir / "src/helpers.rs").write_text(HELPERS)
        (self.dir / "src/lib.rs").write_text(LIB)
        (self.dir / "Cargo.toml").write_text(CARGO)
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
        self.assertIn("5 invariant rows and 5 witnesses", r.stdout)

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


    # A witness is its closure: attributes, and the test items it reaches (ADR-0023 amendment).

    def test_an_ignored_rust_witness_is_refused(self):
        self.edit("src/helpers.rs", "    #[test]\n    fn a_helper_keeps_its_verdict", "    #[test]\n    #[ignore]\n    fn a_helper_keeps_its_verdict")
        self.assert_refused("witness a_helper_keeps_its_verdict changed: its attributes or a test item")

    def test_a_weakened_rust_helper_is_refused(self):
        self.edit("src/helpers.rs", "        super::production(LIMIT)", "        7")
        self.assert_refused("witness a_helper_keeps_its_verdict changed: its attributes or a test item")

    def test_a_changed_test_constant_is_refused(self):
        self.edit("src/helpers.rs", "const LIMIT: u32 = 7;", "const LIMIT: u32 = 8;")
        self.assert_refused("witness a_helper_keeps_its_verdict changed: its attributes or a test item")

    def test_proptest_case_count_is_pinned(self):
        self.edit("src/helpers.rs", "with_cases(64)", "with_cases(1)")
        self.assert_refused("witness generated_cases_keep_their_count changed: its attributes or a test item")

    def test_a_helper_reached_through_an_alias_is_pinned(self):
        self.edit("src/helpers.rs", "        super::production(LIMIT)", "        7")
        self.assert_refused("witness a_helper_keeps_its_verdict changed: its attributes or a test item")

    def test_an_inner_attribute_of_the_enclosing_module_is_pinned(self):
        self.edit("src/helpers.rs", "mod tests {\n    fn unrelated", "mod tests {\n    #![cfg(any())]\n    fn unrelated")
        self.assert_refused("witness a_helper_keeps_its_verdict changed: its attributes or a test item")

    def test_the_module_declaration_that_compiles_a_witness_is_pinned(self):
        self.edit("src/lib.rs", "mod helpers;", "#[cfg(not(test))]\nmod helpers;")
        self.assert_refused("witness a_helper_keeps_its_verdict changed: its attributes or a test item")

    def test_a_custom_test_harness_or_runner_needs_the_owner(self):
        p = self.dir / "Cargo.toml"
        p.write_text(p.read_text() + '\n[[test]]\nname = "report"\nharness = false\n')
        self.assert_refused("Cargo.toml: build configuration changed")
        p.write_text(CARGO)
        (self.dir / ".cargo").mkdir()
        (self.dir / ".cargo/config.toml").write_text('[target.x86_64-unknown-linux-gnu]\nrunner = "./fake"\n')
        run(self.dir, "git", "add", "-A")
        self.assert_refused(".cargo/config.toml: build configuration changed")

    def test_dependencies_and_profiles_are_not_build_pins(self):
        p = self.dir / "Cargo.toml"
        p.write_text(p.read_text() + '\n[dependencies]\nserde = "1"\n\n[profile.release]\nopt-level = 2\n')
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_a_python_witness_replaced_at_import_is_refused(self):
        p = self.dir / "scripts/test_recovery.py"
        p.write_text(p.read_text() + "\n\nsetattr(RecoveryTests, 'test_recovery_keeps_the_cursor', lambda self: None)\n")
        self.assert_refused("witness RecoveryTests.test_recovery_keeps_the_cursor changed: its attributes or a test item")

    def test_a_python_witness_shadowed_in_its_class_body_is_refused(self):
        p = self.dir / "scripts/test_recovery.py"
        p.write_text(p.read_text() + "\n    test_recovery_keeps_the_cursor = lambda self: None\n")
        self.assert_refused("witness RecoveryTests.test_recovery_keeps_the_cursor changed: its attributes or a test item")

    def test_another_python_test_body_does_not_count(self):
        p = self.dir / "scripts/test_recovery.py"
        self.edit("scripts/test_recovery.py", "    def test_recovery_keeps_the_cursor(self):",
                  "    def test_unpinned(self):\n        self.assertTrue(True)\n\n    def test_recovery_keeps_the_cursor(self):")
        self.assertEqual(self.pin(self.key).returncode, 0)
        self.edit("scripts/test_recovery.py", "        self.assertTrue(True)", "        self.assertTrue(1)")
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_a_helper_types_impl_is_pinned_with_the_type(self):
        # 2026-10-14: since #22 an impl was named by its trait or module path, so a witness
        # using Probe did not reach `impl self::Seven for Probe` and its behaviour was unpinned.
        self.edit("src/helpers.rs", "        fn seven(&self) -> u32 {\n            7", "        fn seven(&self) -> u32 {\n            8")
        self.assert_refused("witness a_helper_keeps_its_verdict changed: its attributes or a test item")

    def test_unrelated_helpers_and_production_code_do_not_count(self):
        self.edit("src/helpers.rs", "    fn unrelated() -> u32 {\n        1", "    fn unrelated() -> u32 {\n        2")
        self.edit("src/helpers.rs", "pub fn production(x: u32) -> u32 {\n    x", "pub fn production(x: u32) -> u32 {\n    x + 0")
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_a_skipped_python_witness_is_refused(self):
        self.edit("scripts/test_recovery.py", "    def test_restart_keeps_the_start", "    @unittest.skip(\"later\")\n    def test_restart_keeps_the_start")
        self.assert_refused("witness RecoveryTests.test_restart_keeps_the_start changed: its attributes or a test item")

    def test_a_skipped_python_class_is_refused(self):
        self.edit("scripts/test_recovery.py", "class RecoveryTests(", "@unittest.skip(\"later\")\nclass RecoveryTests(")
        self.assert_refused("witness RecoveryTests.test_restart_keeps_the_start changed: its attributes or a test item")

    def test_a_python_fixture_or_module_helper_change_is_refused(self):
        self.edit("scripts/test_recovery.py", "self.base = 0", "self.base = 1")
        self.assert_refused("witness RecoveryTests.test_restart_keeps_the_start changed: its attributes or a test item")
        self.edit("scripts/test_recovery.py", "self.base = 1", "self.base = 0")
        self.edit("scripts/test_recovery.py", "START = 7", "START = 6")
        self.assert_refused("witness RecoveryTests.test_restart_keeps_the_start changed: its attributes or a test item")

    def test_the_closure_command_names_what_is_pinned(self):
        r = run(self.dir, "python3", "scripts/witness-pin.py", "closure", "a_helper_keeps_its_verdict")
        self.assertIn("src/helpers.rs:11 LIMIT", r.stdout)
        self.assertIn("src/helpers.rs:13 verdict", r.stdout)
        self.assertIn("src/helpers.rs:17 judged", r.stdout)
        self.assertNotIn("unrelated", r.stdout)

    def test_a_manifest_without_closures_is_noted_and_refused_on_main(self):
        import json
        manifest = self.dir / "docs/witness-manifest.json"
        pinned = json.loads(manifest.read_text())
        del pinned["closures_v3"]
        manifest.write_text(json.dumps(pinned, indent=1, sort_keys=True) + "\n")
        (self.dir / "docs/witness-manifest.json.sig").unlink()
        subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", self.key, "-n", "sokol-witness", str(manifest)],
                       stdin=subprocess.DEVNULL, check=True)
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("witness closures (attributes, helpers) are not pinned yet", r.stdout)
        r = run(self.dir, "python3", "scripts/witness-pin.py", "check", "--signers", str(self.signers), "--every-pin")
        self.assertEqual(r.returncode, 1, r.stdout)

    # A pinned witness must also run and pass: an attribute outside any hash, or a test runner
    # that skips it, would otherwise leave a signed row with no evidence behind it.

    def executed(self, log):
        (self.dir.parent / f"{self.dir.name}-log").write_text(log)
        return run(self.dir, "python3", "scripts/witness-pin.py", "check", "--signers", str(self.signers),
                   "--executed", str(self.dir.parent / f"{self.dir.name}-log"))

    def test_every_pinned_witness_ran_and_passed(self):
        r = self.executed(LOG)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_an_ignored_or_absent_rust_witness_is_refused(self):
        r = self.executed(LOG.replace("a_helper_keeps_its_verdict ... ok", "a_helper_keeps_its_verdict ... ignored"))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("witness a_helper_keeps_its_verdict did not run and pass", r.stdout)
        self.assertIn("(ignored)", r.stdout)
        r = self.executed(LOG.replace("test helpers::tests::generated_cases_keep_their_count ... ok\n", ""))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("witness generated_cases_keep_their_count did not run and pass", r.stdout)
        self.assertIn("(absent)", r.stdout)

    def test_python_witness_arguments_come_from_the_base_workflow_when_given(self):
        ci = self.dir / ".github/workflows/ci.yml"
        ci.parent.mkdir(parents=True)
        ci.write_text("run: python3 scripts/test_recovery.py --not-an-option\n")
        r = self.executed(LOG)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("witness RecoveryTests.test_recovery_keeps_the_cursor did not run and pass", r.stdout)
        base = self.dir.parent / f"{self.dir.name}-base-ci.yml"
        base.write_text("run: python3 scripts/test_recovery.py\n")
        log = self.dir.parent / f"{self.dir.name}-log"
        r = subprocess.run(["python3", "scripts/witness-pin.py", "check", "--signers", str(self.signers),
                            "--executed", str(log)], cwd=self.dir, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=120, env={**os.environ, "WITNESS_PIN_CI": str(base)})
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_python_witnesses_can_be_checked_from_a_run_python_log(self):
        out = run(self.dir, "python3", "scripts/witness-pin.py", "run-python").stdout
        self.assertIn("== witness RecoveryTests.test_recovery_keeps_the_cursor scripts/test_recovery.py", out)
        log = self.dir.parent / f"{self.dir.name}-python"
        (self.dir.parent / f"{self.dir.name}-log").write_text(LOG)
        for text, code in ((out, 0), (out.replace("test_recovery_keeps_the_cursor (", "test_other ("), 1), ("", 1)):
            log.write_text(text)
            r = run(self.dir, "python3", "scripts/witness-pin.py", "check", "--signers", str(self.signers),
                    "--executed", str(self.dir.parent / f"{self.dir.name}-log"), "--executed-python", str(log))
            self.assertEqual(r.returncode, code, r.stdout)

    def test_a_python_witness_that_needs_a_tool_runs_with_the_gates_environment(self):
        # EXCHANGE-P1, 2026-10-14: its witnesses skip without SOKOL_WARRANT_BIN. The gate runs
        # pinned Python witnesses in its own environment, and a skip is not a pass.
        self.edit("scripts/test_recovery.py", "    def test_recovery_keeps_the_cursor",
                  "    @unittest.skipUnless(__import__('os').environ.get('WITNESS_TOOL'), 'needs WITNESS_TOOL')\n"
                  "    def test_recovery_keeps_the_cursor")
        self.assertEqual(self.pin(self.key).returncode, 0)
        r = self.executed(LOG)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("witness RecoveryTests.test_recovery_keeps_the_cursor did not run and pass", r.stdout)
        log = self.dir.parent / f"{self.dir.name}-log"
        r = subprocess.run(["python3", "scripts/witness-pin.py", "check", "--signers", str(self.signers),
                            "--executed", str(log)], cwd=self.dir, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=120, env={**os.environ, "WITNESS_TOOL": "1"})
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_a_failing_python_witness_is_refused(self):
        self.edit("scripts/test_recovery.py", "def cursor(*_):\n    return 7", "def cursor(*_):\n    return 8")
        r = self.executed(LOG)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("witness RecoveryTests.test_recovery_keeps_the_cursor did not run and pass", r.stdout)


if __name__ == "__main__":
    unittest.main()
