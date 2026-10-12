"""scripts/check-retired.sh, the retired-files table (docs/RETIRED.md, 2026-10-12 on).

Each case builds a small repository whose archive tags hold a file that was then retired, and
breaks one rule of its table row: the file is back, the digest is not the tag's bytes, the loss
is empty, a SUPERSEDED row names no replacement or one that does not exist, the table is empty.

    python3 scripts/test_check_retired.py
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
OLD = "# An old pilot\n\nStatus: do not merge.\n"
DIGEST = hashlib.sha256(OLD.encode()).hexdigest()
LEDGER = """# Retired

| ID | What | Fixed | Cited in |
|---|---|---|---|
| F01 | x | #1 | `x.rs` |

<!-- retired-files: path | mode | sha256 at the tag | replacement | loss -->
{row}

## After
"""
ROW = f"| `docs/OLD.md` | SUPERSEDED | {DIGEST} | ADR-0001 | the pilot's narrative |"


def run(cwd, *cmd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)


class RetiredFiles(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        for sub in ("scripts", "docs/adr"):
            (self.dir / sub).mkdir(parents=True)
        shutil.copy(HERE / "check-retired.sh", self.dir / "scripts/check-retired.sh")
        (self.dir / "docs/adr/0001-a.md").write_text("# ADR-0001\n")
        (self.dir / "x.rs").write_text("// F01\n")
        (self.dir / "docs/OLD.md").write_text(OLD)
        (self.dir / "docs/RETIRED.md").write_text(LEDGER.format(row=ROW))
        git = lambda *a: run(self.dir, "git", "-c", "user.name=t", "-c", "user.email=t@t", *a)
        git("init", "-q")
        git("add", "-A")
        git("commit", "-qm", "before")
        for tag in ("archive/2026-09-29", "archive/2026-10-05", "archive/2026-10-12"):
            git("tag", tag)
        git("rm", "-q", "docs/OLD.md")
        git("commit", "-qm", "retire")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def check(self):
        return run(self.dir, "bash", "scripts/check-retired.sh")

    def with_row(self, row):
        (self.dir / "docs/RETIRED.md").write_text(LEDGER.format(row=row))

    def assert_refused(self, needle):
        r = self.check()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(needle, r.stdout)

    def test_a_retired_file_with_its_digest_and_loss_passes(self):
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("1 retired files: absent, digests match", r.stdout)

    def test_a_retired_file_back_in_the_tree_is_refused(self):
        (self.dir / "docs/OLD.md").write_text(OLD)
        self.assert_refused("docs/OLD.md is retired but still in the tree")

    def test_a_digest_that_is_not_the_tagged_bytes_is_refused(self):
        self.with_row(ROW.replace(DIGEST, "0" * 64))
        self.assert_refused("bytes at archive/2026-10-12 are not")

    def test_an_empty_loss_is_refused(self):
        self.with_row(ROW.replace("the pilot's narrative", "—"))
        self.assert_refused("a retirement names what is lost")

    def test_superseded_names_an_existing_replacement(self):
        self.with_row(ROW.replace("ADR-0001", "—"))
        self.assert_refused("SUPERSEDED names its replacement")
        self.with_row(ROW.replace("ADR-0001", "ADR-0099"))
        self.assert_refused("ADR-0099 does not exist")

    def test_an_unknown_mode_is_refused(self):
        self.with_row(ROW.replace("SUPERSEDED", "FORGOTTEN"))
        self.assert_refused("mode FORGOTTEN")

    def test_an_empty_table_is_refused(self):
        self.with_row("")
        self.assert_refused("has no retired-files rows")


if __name__ == "__main__":
    unittest.main()
