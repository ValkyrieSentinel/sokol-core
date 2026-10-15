#!/usr/bin/env python3
"""scripts/pre-push.sh clears the repository variables git exports to a hook before it runs
anything: with GIT_DIR inherited, the fixture repositories of its regressions were written into
the real repository (2026-10-15). The first command of the script is replaced by a stub that
records its environment, so nothing else runs."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


class PrePushEnvironment(unittest.TestCase):
    def test_hook_variables_do_not_reach_the_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            seen = tmp / "seen"
            stub = bin_dir / "cargo"
            stub.write_text(f"#!/bin/sh\nenv > '{seen}'\nexit 3\n")
            stub.chmod(0o755)
            sacrificial = tmp / "other.git"
            hook_env = {
                "GIT_DIR": str(sacrificial),
                "GIT_INDEX_FILE": str(tmp / "index"),
                "GIT_WORK_TREE": str(tmp),
            }
            env = {**os.environ, **hook_env, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
            result = subprocess.run(["bash", str(HERE / "pre-push.sh")], env=env,
                                    capture_output=True, text=True, stdin=subprocess.DEVNULL,
                                    timeout=60)
            self.assertNotEqual(result.returncode, 0, "the stub stops the script")
            self.assertTrue(seen.exists(), result.stdout + result.stderr)
            names = {line.split("=", 1)[0] for line in seen.read_text().splitlines()}
            self.assertFalse(names & set(hook_env), f"hook variables reached the checks: {names & set(hook_env)}")


if __name__ == "__main__":
    unittest.main()
