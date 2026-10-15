"""A mesh experiment must refuse existing resources before arming destructive cleanup."""
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'bench/mesh.sh'


class MeshPreflight(unittest.TestCase):
    def test_existing_bridge_or_namespace_is_never_removed_on_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'calls'
            (root / 'ip').write_text('#!/bin/sh\necho "$*" >> "$CALLS"\n'
                'case "$1 $2" in\n'
                '"link show") [ "$COLLISION" = bridge ] && [ "$3" = skbr0 ]; exit $?;;\n'
                '"netns list") [ "$COLLISION" = namespace ] && echo "sk-n2 (id: 0)"; exit 0;;\n'
                'esac\nexit 0\n')
            (root / 'ip').chmod(0o755)
            (root / 'flock').write_text('#!/bin/sh\nexit 0\n')
            (root / 'flock').chmod(0o755)
            for collision in ('bridge', 'namespace'):
                log.unlink(missing_ok=True)
                result = subprocess.run(['bash', str(SCRIPT), 'soak', shutil.which('false'), shutil.which('false'), '3', '0'],
                    env={**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                         'CALLS': str(log), 'COLLISION': collision, 'BENCH_LOCK': str(root / 'lock')},
                    capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                changed = [line for line in log.read_text().splitlines()
                           if not line.startswith(('link show', 'netns list'))]
                self.assertEqual(changed, [], 'refusal changed the topology')
                self.assertIn('REFUSED existing mesh', result.stdout)


if __name__ == '__main__': unittest.main()
