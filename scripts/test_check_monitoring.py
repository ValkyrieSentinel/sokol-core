"""scripts/check-monitoring.sh: the alert rules and the dashboard select series the node exports.

The check compared metric names only. A label value an alert selects on
(`sokol_xdp_mode{mode="generic"}`, `sokol_mesh_broadcasts_dropped_total{class="urgent"}`)
could be renamed in the exporter and the check, the metrics tests and promtool's own rule
tests (which feed synthetic series) all stayed green, while the alert could never fire.

    python3 scripts/test_check_monitoring.py
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
FILES = [
    'scripts/check-monitoring.sh',
    'deploy/prometheus/sokol-alerts.yml',
    'deploy/grafana/sokol-dashboard.json',
    'orchestrator/src/metrics.rs',
    'orchestrator/src/detections.rs',
    'orchestrator/src/p2p.rs',
    'orchestrator/src/block_table.rs',
    'common/src/lib.rs',
]


class Monitoring(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        for f in FILES:
            (self.dir / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / f, self.dir / f)

    def mutate(self, rel, old, new):
        path = self.dir / rel
        text = path.read_text()
        self.assertIn(old, text, f'mutation anchor missing in {rel}')
        path.write_text(text.replace(old, new))

    def run_check(self):
        return subprocess.run([str(self.dir / 'scripts/check-monitoring.sh')],
                              capture_output=True, text=True)

    def test_the_repository_passes(self):
        r = self.run_check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_renamed_metric_fails(self):
        self.mutate('orchestrator/src/metrics.rs', 'sokol_claims_waiting', 'sokol_claims_queued')
        self.assertNotEqual(self.run_check().returncode, 0)

    def test_a_renamed_label_value_an_alert_selects_fails(self):
        for rel, old, new in [
            ('orchestrator/src/metrics.rs', '{ "native" } else { "generic" }',
             '{ "native" } else { "skb" }'),
            ('orchestrator/src/metrics.rs', 'class=\\"urgent\\"', 'class=\\"decision\\"'),
            ('orchestrator/src/detections.rs', '"enforced", "pending"', '"enforced", "queued"'),
        ]:
            with self.subTest(new):
                self.setUp()
                self.mutate(rel, old, new)
                r = self.run_check()
                self.assertNotEqual(
                    r.returncode, 0,
                    f'{old} -> {new}: an alert now selects a series nobody exports, '
                    f'and the check passed: {r.stdout.strip()}')


if __name__ == '__main__':
    unittest.main()
