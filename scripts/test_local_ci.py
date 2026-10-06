"""scripts/local-ci.sh's tool and monitoring steps, with fixture pins and stub commands.

Review of #153: (1) monitoring ran only the metric-name check, never promtool, even with docker;
(2) tools were trusted by their version text, so binaries found on PATH bypassed the checksum
and the `gobgp` client was never checked. Now every run extracts the pinned archives (checksum
verified, also for a cached copy) into a directory that must be where each tool resolves.

    python3 scripts/test_local_ci.py      (Linux; needs tar, zstd, sha256sum)
"""
import gzip
import hashlib
import io
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / 'local-ci.sh'
ARCH = {'x86_64': 'x86_64', 'aarch64': 'aarch64'}.get(platform.machine())


def tar_bytes(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as t:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def script(text):
    return '#!/bin/sh\n' + text + '\n'


@unittest.skipUnless(ARCH and shutil.which('zstd'), 'Linux x86_64/aarch64 with zstd')
class Steps(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.served = self.tmp / 'served'
        self.served.mkdir()
        self.stubs = self.tmp / 'stubs'
        self.stubs.mkdir()
        self.calls = self.tmp / 'calls.log'

    def stub(self, name, body):
        path = self.stubs / name
        path.write_text(script(body))
        path.chmod(0o755)

    def serve(self, name, data):
        (self.served / name).write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def fixture(self, gobgp_files=None):
        """Pinned archives served by a curl stub, and a ci.yml naming their checksums."""
        bpf = tar_bytes({'bpf-linker': script('echo bpf-linker 0.11.1')})
        bpf_zst = subprocess.run(['zstd', '-q', '-c'], input=bpf, capture_output=True, check=True).stdout
        bpf_sum = self.serve('bpf-linker-%s-unknown-linux-musl.tar.zst' % ARCH, bpf_zst)
        raw = tar_bytes(gobgp_files or {'gobgp': script('echo gobgp verified'),
                                        'gobgpd': script('echo gobgpd verified')})
        gobgp_gz = gzip.compress(raw)
        gobgp_arch = 'amd64' if ARCH == 'x86_64' else 'arm64'
        gobgp_sum = self.serve('gobgp_4.9.0_linux_%s.tar.gz' % gobgp_arch, gobgp_gz)
        ci = self.tmp / 'ci.yml'
        ci.write_text(f'''env:
  BPF_LINKER_VERSION: v0.11.1
  GOBGP_VERSION: 4.9.0
  CARGO_DENY_VERSION: 0.20.2
jobs:
  x:
    strategy:
      matrix:
        include:
          - arch: {ARCH}
            bpf_linker_sha256: {bpf_sum}
            gobgp_sha256: {gobgp_sum}
    steps:
      - run: docker run --entrypoint promtool prom/prometheus@sha256:{"a" * 64} test rules sokol-alerts.test.yml
''')
        # curl -sSfL -o OUT URL: copy the served file named by the URL's last component.
        self.stub('curl', f'out=$3; url=$4; echo "curl $url" >> {self.calls}; '
                          f'cp "{self.served}/$(basename "$url")" "$out"')
        return ci

    def run_step(self, step, ci, extra_path=None):
        env = dict(os.environ,
                   PATH=os.pathsep.join(filter(None, [extra_path, str(self.stubs), os.environ['PATH']])),
                   LOCAL_CI_YML=str(ci), LOCAL_CI_CACHE=str(self.tmp / 'cache'))
        return subprocess.run([str(SCRIPT), '--step', step], capture_output=True, text=True, env=env)

    def test_tools_on_path_with_matching_versions_are_not_used(self):
        ci = self.fixture()
        planted = self.tmp / 'planted'
        planted.mkdir()
        for name, text in (('bpf-linker', 'echo bpf-linker 0.11.1'), ('gobgpd', 'echo gobgpd version 4.9.0'),
                           ('gobgp', 'echo WRONG-CLIENT')):
            (planted / name).write_text(script(text))
            (planted / name).chmod(0o755)
        result = self.run_step('tools', ci, extra_path=str(planted))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        tools = self.tmp / 'cache' / 'bin'
        for tool in ('bpf-linker', 'gobgp', 'gobgpd'):
            self.assertIn('using %s/%s' % (tools, tool), result.stdout)
        self.assertIn('curl', self.calls.read_text(), 'the archives were fetched and checked')

    def test_a_tampered_archive_fails_even_when_cached_once(self):
        ci = self.fixture()
        self.assertEqual(self.run_step('tools', ci).returncode, 0)
        # The cached gobgp archive is changed afterwards, and the server now serves a tampered one.
        cached = next((self.tmp / 'cache' / 'archives').glob('gobgp-*'))
        cached.write_bytes(cached.read_bytes() + b'x')
        served = next(self.served.glob('gobgp_*'))
        served.write_bytes(served.read_bytes() + b'x')
        result = self.run_step('tools', ci)
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_an_archive_without_the_gobgp_client_fails(self):
        ci = self.fixture(gobgp_files={'gobgpd': script('echo gobgpd verified')})
        result = self.run_step('tools', ci)
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_monitoring_runs_ci_pinned_promtool_and_propagates_its_failure(self):
        ci = self.fixture()
        self.stub('docker', f'echo "docker $*" >> {self.calls}; exit ${{DOCKER_STATUS:-0}}')
        ok = self.run_step('monitoring', ci)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        call = [l for l in self.calls.read_text().splitlines() if l.startswith('docker ')][-1]
        self.assertIn('prom/prometheus@sha256:' + 'a' * 64, call)
        self.assertIn('promtool', call)
        self.assertIn('test rules sokol-alerts.test.yml', call)
        os.environ['DOCKER_STATUS'] = '17'
        try:
            failed = self.run_step('monitoring', ci)
        finally:
            del os.environ['DOCKER_STATUS']
        self.assertNotEqual(failed.returncode, 0, 'a failing promtool fails the step')


if __name__ == '__main__':
    unittest.main()
