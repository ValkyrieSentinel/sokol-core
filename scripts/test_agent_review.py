"""The shadow agent reviewer's publisher (scripts/agent_review.py), ported from Stargate.

The reviewer CLI is a fake executable; what is tested is what surrounds it: binding to one
open pull request, isolation of the reviewer, the verdict contract and the status it yields.

    python3 scripts/test_agent_review.py
"""
import contextlib
import http.server
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
REVIEW = HERE / 'agent_review.py'
REPO = 'owner/repo'
SECRET = 'oauth-test-credential-0123456789'
CONTEXT = 'sokol/agent-review'


def module(source=None):
    spec = importlib.util.spec_from_file_location('agent_review', REVIEW)
    loaded = importlib.util.module_from_spec(spec)
    if source is None:
        spec.loader.exec_module(loaded)
    else:
        loaded.__file__ = str(REVIEW)
        exec(compile(source, 'agent_review_mutant', 'exec'), loaded.__dict__)
    return loaded


class FakeGitHub:
    """Open pull requests, branch refs and recorded status writes; nothing else."""

    def __init__(self, pulls, refs):
        self.pulls, self.refs, self.requests = pulls, refs, []
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                fake.requests.append(('GET', self.path, None))
                url = urlsplit(self.path)
                parts = url.path.strip('/').split('/')
                if parts[3:] == ['pulls']:
                    page = int(parse_qs(url.query)['page'][0])
                    opened = [p for p in fake.pulls if p['state'] == 'open']
                    return self.reply(200, opened[(page - 1) * 100:page * 100])
                if parts[3:4] == ['pulls']:
                    found = [p for p in fake.pulls if str(p['number']) == parts[4]]
                    return self.reply(200, found[0]) if found else self.reply(404, {})
                if parts[3:6] == ['git', 'ref', 'heads'] and '/'.join(parts[6:]) in fake.refs:
                    return self.reply(200, {'object': {'sha': fake.refs['/'.join(parts[6:])]}})
                self.reply(404, {})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                fake.requests.append(('POST', self.path, body))
                self.reply(201, {})

        self.server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.api = f'http://127.0.0.1:{self.server.server_port}'

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def statuses(self, head):
        return [(b['state'], b.get('description', '')) for m, p, b in self.requests
                if m == 'POST' and p.endswith('/statuses/' + head) and b.get('context') == CONTEXT]

    def writes(self):
        return [(m, p) for m, p, b in self.requests if m != 'GET']


def git(cwd, *args):
    return subprocess.run(['git', '-C', str(cwd), '-c', 'user.name=t', '-c', 'user.email=t@t', *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def answer(verdict, *findings, summary='s'):
    return dict(verdict=verdict, summary=summary,
                findings=[dict(severity=s, location='f.rs:1', claim='c') for s in findings])


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        origin = self.tmp / 'origin'
        origin.mkdir()
        git(origin, 'init', '-q', '-b', 'main')
        (origin / 'node.rs').write_text('fn main() {}\n')
        git(origin, 'add', '-A')
        git(origin, 'commit', '-q', '-m', 'base')
        self.base = git(origin, 'rev-parse', 'HEAD')
        git(origin, 'checkout', '-q', '-b', 'change')
        (origin / 'node.rs').write_text('fn main() { let window = 60_000; }\n')
        git(origin, 'commit', '-q', '-am', 'change')
        self.good = git(origin, 'rev-parse', 'HEAD')
        (origin / 'node.rs').write_text('fn main() { let window = 60_001; }\n')
        git(origin, 'commit', '-q', '-am', 'other')
        self.other = git(origin, 'rev-parse', 'HEAD')
        git(origin, 'checkout', '-q', 'main')
        subprocess.run(['git', 'clone', '-q', str(origin), str(self.tmp / 'clone')], check=True)
        self.seen = self.tmp / 'seen.json'

    def fake_claude(self, stdout, exit_code=0):
        """An executable that records what the reviewer would see, prints `stdout`, exits."""
        path = self.tmp / 'claude'
        path.write_text(f'''#!{sys.executable}
import json, os, sys
json.dump(dict(argv=sys.argv[1:], env=sorted(os.environ), cwd=sorted(os.listdir('.')),
               diff=open('review.diff').read()), open({str(self.seen)!r}, 'w'))
sys.stdout.write({stdout!r})
sys.exit({exit_code})
''')
        path.chmod(0o755)
        return str(path)

    def result(self, structured, **extra):
        return json.dumps(dict(type='result', subtype='success', is_error=False,
                               structured_output=structured, **extra))

    def pull(self, number, head):
        return dict(number=number, state='open', head=dict(sha=head), base=dict(ref='main'))

    def run_review(self, stdout, head=None, pulls=None, source=None, exit_code=0, summary_path=None):
        head = head or self.good
        pulls = [self.pull(1, head)] if pulls is None else pulls
        fake = FakeGitHub(pulls, {'main': self.base})
        self.addCleanup(fake.close)
        printed = io.StringIO()
        try:
            with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(printed):
                code = module(source).publish(
                    api=fake.api, token='github-token', repository=REPO, head=head,
                    event_pulls=[p['number'] for p in pulls], clone=str(self.tmp / 'clone'),
                    model='claude-opus-5-5', secret=SECRET, summary_path=summary_path,
                    claude=self.fake_claude(stdout, exit_code))
        except Exception:
            code = 'raised'
        self.printed = printed.getvalue()
        return code, fake.statuses(head), fake


class Publisher(Base):
    def test_pass_is_success_on_exactly_that_head(self):
        code, statuses, fake = self.run_review(self.result(answer('pass', 'minor')))
        self.assertEqual([s for s, d in statuses], ['pending', 'success'])
        self.assertEqual({p for m, p in fake.writes()}, {f'/repos/{REPO}/statuses/{self.good}'})
        self.assertEqual(code, 0)

    def test_the_reviewer_sees_only_the_export_the_diff_and_its_credential(self):
        self.run_review(self.result(answer('pass')))
        seen = json.loads(self.seen.read_text())
        self.assertEqual(seen['cwd'], ['head', 'review.diff'])
        os_added = {'LC_CTYPE', '__CF_USER_TEXT_ENCODING'}  # macOS adds these to every process
        self.assertEqual(sorted(set(seen['env']) - os_added), ['CLAUDE_CODE_OAUTH_TOKEN', 'HOME', 'PATH'])
        argv = seen['argv']
        self.assertEqual(argv[argv.index('--tools') + 1], 'Read,Grep,Glob')
        self.assertNotIn('--dangerously-skip-permissions', argv)
        self.assertIn('60_000', seen['diff'])

    def test_hold_and_deny_are_failure(self):
        for verdict, findings in (('hold', ('major',)), ('deny', ('blocker',))):
            with self.subTest(verdict):
                code, statuses, _ = self.run_review(self.result(answer(verdict, *findings)))
                self.assertEqual((statuses[-1][0], code), ('failure', 2))

    def test_inadmissible_answers_are_errors_never_success(self):
        cases = {
            'pass with a blocker': self.result(answer('pass', 'blocker')),
            'pass with a major': self.result(answer('pass', 'major')),
            'deny without a blocker': self.result(answer('deny', 'major')),
            'unknown verdict': self.result(answer('maybe')),
            'extra field': self.result(dict(answer('pass'), approve=True)),
            'no structured output': self.result(None),
            'api error': json.dumps(dict(subtype='success', is_error=True, api_error='credits_required')),
            'not json': 'pass',
        }
        for name, stdout in cases.items():
            with self.subTest(name):
                code, statuses, _ = self.run_review(stdout)
                self.assertEqual(statuses[-1][0], 'error')
                self.assertNotIn('success', [s for s, d in statuses])

    def test_a_failed_process_is_an_error_even_with_a_valid_pass_on_stdout(self):
        code, statuses, _ = self.run_review(self.result(answer('pass')), exit_code=7)
        self.assertEqual(statuses[-1][0], 'error')
        self.assertIn('exited 7', statuses[-1][1])

    def test_an_escaped_credential_is_caught_after_decoding_and_never_published(self):
        escaped = ''.join(f'\\u{ord(c):04x}' for c in SECRET)
        stdout = self.result(answer('pass')).replace('"summary": "s"', f'"summary": "{escaped}"')
        summary = self.tmp / 'summary.md'
        code, statuses, fake = self.run_review(stdout, summary_path=str(summary))
        self.assertEqual(statuses[-1][0], 'error')
        self.assertFalse(any(SECRET in json.dumps(b) for m, p, b in fake.requests if b))
        self.assertFalse(summary.exists() and SECRET in summary.read_text())
        self.assertNotIn(SECRET, self.printed)

    def test_unbound_or_moved_heads_write_nothing(self):
        for pulls in ([], [self.pull(1, self.other)], [self.pull(1, self.good), self.pull(2, self.good)]):
            with self.subTest(len(pulls)):
                code, _, fake = self.run_review(self.result(answer('pass')), pulls=pulls)
                self.assertEqual((fake.writes(), code != 0), ([], True))
                self.assertFalse(self.seen.exists())


class Control(Base):
    SITE = "    if verdict == 'pass' and worst & {'blocker', 'major'}:\n"

    def test_without_the_consistency_rule_a_pass_with_a_blocker_succeeds(self):
        source = REVIEW.read_text()
        self.assertIn(self.SITE, source, 'mutation site not found: the control would prove nothing')
        code, statuses, _ = self.run_review(self.result(answer('pass', 'blocker')),
                                            source=source.replace(self.SITE, '    if False:\n'))
        self.assertEqual(statuses[-1][0], 'success')


if __name__ == '__main__':
    unittest.main()
