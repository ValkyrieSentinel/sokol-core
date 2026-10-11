"""Adversarial contexts/reports: a matching unsigned claim cannot become native evidence."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('contract_task', ROOT / 'scripts/contract-task.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class ContractTask(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        sources = ['scripts/witness-pin.py', 'scripts/contract-task.py', 'docs/INVARIANTS.md',
                   'docs/witness-manifest.json', 'docs/witness-manifest.json.sig', '.github/witness-signers',
                   'orchestrator/src/delivery.rs', 'orchestrator/src/block_table.rs',
                   'orchestrator/src/state_input.rs', 'orchestrator/src/state_store.rs',
                   'orchestrator/src/replay.rs', 'common/src/audit_log.rs']
        sources += [p.relative_to(ROOT).as_posix() for p in (ROOT / 'docs/contracts').glob('*.shadow.json')]
        sources += [p.relative_to(ROOT).as_posix() for p in (ROOT / 'docs/contracts/proposals').glob('*.proposal.json')]
        for name in sources:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', 'add', '-A'], cwd=self.root, check=True)

    def tearDown(self):
        self.temp.cleanup()

    def context(self):
        return tool.prepare(self.root, 'IPC-A1')

    def report(self):
        context, inputs = self.context()
        return {'profile': 'sokol.agent.witness-run.v1', 'context': context, 'inputs': inputs,
                'execution': {'status': 'RECORDED_PASS', 'returncode': 0},
                'authenticity': 'UNSIGNED_LOCAL_REPORT'}

    def output(self):
        packet, _ = self.context()
        return b''.join(('tests::' + w + ': test\ntest tests::' + w + ' ... ok\n').encode()
                        for w in packet['body']['witnesses'])

    def change_contract(self, edit):
        path = self.root / 'docs/contracts/IPC-A1.shadow.json'
        value = json.loads(path.read_text())
        edit(value)
        path.write_text(json.dumps(value))

    def test_context_is_small_deterministic_and_never_claims_execution(self):
        a, inputs = self.context()
        b, _ = self.context()
        self.assertEqual(a, b)
        self.assertLessEqual(len(tool.encode(a)), tool.MAX_PACKET_BYTES)
        self.assertEqual(a['body']['execution'], 'UNKNOWN')
        self.assertEqual(a['body']['binding']['correspondence'], 'MATCH')
        self.assertEqual(a['body']['binding']['owner_signature'], 'VERIFIED_AGAINST_SUPPLIED_SIGNERS')
        self.assertEqual(a['body']['snapshot'], 'sha256:' + tool.digest(tool.encode(inputs)))

    def test_unpinned_mesh_is_visible_but_never_promoted_to_owner_acceptance(self):
        value, _ = tool.prepare(self.root, 'MESH-K1')
        self.assertEqual(value['body']['binding']['correspondence'], 'UNPINNED')
        self.assertEqual(value['body']['recipe'], 'orchestrator-unit')
        self.assertEqual(value['body']['execution'], 'UNKNOWN')

    def test_new_restore_proposal_gets_context_without_becoming_an_adopted_contract(self):
        proposal = next((self.root / 'docs/contracts/proposals').glob('STATE-B1-*.proposal.json'))
        value, _ = tool.prepare(self.root, 'STATE-B1', proposal=proposal.relative_to(self.root).as_posix())
        self.assertEqual(value['body']['binding']['correspondence'], 'UNSIGNED_PROPOSAL')
        self.assertEqual(value['body']['binding']['proposal_acceptance'], 'NOT_ESTABLISHED')
        self.assertEqual(value['body']['recipe'], 'orchestrator-unit')
        self.assertFalse((self.root / 'docs/contracts/STATE-B1.shadow.json').exists())

    def test_replay_proposal_uses_one_fixed_runner_for_both_rust_packages(self):
        proposal = next((self.root / 'docs/contracts/proposals').glob('REPLAY-B1-*.proposal.json'))
        value, _ = tool.prepare(self.root, 'REPLAY-B1', proposal=proposal.relative_to(self.root).as_posix())
        self.assertEqual(value['body']['binding']['correspondence'], 'UNSIGNED_PROPOSAL')
        self.assertEqual(value['body']['execution'], 'UNKNOWN')
        self.assertEqual(value['body']['recipe'], 'workspace-unit')
        command = value['body']['command']
        self.assertEqual(command, tool.RECIPES['workspace-unit'])
        self.assertIn('--lib', command)
        self.assertIn('--bins', command)
        packages = [command[i + 1] for i, arg in enumerate(command) if arg == '-p']
        self.assertEqual(packages, ['orchestrator', 'common'])

    def test_two_compiled_matches_require_two_successes_in_the_mixed_runner(self):
        packet, _ = self.context()
        packet['body']['recipe'] = 'workspace-unit'
        packet['body']['command'] = tool.RECIPES['workspace-unit']
        packet['body']['witnesses'] = ['shared']
        for count in [1, 2]:
            def runner(_root, command, **_options):
                if '--list' in command:
                    return 0, b'tests::shared: test\ntests::shared: test\n'
                return 0, b'test tests::shared ... ok\n' * count
            with patch.object(tool.platform, 'system', return_value='Linux'), patch.object(tool, 'run_bounded', side_effect=runner):
                execution, _ = tool.execute(self.root, packet)
            self.assertEqual(execution['status'], 'RECORDED_PASS' if count == 2 else 'RECORDED_FAIL')
            self.assertEqual(execution['compiled_match_counts']['shared'], 2)

    def test_invalid_id_and_proposal_paths_are_refused(self):
        for rid in ('../IPC-A1', 'IPC-A1/../../x', ''):
            with self.assertRaises(ValueError):
                tool.prepare(self.root, rid)
        with self.assertRaisesRegex(ValueError, 'local proposal path'):
            tool.prepare(self.root, 'IPC-A1', proposal='../../attack.json')

    def test_bad_signature_and_coordinated_unsigned_replacement_are_refused(self):
        self.change_contract(lambda c: c.update(statement='An ACK proves all kernel effects.'))
        path = self.root / 'docs/witness-manifest.json'
        value = json.loads(path.read_text())
        value['rows']['IPC-A1']['statement'] = tool.digest(b'An ACK proves all kernel effects.')
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'signature verification failed'):
            self.context()

    def test_signature_verification_uses_exact_cached_external_trust_bytes(self):
        trust = self.root / 'external-signers'
        expected = (self.root / '.github/witness-signers').read_bytes()
        trust.write_bytes(expected)
        original_checker = tool.checker
        def checked(root):
            module = original_checker(root)
            original_verify = module.verify_manifest
            def frozen(manifest, signature, signers):
                self.assertNotEqual(signers, trust)
                self.assertEqual(signers.read_bytes(), expected)
                trust.write_bytes(b'unknown invalid transient authority')
                try:
                    return original_verify(manifest, signature, signers)
                finally:
                    trust.write_bytes(expected)
            module.verify_manifest = frozen
            return module
        with patch.object(tool, 'checker', side_effect=checked):
            value, _ = tool.prepare(self.root, 'IPC-A1', signers=trust)
        self.assertEqual(value['body']['binding']['signers_sha256'], tool.digest(expected))
        self.assertEqual(value['body']['binding']['signer_provenance'], 'CALLER_SUPPLIED')

    def test_changed_witness_is_refused_but_helper_change_only_changes_snapshot(self):
        first, _ = self.context()
        source = self.root / 'orchestrator/src/delivery.rs'
        source.write_text(source.read_text() + '\nfn unsigned_helper() {}\n')
        second, _ = self.context()
        self.assertNotEqual(first['id'], second['id'])
        self.assertEqual(second['body']['binding']['correspondence'], 'MATCH')
        source.write_text(source.read_text().replace('fn an_unterminated_ack_does_not_retire_the_signal()',
                                                  'fn dropped_pinned_witness()'))
        with self.assertRaisesRegex(ValueError, 'Missing witness body'):
            self.context()

    def test_symlink_and_oversized_inputs_fail_before_projection(self):
        source = self.root / 'orchestrator/src/delivery.rs'
        source.unlink()
        source.symlink_to(ROOT / 'orchestrator/src/delivery.rs')
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            self.context()
        source.unlink()
        source.write_bytes(b'x' * (tool.MAX_FILE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, 'byte bound'):
            self.context()

    def test_matching_forged_report_has_unknown_execution_without_replay(self):
        report = self.report()
        report['execution'] = {'status': 'PASS', 'proof': 'invented'}
        verdict = tool.verify_report(self.root, report)
        self.assertEqual(verdict['binding'], 'MATCH')
        self.assertEqual(verdict['execution'], 'UNKNOWN')
        self.assertEqual(verdict['historical_execution'], 'UNVERIFIED')

    def test_malformed_report_shapes_refuse_without_executing(self):
        for value in ([], None, {}, {'profile': 'sokol.agent.witness-run.v1', 'context': []},
                      {'profile': 'sokol.agent.witness-run.v1', 'context': {'body': {'binding': []}}}):
            with patch.object(tool, 'execute') as runner:
                with self.assertRaises(ValueError):
                    tool.verify_report(self.root, value, replay=True)
                runner.assert_not_called()

    def test_helper_config_and_file_inventory_changes_make_old_reports_stale(self):
        report = self.report()
        with patch.dict(os.environ, {'RUSTFLAGS': 'different compiler configuration'}):
            self.assertEqual(tool.verify_report(self.root, report)['binding'], 'STALE')
        source = self.root / 'orchestrator/src/delivery.rs'
        source.write_text(source.read_text() + '\nfn changed_helper() {}\n')
        self.assertEqual(tool.verify_report(self.root, report)['binding'], 'STALE')
        report = self.report()
        new = self.root / 'added-fixture.json'
        new.write_text('{}')
        subprocess.run(['git', 'add', new.name], cwd=self.root, check=True)
        self.assertEqual(tool.verify_report(self.root, report)['binding'], 'STALE')

    def test_exit_zero_and_zero_tests_never_count_as_pass(self):
        packet, _ = self.context()
        with patch.object(tool, 'run_bounded', return_value=(0, b'test result: ok. 0 passed\n')):
            execution, _ = tool.execute(self.root, packet)
        self.assertEqual(execution['status'], 'RECORDED_FAIL')
        self.assertEqual(execution['missing_witnesses'], sorted(packet['body']['witnesses']))

    def test_forged_pass_lines_cannot_replace_the_compilers_list_of_tests(self):
        packet, _ = self.context()
        forged = b''.join(('test tests::' + w + ' ... ok\n').encode() for w in packet['body']['witnesses'])
        with patch.object(tool, 'run_bounded', return_value=(0, forged)):
            execution, _ = tool.execute(self.root, packet)
        self.assertEqual(execution['status'], 'RECORDED_FAIL')

    def test_an_ignored_witness_is_not_settled_by_an_extra_success_line(self):
        packet, _ = self.context()
        first = packet['body']['witnesses'][0]
        forged = self.output() + ('test tests::' + first + ' ... ignored\n').encode()
        with patch.object(tool, 'run_bounded', return_value=(0, forged)):
            execution, _ = tool.execute(self.root, packet)
        self.assertEqual(execution['status'], 'RECORDED_FAIL')

    def test_one_missing_witness_and_nonzero_exit_refuse_a_pass(self):
        packet, _ = self.context()
        output = self.output()
        for status, text in [(0, output.split(b'\n', 1)[1]), (1, output)]:
            with patch.object(tool, 'run_bounded', return_value=(status, text)):
                execution, _ = tool.execute(self.root, packet)
            self.assertEqual(execution['status'], 'RECORDED_FAIL')

    def test_rust_runner_uses_only_validated_named_filters_and_a_shared_output_budget(self):
        packet, _ = self.context()
        packet['body']['recipe'] = 'orchestrator-unit'
        packet['body']['command'] = tool.RECIPES['orchestrator-unit']
        calls = []
        def runner(_root, command, **options):
            calls.append((command, options))
            witness = command[command.index('--bins') + 1]
            if '--list' in command:
                return 0, ('tests::' + witness + ': test\n').encode()
            self.assertIn('--exact', command)
            return 0, ('test ' + witness + ' ... ok\n').encode()
        with patch.object(tool.platform, 'system', return_value='Linux'), patch.object(tool, 'run_bounded', side_effect=runner):
            execution, _ = tool.execute(self.root, packet)
        self.assertEqual(execution['status'], 'RECORDED_PASS')
        self.assertEqual(len(calls), 2 * len(packet['body']['witnesses']))
        self.assertLess(calls[-1][1]['bound'], calls[0][1]['bound'])
        packet['body']['witnesses'] = ['--skip']
        with patch.object(tool.platform, 'system', return_value='Linux'), patch.object(tool, 'run_bounded') as runner:
            with self.assertRaisesRegex(ValueError, 'Invalid witness filter'):
                tool.execute(self.root, packet)
            runner.assert_not_called()

    def test_imported_command_and_annotations_never_select_a_runner(self):
        packet, _ = self.context()
        packet['body']['command'] = ['sh', '-c', 'touch unexpected-effect']
        with patch.object(tool, 'run_bounded') as runner:
            with self.assertRaisesRegex(ValueError, 'fixed witness runner'):
                tool.execute(self.root, packet)
            runner.assert_not_called()
        report = self.report()
        report['context']['body']['command'] = ['sh', '-c', 'touch unexpected-effect']
        self.assertEqual(tool.verify_report(self.root, report, replay=True)['binding'], 'STALE')
        self.change_contract(lambda c: c['annotations'].update(command='touch unexpected-effect'))
        packet, _ = self.context()
        self.assertEqual(packet['body']['command'], tool.RECIPES['delivery'])
        self.assertFalse((self.root / 'unexpected-effect').exists())

    def test_rust_cache_is_namespaced_by_snapshot_and_configuration(self):
        packet, _ = self.context()
        packet['body']['recipe'] = 'orchestrator-unit'
        packet['body']['command'] = tool.RECIPES['orchestrator-unit']
        paths = []
        def runner(_root, command, **options):
            paths.append(options['env']['CARGO_TARGET_DIR'])
            self.assertEqual(options['env']['CARGO_BUILD_TARGET_DIR'], paths[-1])
            self.assertEqual(options['env']['CARGO_BUILD_BUILD_DIR'], str(Path(paths[-1]) / 'build'))
            witness = command[command.index('--bins') + 1]
            line = 'tests::' + witness + ': test\n' if '--list' in command else 'test ' + witness + ' ... ok\n'
            return 0, line.encode()
        with patch.object(tool.platform, 'system', return_value='Linux'), patch.object(tool, 'run_bounded', side_effect=runner):
            with patch.dict(os.environ, {'CARGO_TARGET_DIR': str(self.root / 'cache')}):
                self.assertEqual(tool.execute(self.root, packet)[0]['status'], 'RECORDED_PASS')
                first = paths[-1]
                self.assertTrue(first.startswith(str(self.root / 'cache/sokol-contract-task') + '/'))
                self.assertEqual(os.environ['CARGO_TARGET_DIR'], str(self.root / 'cache'))
                packet['body']['snapshot'] = 'sha256:different'
                tool.execute(self.root, packet)
                self.assertNotEqual(paths[-1], first)
                second = paths[-1]
                packet['body']['configuration'] = {'different': True}
                tool.execute(self.root, packet)
                self.assertNotEqual(paths[-1], second)
            with patch.dict(os.environ, {'CARGO_TARGET_DIR': 'relative-cache'}):
                with self.assertRaisesRegex(ValueError, 'absolute'):
                    tool.execute(self.root, packet)

    def test_replay_ignores_a_forged_green_and_runs_fresh_verification(self):
        report = self.report()
        with patch.object(tool, 'execute', return_value=({'status': 'RECORDED_FAIL', 'returncode': 1}, b'fail')) as runner:
            verdict = tool.verify_report(self.root, report, replay=True)
        runner.assert_called_once()
        self.assertEqual(verdict['execution'], 'REPLAYED_FAIL')
        with patch.object(tool, 'execute', return_value=({'status': 'RECORDED_PASS', 'returncode': 0}, b'ok')):
            self.assertEqual(tool.verify_report(self.root, report, replay=True)['execution'], 'REPLAYED_PASS')

    def test_changed_inputs_during_verification_are_never_recorded_as_fresh(self):
        def moved(_root, _packet):
            source = self.root / 'orchestrator/src/delivery.rs'
            source.write_text(source.read_text() + '\n// changed while the verifier ran\n')
            return {'status': 'RECORDED_PASS', 'returncode': 0}, b'ok'
        with patch.object(tool, 'execute', side_effect=moved):
            report, _ = tool.make_report(self.root, 'IPC-A1')
        self.assertEqual(report['execution']['status'], 'STALE')

    def test_verifier_reads_a_hash_checked_copy_even_if_the_working_tree_changes(self):
        original = self.root / 'orchestrator/src/delivery.rs'
        expected = original.read_bytes()
        seen = []
        def frozen(work, _packet):
            self.assertNotEqual(work, self.root)
            original.write_bytes(expected + b'\nfn transient_edit() {}\n')
            seen.append((work / 'orchestrator/src/delivery.rs').read_bytes())
            original.write_bytes(expected)  # an A-B-A edit cannot alter the private verifier input
            return {'status': 'RECORDED_PASS', 'returncode': 0}, b'ok'
        with patch.object(tool, 'execute', side_effect=frozen):
            report, _ = tool.make_report(self.root, 'IPC-A1')
        self.assertEqual(seen, [expected])
        self.assertEqual(report['execution']['status'], 'RECORDED_PASS')
        self.assertEqual(report['execution']['input_binding'], 'HASH_CHECKED_PRIVATE_TRACKED_COPY')

    def test_executable_mode_changes_stale_the_inventory(self):
        report = self.report()
        source = self.root / 'orchestrator/src/delivery.rs'
        source.chmod(0o755)
        self.assertEqual(tool.verify_report(self.root, report)['binding'], 'STALE')

    def test_process_output_bound_accepts_equality_refuses_overflow_and_reaps(self):
        command = [sys.executable, '-c', 'import sys; sys.stdout.buffer.write(b"x" * 32)']
        self.assertEqual(tool.run_bounded(self.root, command, bound=32), (0, b'x' * 32))
        pid_file = self.root / 'overflow.pid'
        code = 'import os,time; from pathlib import Path; Path("overflow.pid").write_text(str(os.getpid())); os.write(1,b"x"*33); time.sleep(60)'
        with self.assertRaisesRegex(ValueError, 'output bound'):
            tool.run_bounded(self.root, [sys.executable, '-c', code], bound=32)
        pid = int(pid_file.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_a_silent_or_pipe_closed_process_still_has_a_deadline(self):
        for code in ('import time; time.sleep(60)', 'import os,time; os.close(1); os.close(2); time.sleep(60)'):
            start = time.monotonic()
            with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                tool.run_bounded(self.root, [sys.executable, '-c', code], timeout=.1)
            self.assertLess(time.monotonic() - start, 2)


if __name__ == '__main__':
    unittest.main()
