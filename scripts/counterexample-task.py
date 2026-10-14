#!/usr/bin/env python3
"""export | inspect | replay | view: portable native evidence, ordinary Warrant records."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('counterexample_inputs', ROOT / 'scripts/contract-task.py')
inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inputs)
worker_spec = importlib.util.spec_from_file_location('counterexample_worker', ROOT / 'scripts/counterexample_worker.py')
worker = importlib.util.module_from_spec(worker_spec)
worker_spec.loader.exec_module(worker)
MAX_BLOB = 8 * 1024 * 1024
MAX_PACK = 128 * 1024 * 1024
MAX_OBJECTS = 8192
MAX_RECORDS = 16
TOTAL_SECONDS = 1800
MEMORY_BYTES = 8 * 1024 ** 3
SCRATCH_BYTES = 4 * 1024 ** 3
MAX_TASKS = 256
MAX_VIEW_OBSERVATIONS = 4
MAX_REGISTRY_FILES = 100_000
MAX_REGISTRY_BYTES = 2 * 1024 ** 3
PROFILE = 'sokol.counterexample-pack.v1'
CASE = 'operator-lost-reply'
HEX = re.compile(r'[0-9a-f]{64}')
POLICY = {'profile': 'sokol.counterexample-policy.v1', 'case': CASE, 'contract': 'OPERATOR-R1',
          'authority': 'EXPERIMENTAL_REPRODUCTION_ONLY',
          'recipe': 'LOCAL_FIXED_RUNNER_NO_IMPORTED_COMMANDS',
          'success': 'all pinned witnesses pass; derived defect fails at named assertion; restoration passes',
          'limits': 'no owner acceptance, settlement, model identity, kernel effect or deployment admission'}


def encode(value):
    # Domain-specific descriptor bytes, NOT Warrant JCS. Warrant CLI owns all
    # canonicalization/signature operations on Warrant bodies.
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON member')
        result[key] = value
    return result


def document(data):
    def refuse(_):
        raise ValueError('Non-integer JSON number')
    return json.loads(data, object_pairs_hook=no_duplicates, parse_float=refuse, parse_constant=refuse)


def read(path):
    path = Path(path)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('Non-regular input refused')
    return inputs.read(path, MAX_BLOB)


def hash_name(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError('Invalid content address')
    return value


def blob(pack, address):
    value = read(pack / '.warrants/blobs' / hash_name(address))
    if digest(value) != address:
        raise ValueError('Blob bytes do not match address')
    return value


def put(pack, value):
    if len(value) > MAX_BLOB:
        raise ValueError('Blob exceeds limit')
    address = digest(value)
    path = pack / '.warrants/blobs' / address
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and read(path) != value:
        raise ValueError('Existing blob differs')
    path.write_bytes(value)
    return address


def selected_verifier(path, expected):
    path = Path(path).resolve(strict=True)
    if digest(read(path)) != hash_name(expected):
        raise ValueError('Recipient-selected Warrant binary digest differs')
    return path


def warrant(binary, pack, args):
    env = {'PATH': '/usr/bin:/bin', 'WARRANT_SKI_MAX_ATP': '1000'}
    code, output = inputs.run_bounded(pack, [str(binary), '--store', str(pack / '.warrants'), *args],
                                      timeout=120, bound=MAX_BLOB, env=env)
    return code, output


def inventory(pack):
    total, count, records = 0, 0, []
    for path in pack.rglob('*'):
        if path.is_symlink():
            raise ValueError('Symlink in pack')
        rel = path.relative_to(pack).as_posix()
        if path.is_dir():
            if rel not in ('.warrants', '.warrants/blobs', '.warrants/records'):
                raise ValueError('Unexpected pack directory')
            continue
        parts = rel.split('/')
        if rel != 'manifest.json' and not (len(parts) == 3 and parts[:2] in
                [['.warrants', 'blobs'], ['.warrants', 'records']]):
            raise ValueError('Unexpected pack file')
        data = read(path)
        total += len(data)
        count += 1
        if count > MAX_OBJECTS or total > MAX_PACK:
            raise ValueError('Pack exceeds aggregate limit')
        if parts[:2] == ['.warrants', 'blobs']:
            if digest(data) != hash_name(parts[2]):
                raise ValueError('Blob bytes do not match address')
        elif parts[:2] == ['.warrants', 'records']:
            hash_name(parts[2].removesuffix('.json'))
            if not parts[2].endswith('.json'):
                raise ValueError('Invalid record filename')
            records.append((parts[2][:-5], document(data)))
    if not 1 <= len(records) <= MAX_RECORDS:
        raise ValueError('Record count exceeds profile')
    return sorted(records)


def safe_source(name):
    if not isinstance(name, str) or not name or '\\' in name:
        raise ValueError('Invalid source path')
    parts = name.split('/')
    if (any(p in ('', '.', '..', '.git', 'target') for p in parts) or name.startswith('/')
            or name in ('.cargo/config', '.cargo/config.toml')):
        raise ValueError('Invalid source path')
    return name


def validate_descriptor(pack, desc, signers):
    if (set(desc) != {'profile', 'case', 'contract_context', 'files', 'repair_snapshot',
                     'defect_snapshot', 'defect_origin', 'policy', 'worker_sha256'}
            or desc['profile'] != PROFILE or desc['case'] != CASE
            or desc['policy'] != digest(encode(POLICY))
            or desc['defect_origin'] != 'DERIVED_COUNTERFACTUAL_NOT_HISTORICAL_COMMIT'
            or desc['worker_sha256'] != digest(read(ROOT / 'scripts/counterexample_worker.py'))):
        raise ValueError('Unsupported descriptor or local method differs')
    if blob(pack, desc['policy']) != encode(POLICY):
        raise ValueError('Reproduction policy differs')
    files = desc['files']
    if not isinstance(files, dict) or not 1 <= len(files) <= inputs.MAX_FILES:
        raise ValueError('Source file count outside limit')
    total = 0
    for name, entry in files.items():
        safe_source(name)
        if set(entry) != {'sha256', 'executable'} or type(entry['executable']) is not bool:
            raise ValueError('Invalid source entry')
        data = blob(pack, entry['sha256'])
        if len(data) > inputs.MAX_FILE_BYTES:
            raise ValueError('Source file exceeds input budget')
        total += len(data)
    if total > inputs.MAX_CHECKOUT_BYTES or desc['repair_snapshot'] != digest(encode(files)):
        raise ValueError('Source snapshot differs or exceeds limit')
    source = blob(pack, files[worker.CASE_FILE]['sha256']).decode()
    if source.count(worker.BEFORE) != 1:
        raise ValueError('Defect anchor differs')
    defect = {**files, worker.CASE_FILE: {**files[worker.CASE_FILE],
               'sha256': digest(source.replace(worker.BEFORE, worker.AFTER).encode())}}
    if desc['defect_snapshot'] != digest(encode(defect)):
        raise ValueError('Derived defect snapshot differs')
    # Never import Python from the received checkout. The recipient's installed
    # owner gate verifies signed inputs using the recipient's signer file.
    pin = inputs.checker(ROOT)
    context = document(blob(pack, desc['contract_context']))
    if set(context) != {'id', 'body'} or context['id'] != 'sha256:' + digest(inputs.encode(context['body'])):
        raise ValueError('Contract context identity differs')
    body = context['body']
    if (body['contract_id'] != 'OPERATOR-R1' or body['snapshot'] != 'sha256:' + desc['repair_snapshot']
            or sorted(body['witnesses']) != sorted(worker.WITNESSES)):
        raise ValueError('Contract scope differs')
    trust = read(signers)
    if body['binding']['signers_sha256'] != digest(trust):
        raise ValueError('Recipient owner signer identity differs')
    manifest = blob(pack, files['docs/witness-manifest.json']['sha256'])
    sig = blob(pack, files['docs/witness-manifest.json.sig']['sha256'])
    with tempfile.TemporaryDirectory(prefix='sokol-pack-owner-') as directory:
        paths = [Path(directory).resolve() / n for n in ('manifest', 'signature', 'signers')]
        for path, value in zip(paths, (manifest, sig, trust)):
            path.write_bytes(value)
        if not pin.verify_manifest(*paths):
            raise ValueError('Owner signature invalid')
    signed = document(manifest)
    contract = document(blob(pack, files['docs/contracts/OPERATOR-R1.shadow.json']['sha256']))
    if contract['statement'] != body['statement'] or sorted(contract['witnesses']) != sorted(worker.WITNESSES):
        raise ValueError('Contract statement or witness set differs')
    pinned_row = signed['rows']['OPERATOR-R1']
    if (pin.sha(' '.join(contract['statement'].split())) != pinned_row['statement']
            or sorted(worker.WITNESSES) != pinned_row['witnesses']):
        raise ValueError('Contract statement differs from owner pin')
    with tempfile.TemporaryDirectory(prefix='sokol-pack-contract-') as directory:
        private = Path(directory).resolve()
        path = private / 'docs/contracts/OPERATOR-R1.shadow.json'
        path.parent.mkdir(parents=True)
        path.write_bytes(blob(pack, files['docs/contracts/OPERATOR-R1.shadow.json']['sha256']))
        if pin.contract_pins(private)['OPERATOR-R1'] != signed['contracts']['OPERATOR-R1']:
            raise ValueError('Contract history differs from owner pin')
    locations = pin.rust_witness_hashes(source, worker.CASE_FILE, set(worker.WITNESSES))
    for name in worker.WITNESSES:
        if sorted(locations.get(name, [])) != signed['witnesses'].get(name):
            raise ValueError('Witness differs from owner pin: ' + name)
    verify_owner_closure(pack, files, trust)
    return body


def verify_owner_closure(pack, files, trust):
    """Use the recipient's gate at its public CLI, with only received DATA around it.

    Test attributes/helpers and build.rs can change a witness without changing
    its body. The existing signed gate already owns those rules; do not invent
    a weaker second normalizer here or import the producer's gate module.
    """
    with tempfile.TemporaryDirectory(prefix='sokol-recipient-owner-gate-') as directory:
        root = Path(directory).resolve()
        source = root / 'source'
        source.mkdir()
        for name, entry in files.items():
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob(pack, entry['sha256']))
            target.chmod(0o755 if entry['executable'] else 0o644)
        gate = source / 'scripts/witness-pin.py'
        gate.write_bytes(read(ROOT / 'scripts/witness-pin.py'))
        signers = root / 'recipient-signers'
        signers.write_bytes(trust)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_ATTR_NOSYSTEM': '1'}
        for argv in (['git', 'init', '--template=', '-q'], ['git', 'add', '-f', '--', *files]):
            code, _ = inputs.run_bounded(source, argv, timeout=30, env=env)
            if code:
                raise ValueError('Cannot index received source data')
        code, output = inputs.run_bounded(source, [shutil.which('python3'), str(gate), 'check',
                                                   '--signers', str(signers)], timeout=120, env=env)
        if code:
            raise ValueError('Recipient owner gate refused witness closure/build: '
                             + output[-2048:].decode('utf-8', 'replace'))


def inspect(pack, binary, signers):
    pack = Path(pack).resolve(strict=True)
    records = inventory(pack)
    manifest = document(read(pack / 'manifest.json'))
    if (set(manifest) != {'evidence_pack', 'profile', 'subject', 'proposal', 'root', 'records', 'ski_checks'}
            or manifest['evidence_pack'] != '0' or manifest['profile'] != PROFILE
            or manifest['root'] != manifest['proposal'] or manifest['ski_checks'] != []
            or manifest['records'] != [wid for wid, _ in records]):
        raise ValueError('Unsupported pack manifest')
    desc = document(blob(pack, manifest['subject']))
    body = validate_descriptor(pack, desc, signers)
    ids = {wid for wid, _ in records}
    if manifest['proposal'] not in ids:
        raise ValueError('Proposal is missing')
    for wid, envelope in records:
        record = envelope['body']
        if (len(envelope['sigs']) > 4 or len(record['because']) > 4 or len(record['evidence']) > 32
                or len(record['prior']) > 2 or len(record['actor']['id']) > 200):
            raise ValueError('Record collection exceeds pilot budget')
        if (record['decision'] != 'propose' or record['subject']['hash'] != manifest['subject']
                or record['under'] != [desc['policy']]
                or any(r.get('runtime') not in (None, 'cmd@v1') for r in record['because'])):
            raise ValueError('Record outside experimental reproduction profile')
        if wid == manifest['proposal'] and record['prior']:
            raise ValueError('Proposal must be this pack root')
        if wid != manifest['proposal'] and manifest['proposal'] not in record['prior']:
            raise ValueError('Observation must answer proposal')
    code, raw = warrant(binary, pack, ['verify', '--json'])
    report = document(raw)
    if (code != 0 or report.get('report') != 'warrant.verify-report@v0' or report.get('grade') != 'base'
            or report.get('ok') is not True or report.get('errors') != 0 or report.get('records') != len(records)
            or report.get('warnings') != sum(f['level'] == 'WARN' for f in report.get('findings', []))):
        raise ValueError('Warrant verification failed or report is inconsistent')
    return manifest, desc, body, records, report


def file_record(pack, binary, subject, actor, key, evidence, prior=None, execution=None, respond_to=None):
    (pack / '.warrants/records').mkdir(parents=True, exist_ok=True)
    args = ['propose', '--subject', subject, '--under', digest(encode(POLICY)),
            '--actor', actor, '--key', str(Path(key).resolve())]
    for value in evidence:
        args += ['--evidence', value]
    if prior:
        args += ['--prior', prior]
    if respond_to:
        args += ['--prior', hash_name(respond_to)]
    if execution:
        if execution['status'] in ('REFUSED', 'SOURCE_MISMATCH'):
            args += ['--reason', 'Native check UNVERIFIED: ' + execution['status'] + '; no test verdict claimed.']
        else:
            args += ['--check', put(pack, read(ROOT / 'scripts/counterexample_worker.py')),
                 '--runtime', 'cmd@v1', '--verdict', 'pass' if execution['status'] == 'REPRODUCED' else 'fail',
                 '--transcript', execution['native_transcript']]
    else:
        args += ['--reason', 'Proposal to reproduce a scoped counterfactual; no execution or acceptance claimed.']
    code, out = warrant(binary, pack, args)
    if code:
        raise ValueError('Cannot file Warrant: ' + out.decode('utf-8', 'replace'))
    return hash_name(out.decode().strip())


def export(pack, binary, actor, key, signers):
    pack = Path(pack).absolute()
    if pack.exists():
        raise ValueError('Output must not exist')
    context, files = inputs.prepare(ROOT, 'OPERATOR-R1', str(signers))
    with tempfile.TemporaryDirectory(prefix='sokol-pack-export-') as directory:
        scratch = Path(directory).resolve()
        for name, entry in files.items():
            safe_source(name)
            value = inputs.read(ROOT / name)
            if digest(value) != entry['sha256']:
                raise ValueError('Source moved during export')
            put(scratch, value)
        put(scratch, encode(POLICY))
        source = inputs.read(ROOT / worker.CASE_FILE).decode()
        if source.count(worker.BEFORE) != 1:
            raise ValueError('Defect anchor differs')
        defect = {**files, worker.CASE_FILE: {**files[worker.CASE_FILE],
                   'sha256': digest(source.replace(worker.BEFORE, worker.AFTER).encode())}}
        desc = {'profile': PROFILE, 'case': CASE, 'contract_context': put(scratch, inputs.encode(context)),
                'files': files, 'repair_snapshot': digest(encode(files)),
                'defect_snapshot': digest(encode(defect)), 'policy': digest(encode(POLICY)),
                'defect_origin': 'DERIVED_COUNTERFACTUAL_NOT_HISTORICAL_COMMIT',
                'worker_sha256': digest(read(ROOT / 'scripts/counterexample_worker.py'))}
        subject = put(scratch, encode(desc))
        proposal = file_record(scratch, binary, subject, actor, key, [desc['contract_context']])
        (scratch / 'manifest.json').write_bytes(encode({'evidence_pack': '0', 'profile': PROFILE,
             'subject': subject, 'proposal': proposal, 'root': proposal, 'records': [proposal], 'ski_checks': []}))
        inspect(scratch, binary, signers)
        if inputs.checkout(ROOT) != files:
            raise ValueError('Source moved during export')
        shutil.copytree(scratch, pack)
    return {'pack': str(pack), 'proposal': proposal, 'subject': subject, 'execution': 'NOT_RUN'}


def public_registry(path):
    """Select only public crate bytes, never Cargo credentials/config/cache tools."""
    path = Path(path).resolve(strict=True)
    entries, total = [], 0
    for item in sorted(path.rglob('*')):
        if item.is_symlink():
            raise ValueError('Registry symlink refused')
        if not item.is_file():
            continue
        total += item.stat().st_size
        if len(entries) >= MAX_REGISTRY_FILES or total > MAX_REGISTRY_BYTES:
            raise ValueError('Registry exceeds input budget')
        entries.append([item.relative_to(path).as_posix(), file_digest(item)])
    return {'sha256': digest(encode(entries)), 'files': len(entries), 'bytes': total}


def file_digest(path):
    if not stat.S_ISREG(path.stat().st_mode) or path.is_symlink():
        raise ValueError('Non-regular public tool input')
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def toolchain_identity(path):
    # Shared compiler libraries and Rust sysroot are inputs too, not merely the
    # tiny rustc launcher. The complete selected toolchain is mounted read-only.
    return public_registry(path)


def registry_layout(path):
    # A global Cargo home can also cache private registries. Refuse those rather
    # than exposing their sources merely because the caller selected "registry".
    for item in path.iterdir():
        if item.name == 'CACHEDIR.TAG' and item.is_file():
            continue
        if item.name not in ('src', 'cache', 'index') or not item.is_dir():
            raise ValueError('Only crates.io public registry inputs are admitted')
        for registry in item.iterdir():
            if not re.fullmatch(r'index\.crates\.io-[0-9a-f]{16}', registry.name) or not registry.is_dir():
                raise ValueError('Private or unsupported Cargo registry refused')


def sandbox(source, toolchain, registry, worker_path, unit=None, defect=None):
    # Every argument is recipient-owned; nothing from the manifest becomes argv.
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
            '--cap-drop', 'ALL', '--clearenv', '--ro-bind', '/usr', '/usr',
            '--ro-bind', '/lib', '/lib', '--ro-bind-try', '/lib64', '/lib64',
            '--symlink', 'usr/bin', '/bin', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
            '--ro-bind', '/etc/ld.so.cache', '/etc/ld.so.cache',
            '--proc', '/proc', '--dev', '/dev', '--ro-bind', str(source), '/source',
            '--ro-bind', str(defect or source), '/defect',
            '--ro-bind', str(toolchain), '/toolchain', '--ro-bind', str(worker_path), '/runner.py',
            '--size', str(SCRATCH_BYTES), '--tmpfs', '/target',
            '--size', str(128 * 1024 * 1024), '--tmpfs', '/tmp',
            '--size', str(32 * 1024 * 1024), '--tmpfs', '/cargo',
            '--ro-bind', str(registry), '/cargo/registry',
            '--setenv', 'PATH', '/toolchain/bin:/usr/bin:/bin', '--setenv', 'HOME', '/tmp',
            '--setenv', 'CARGO_HOME', '/cargo', '--setenv', 'CARGO_TARGET_DIR', '/target',
            '--setenv', 'CARGO_BUILD_JOBS', '2', '--setenv', 'RUSTFLAGS', '-C debuginfo=0',
            '--setenv', 'SOKOL_BUILD_ID', 'counterexample-isolated',
            '--chdir', '/source', '/usr/bin/python3', '/runner.py']
    return ['/usr/bin/systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect',
            *(['--unit', unit] if unit else []),
            '--service-type=exec', '-p', f'MemoryMax={MEMORY_BYTES}', '-p', f'TasksMax={MAX_TASKS}',
            '-p', f'RuntimeMaxSec={TOTAL_SECONDS}', '-p', 'KillMode=control-group', *argv]


def isolated_run(source, toolchain, registry, runner, defect=None):
    unit = 'sokol-counterexample-' + uuid.uuid4().hex
    try:
        return inputs.run_bounded(source, sandbox(source, toolchain, registry, runner, unit, defect),
                                   TOTAL_SECONDS + 15, MAX_BLOB)
    finally:
        # Killing the systemd-run client alone does not cancel its service. Stop
        # this exact randomly named cgroup also on output/parent deadline faults.
        subprocess.run(['/usr/bin/systemctl', '--user', 'stop', unit + '.service'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)


def evaluate(execution, descriptor=None):
    if set(execution) != {'profile', 'phases'} or execution['profile'] != 'sokol.counterexample-execution.v1':
        return 'REFUSED'
    phases = execution['phases']
    if not isinstance(phases, list) or [p.get('phase') for p in phases] != ['repair', 'defect', 'restored']:
        return 'REFUSED'
    for phase in phases:
        if descriptor:
            expected_snapshot = descriptor['defect_snapshot'] if phase['phase'] == 'defect' else descriptor['repair_snapshot']
            if phase.get('snapshot') != expected_snapshot:
                return 'SOURCE_MISMATCH'
        if phase['build']['status'] != 'BUILT' or phase['build']['returncode'] != 0:
            return 'BUILD_ERROR'
        rows = phase['witnesses']
        expected = [worker.FOCUS] if phase['phase'] == 'defect' else list(worker.WITNESSES)
        if [r['witness'] for r in rows] != expected:
            return 'INCOMPLETE'
        defect = phase['phase'] == 'defect'
        for row in rows:
            actual = worker.classify(row['returncode'], row['output'], row['witness'], defect)
            if row['status'] != actual or actual != ('ASSERTION_RED' if defect else 'PASS'):
                return 'NOT_REPRODUCED'
    return 'REPRODUCED'


def worker_report(raw, code):
    frames = [line[len(worker.FRAME):] for line in raw.decode('utf-8').splitlines()
              if line.startswith(worker.FRAME)]
    if len(frames) != 1:
        raise ValueError('ISOLATION_OR_RESOURCE_REFUSAL: missing or ambiguous worker frame')
    execution = document(frames[0])
    status = evaluate(execution)
    expected_code = 0 if status == 'REPRODUCED' else 3 if status == 'REFUSED' else 1
    if code != expected_code:
        raise ValueError('Worker exit status contradicts its measured execution')
    return execution


def replay(pack, output, binary, signers, actor, key, toolchain, registry, respond_to=None):
    if platform.system() != 'Linux' or os.geteuid() == 0:
        raise ValueError('Linux non-root isolated worker required')
    pack = Path(pack).resolve(strict=True)
    output = Path(output).absolute()
    if output.exists():
        raise ValueError('Output must not exist')
    if output.resolve().is_relative_to(pack):
        raise ValueError('Output must be outside the received pack')
    manifest, desc, _, records, _ = inspect(pack, binary, signers)
    if respond_to and (respond_to == manifest['proposal'] or respond_to not in {wid for wid, _ in records}):
        raise ValueError('Response must name a record already in the inspected pack')
    toolchain = Path(toolchain).resolve(strict=True)
    registry = Path(registry).resolve(strict=True)
    registry_layout(registry)
    external = public_registry(registry)
    tools = toolchain_identity(toolchain)
    method = {name: digest(read(ROOT / name)) for name in
              ('scripts/counterexample_worker.py', 'scripts/counterexample-task.py',
               'scripts/contract-task.py', 'scripts/witness-pin.py')}
    with tempfile.TemporaryDirectory(prefix='sokol-recipient-') as directory:
        source = Path(directory).resolve() / 'source'
        source.mkdir()
        for name, entry in desc['files'].items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob(Path(pack), entry['sha256']))
            path.chmod(0o755 if entry['executable'] else 0o644)
        defect = Path(directory).resolve() / 'defect'
        shutil.copytree(source, defect)
        mutant_path = defect / worker.CASE_FILE
        mutant_path.write_bytes(mutant_path.read_bytes().decode().replace(worker.BEFORE, worker.AFTER).encode())
        # Freeze the trusted local method before exposing it read-only to the worker.
        runner = Path(directory).resolve() / 'worker.py'
        runner.write_bytes(read(ROOT / 'scripts/counterexample_worker.py'))
        code, raw = isolated_run(source, toolchain, registry, runner, defect)
        execution = worker_report(raw, code)
        status = evaluate(execution, desc)
        if public_registry(registry) != external or toolchain_identity(toolchain) != tools:
            raise ValueError('External inputs moved during replay')
        if any(digest(read(ROOT / name)) != value for name, value in method.items()):
            raise ValueError('Local method moved during replay')
        # Incoming bytes may have moved while native code ran. Never sign observations
        # against another pack than the one this recipient actually inspected.
        current, current_desc, _, _, _ = inspect(pack, binary, signers)
        if current != manifest or current_desc != desc:
            raise ValueError('Pack moved during replay')
        report = {'profile': 'sokol.counterexample-observation.v1', 'subject': manifest['subject'],
                  'status': status, 'execution': execution, 'method': method,
                  'native_transcript': digest(raw), 'native_returncode': code,
                  'recipient_verifier_sha256': digest(read(binary)), 'toolchain': tools,
                  'registry': external, 'system': {'machine': platform.machine(), 'kernel': platform.release()},
                  'budget': {'seconds': TOTAL_SECONDS, 'memory_bytes': MEMORY_BYTES,
                             'target_bytes': SCRATCH_BYTES, 'tasks': MAX_TASKS, 'output_bytes': MAX_BLOB},
                  'authority': 'EXPERIMENTAL_OBSERVATION_NOT_OWNER_ACCEPTANCE',
                  'independence': 'FRESH_PROCESS_NOT_INDEPENDENT_MODEL_REVIEW'}
        staged = Path(directory).resolve() / 'pack'
        shutil.copytree(pack, staged)
        put(staged, raw)
        report_hash = put(staged, encode(report))
        observation = file_record(staged, binary, manifest['subject'], actor, key,
                                  [report_hash], manifest['proposal'], report, respond_to)
        updated_manifest = {**manifest, 'records': sorted([*manifest['records'], observation])}
        (staged / 'manifest.json').write_bytes(encode(updated_manifest))
        inspect(staged, binary, signers)
        shutil.copytree(staged, output)
    return {'pack': str(output), 'observation': observation, 'status': status,
            'report_sha256': report_hash, 'execution': 'FRESH_LOCAL_RUN'}


def view(pack, binary, signers):
    pack = Path(pack).resolve(strict=True)
    manifest, desc, body, records, verification = inspect(pack, binary, signers)
    observations = []
    for wid, env in records:
        for address in sorted(set(env['body']['evidence'])):
            try:
                report = document(blob(pack, address))
            except (ValueError, UnicodeError):
                continue
            if isinstance(report, dict) and report.get('profile') == 'sokol.counterexample-observation.v1':
                if report.get('subject') != manifest['subject']:
                    raise ValueError('Observation transcript is not bound to this subject/evidence')
                if report['status'] != evaluate(report['execution'], desc):
                    raise ValueError('Recorded status contradicts transcript')
                raw = blob(pack, report['native_transcript'])
                if worker_report(raw, report['native_returncode']) != report['execution']:
                    raise ValueError('Observation differs from native transcript')
                if report['status'] not in ('REFUSED', 'SOURCE_MISMATCH'):
                    matching = [r for r in env['body']['because'] if r.get('runtime') == 'cmd@v1'
                                and r.get('check') == desc['worker_sha256']
                                and r.get('transcript') == report['native_transcript']
                                and r.get('verdict') == ('pass' if report['native_returncode'] == 0 else 'fail')]
                    if len(matching) != 1:
                        raise ValueError('Native check reason/exit/transcript differs')
                observations.append({'warrant': wid, 'actor': env['body']['actor']['id'],
                                     'claimed_status': report['status'], 'execution': 'RECORDED_NOT_REPLAYED',
                                     'method': report.get('method', {'status': 'NOT_RECORDED'}),
                                     'budget': report.get('budget', {'status': 'NOT_RECORDED'}),
                                     'toolchain': report.get('toolchain', {'status': 'NOT_RECORDED'}),
                                     'registry': report.get('registry', {'status': 'NOT_RECORDED'}),
                                     'transcript': report['native_transcript'], 'observation': address})
    return {'profile': 'sokol.counterexample-view.v1', 'subject': manifest['subject'],
            'proposal': manifest['proposal'], 'claim': 'An applied command with a lost reply is reported UNKNOWN, not NOT_SENT.',
            'contract_statement': body['statement'], 'case': CASE,
            'repair_snapshot': desc['repair_snapshot'], 'defect_snapshot': desc['defect_snapshot'],
            'defect_origin': desc['defect_origin'], 'owner_witness_binding': 'VERIFIED_AGAINST_RECIPIENT_SIGNERS',
            'warrant_findings': verification['findings'], 'observations': observations[:MAX_VIEW_OBSERVATIONS],
            'observations_total': len(observations),
            'projection_partial': len(observations) > MAX_VIEW_OBSERVATIONS,
            'comparison': ('RECORDED_DISAGREEMENT' if len({r['claimed_status'] for r in observations}) > 1
                           else 'RECORDED_AGREEMENT_NOT_SETTLEMENT' if len(observations) > 1 else 'NOT_COMPARED'),
            'limits': ['Imported signatures/reports do not establish past execution or actor identity.',
                       'Owner pins bind contract history and witness bodies, not approval of every source byte or helper adequacy.',
                       'Native cmd@v1 is replayed only by this recipient-selected isolated runner.',
                       'No settlement, owner acceptance, kernel effect or deployment authority.']}


def markdown(value):
    lines = ['# Scoped counterexample', '', value['claim'], '',
             f"Subject: `{value['subject']}`", f"Repair: `{value['repair_snapshot']}`",
             f"Defect: `{value['defect_snapshot']}` ({value['defect_origin']})", '',
             f"Comparison: {value['comparison']}; observations: {value['observations_total']}"
             + (' (partial projection)' if value['projection_partial'] else ''), '',
             '| Actor (claimed) | Observation (claimed) | Execution |', '|---|---|---|']
    for row in value['observations']:
        # JSON-quote untrusted prose and strip table/HTML syntax in the human projection.
        actor = json.dumps(row['actor'], ensure_ascii=True).replace('|', '\\u007c').replace('<', '\\u003c')
        lines.append(f"| {actor} | {row['claimed_status']} | {row['execution']} |")
    lines += ['', *('- ' + limit for limit in value['limits'])]
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('export', 'inspect', 'replay', 'view'))
    parser.add_argument('pack', type=Path)
    parser.add_argument('--warrant', required=True, type=Path)
    parser.add_argument('--warrant-sha256', required=True, help='Recipient-selected verifier digest; never read from pack')
    parser.add_argument('--signers', type=Path, default=ROOT / '.github/witness-signers')
    parser.add_argument('--actor')
    parser.add_argument('--key', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--toolchain', type=Path)
    parser.add_argument('--registry', type=Path)
    parser.add_argument('--respond-to', help='Optional prior observation in this pack to answer')
    parser.add_argument('--markdown', action='store_true')
    args = parser.parse_args()
    try:
        binary = selected_verifier(args.warrant, args.warrant_sha256)
        if args.action in ('export', 'replay') and (not args.actor or not args.key):
            raise ValueError('A caller-selected actor and signing key are required')
        if args.action == 'export':
            value = export(args.pack, binary, args.actor, args.key, args.signers)
        elif args.action == 'replay':
            if not all((args.output, args.toolchain, args.registry)):
                raise ValueError('Replay requires output, toolchain and public registry paths')
            value = replay(args.pack, args.output, binary, args.signers, args.actor,
                           args.key, args.toolchain, args.registry, args.respond_to)
        elif args.action == 'inspect':
            manifest, _, _, _, report = inspect(args.pack, binary, args.signers)
            value = {'subject': manifest['subject'], 'verification': report, 'execution': 'NOT_RUN'}
        else:
            value = view(args.pack, binary, args.signers)
        print(markdown(value) if args.markdown and args.action == 'view' else encode(value).decode())
        return 0 if value.get('status', 'REPRODUCED') == 'REPRODUCED' else 1
    except (ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError,
            UnicodeError, subprocess.TimeoutExpired) as error:
        print(encode({'status': 'REFUSED', 'reason': str(error), 'execution': 'NOT_ESTABLISHED'}).decode())
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
