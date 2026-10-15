#!/usr/bin/env python3
"""Build/verify/install/remove a complete, bounded candidate. No service is started.

Consumers select the expected archive SHA256 independently. Integrity is not owner
admission, provenance authentication or hardware qualification. Python stdlib only
for consumers; only the producer needs Cargo and the source checkout.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_FILES = 512
MAX_META = 1_048_576
PREFIXES = ('usr/local/bin/', 'usr/local/share/sokol/', 'etc/systemd/system/')
METADATA = {'candidate.json', 'SBOM.spdx.json', 'build-inputs.json', 'SHA256SUMS'}


def encode(value):
    return json.dumps(value, sort_keys=True, indent=2).encode() + b'\n'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bounded(path, limit=MAX_FILE):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Non-regular input: ' + str(path))
    with path.open('rb') as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Oversized input: ' + str(path))
    return data


def name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', value):
        raise ValueError('Unsafe member path')
    p = PurePosixPath(value)
    if not isinstance(value, str) or p.is_absolute() or str(p) != value or '..' in p.parts or '\\' in value or not p.parts:
        raise ValueError('Unsafe member path')
    return value


def arch():
    result = {'x86_64': 'x86_64', 'aarch64': 'aarch64', 'arm64': 'aarch64'}.get(platform.machine())
    if result is None:
        raise ValueError('Unsupported architecture')
    return result


def command(argv, cwd=ROOT):
    result = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if result.returncode or len(result.stdout) > 8 * MAX_META:
        raise ValueError('Producer command refused: ' + ' '.join(argv) + ': ' + result.stderr[-1024:].decode(errors='replace'))
    return result.stdout


def sbom(commit):
    packages = {}
    for directory in (ROOT, ROOT / 'ebpf'):
        metadata = json.loads(command(['cargo', 'metadata', '--locked', '--offline', '--format-version', '1'], cwd=directory))
        for p in metadata['packages']:
            identity = (p['name'], p['version'], p['source'] or 'workspace')
            pid = 'SPDXRef-' + sha(encode(identity))[:24]
            packages[pid] = {'SPDXID': pid, 'name': p['name'], 'versionInfo': p['version'],
                             'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False,
                             'licenseDeclared': p['license'] or 'NOASSERTION',
                             'licenseConcluded': 'NOASSERTION', 'copyrightText': 'NOASSERTION'}
    created = command(['git', 'show', '-s', '--format=%cI', commit]).decode().strip()
    from datetime import datetime, timezone
    created = datetime.fromisoformat(created).astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    return {'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
            'name': 'sokol-core-build-graph',
            'documentNamespace': 'https://github.com/s0fractal/sokol-core/sbom/' + commit + '/' + arch(),
            'creationInfo': {'creators': ['Tool: sokol-candidate'], 'created': created},
            'documentComment': 'Union of resolved Cargo metadata graphs, not measured symbol-level binary dependencies.',
            'packages': [packages[k] for k in sorted(packages)],
            'relationships': [{'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES',
                               'relatedSpdxElement': k} for k in sorted(packages)]}


def build(binaries, output):
    if command(['git', 'status', '--porcelain', '--untracked-files=no']).strip():
        raise ValueError('Candidate build requires a clean committed source tree')
    commit = command(['git', 'rev-parse', 'HEAD']).decode().strip()
    version = command([str(binaries.resolve() / 'orchestrator'), '--version']).decode().strip()
    if not version.endswith('(build ' + commit[:12] + ')'):
        raise ValueError('Orchestrator build identity differs from clean source commit')
    inventory = json.loads(bounded(ROOT / 'deploy/candidate.json', MAX_META))
    if inventory['profile'] != 'sokol.product-inventory.v1':
        raise ValueError('Unsupported product inventory')
    payload, modes = {}, {}
    for row in inventory['files']:
        dest = name(row['path'])
        if not dest.startswith(PREFIXES) or dest in payload or row['mode'] not in (0o644, 0o755):
            raise ValueError('Invalid product inventory entry')
        source = row['source']
        path = binaries / source[7:] if source.startswith('binary:') else ROOT / name(source)
        payload[dest], modes[dest] = bounded(path), row['mode']
    if len(payload) > MAX_FILES - len(METADATA) or sum(map(len, payload.values())) > MAX_ARCHIVE:
        raise ValueError('Product exceeds budget')
    payload['SBOM.spdx.json'] = encode(sbom(commit))
    payload['build-inputs.json'] = encode({
        'profile': 'sokol.build-inputs.v1', 'source_commit': commit,
        'rustc': command(['rustc', '-Vv']).decode(), 'cargo': command(['cargo', '-V']).decode(),
        'kernel': platform.release(), 'architecture': arch(),
        'locks': {p: sha(bounded(ROOT / p)) for p in ('Cargo.lock', 'ebpf/Cargo.lock')},
        'authority': 'UNSIGNED_BUILDER_RECORD', 'reproducible_binary_comparison': 'NOT_ESTABLISHED'})
    manifest = {'profile': 'sokol.candidate.v1', 'source_commit': commit, 'architecture': arch(),
                'admission': 'NOT_ADMITTED', 'hardware': 'NOT_QUALIFIED',
                'files': {p: {'sha256': sha(data), 'mode': modes[p]} for p, data in sorted(payload.items()) if p not in METADATA}}
    for meta in ('SBOM.spdx.json', 'build-inputs.json'):
        manifest['files'][meta] = {'sha256': sha(payload[meta]), 'mode': 0o644}
        modes[meta] = 0o644
    payload['candidate.json'], modes['candidate.json'] = encode(manifest), 0o644
    payload['SHA256SUMS'] = ''.join(sha(data) + '  ' + p + '\n' for p, data in sorted(payload.items())).encode()
    modes['SHA256SUMS'] = 0o644
    if sum(map(len, payload.values())) > MAX_ARCHIVE:
        raise ValueError('Complete product exceeds budget')
    output = output.resolve()
    if output.exists():
        raise ValueError('Refusing to overwrite candidate output')
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open('xb') as raw, gzip.GzipFile(fileobj=raw, filename='', mode='wb', mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w|') as archive:
                for p, data in sorted(payload.items()):
                    info = tarfile.TarInfo(p)
                    info.size, info.mode, info.mtime = len(data), modes[p], 0
                    archive.addfile(info, io.BytesIO(data))
        digest = sha(bounded(output, MAX_ARCHIVE))
        verify(output, digest)
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return {'archive': str(output), 'sha256': digest, 'source_commit': commit, 'admission': 'NOT_ADMITTED'}


def verify(path, expected):
    if not re.fullmatch('[a-f0-9]{64}', expected):
        raise ValueError('Independently selected expected SHA256 is required')
    data = bounded(path, MAX_ARCHIVE)
    if sha(data) != expected:
        raise ValueError('Archive SHA256 mismatch')
    files, modes, size = {}, {}, 0
    # Bound decompression before tarfile can allocate a malicious PAX/GNU header.
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        unpacked = compressed.read(MAX_ARCHIVE + MAX_META + 1)
    if len(unpacked) > MAX_ARCHIVE + MAX_META:
        raise ValueError('Decompressed archive exceeds budget')
    with tarfile.open(fileobj=io.BytesIO(unpacked), mode='r:') as archive:
        for item in archive:
            p = name(item.name)
            if not item.isfile() or item.size > MAX_FILE or p in files or len(files) >= MAX_FILES or item.mode not in (0o644, 0o755):
                raise ValueError('Unsafe, duplicate or oversized archive member')
            size += item.size
            if size > MAX_ARCHIVE:
                raise ValueError('Unpacked candidate exceeds budget')
            files[p], modes[p] = archive.extractfile(item).read(), item.mode
    if not METADATA.issubset(files) or any(len(files[p]) > MAX_META for p in METADATA):
        raise ValueError('Missing or oversized candidate metadata')
    manifest = json.loads(files['candidate.json'])
    if manifest['profile'] != 'sokol.candidate.v1' or manifest['admission'] != 'NOT_ADMITTED' or manifest['hardware'] != 'NOT_QUALIFIED':
        raise ValueError('Unsupported candidate profile or invented admission')
    if not re.fullmatch('[a-f0-9]{40}', manifest['source_commit']) or manifest['architecture'] not in ('aarch64', 'x86_64'):
        raise ValueError('Invalid candidate source or architecture')
    if set(files) != set(manifest['files']) | {'candidate.json', 'SHA256SUMS'}:
        raise ValueError('Candidate inventory differs from archive')
    for p, entry in manifest['files'].items():
        name(p)
        if p not in METADATA and not p.startswith(PREFIXES):
            raise ValueError('Unsupported installation path')
        if sha(files[p]) != entry['sha256'] or modes[p] != entry['mode']:
            raise ValueError('Candidate member digest/mode mismatch')
    checks = ''.join(sha(value) + '  ' + p + '\n' for p, value in sorted(files.items()) if p != 'SHA256SUMS').encode()
    if files['SHA256SUMS'] != checks:
        raise ValueError('Candidate checksum inventory mismatch')
    json.loads(files['SBOM.spdx.json'])
    json.loads(files['build-inputs.json'])
    return manifest, files


def target(prefix, rel):
    path = prefix / name(rel)
    for part in (path, *path.parents):
        if part == prefix:
            break
        if part.is_symlink():
            raise ValueError('Symlink installation target refused: ' + str(part))
    return path


def install(archive, expected, prefix, remove=False):
    manifest, files = verify(archive, expected)
    if platform.system() != 'Linux' or manifest['architecture'] != arch():
        raise ValueError('Candidate platform mismatch')
    prefix = prefix.resolve(strict=True)
    selected = {p: e for p, e in manifest['files'].items() if p not in METADATA}
    paths = {p: target(prefix, p) for p in selected}
    # Complete preflight before touching a file, including modified-file refusal on removal.
    for p, path in paths.items():
        if path.exists() and (not path.is_file() or (remove and sha(bounded(path)) != selected[p]['sha256'])):
            raise ValueError('Modified or non-regular installed file: ' + str(path))
    for p, path in paths.items():
        if remove:
            path.unlink(missing_ok=True)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix='.sokol-install-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(files[p]); stream.flush(); os.fsync(stream.fileno())
            os.chmod(temp, selected[p]['mode'])
            os.replace(temp, path)
        finally:
            Path(temp).unlink(missing_ok=True)
    return {'status': 'REMOVED' if remove else 'INSTALLED_FILES', 'source_commit': manifest['source_commit'],
            'admission': 'NOT_ADMITTED', 'service': 'NOT_STARTED', 'state_and_configuration': 'UNTOUCHED'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('build'); p.add_argument('--binaries', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    for action in ('verify', 'install', 'remove'):
        p = sub.add_parser(action); p.add_argument('archive', type=Path); p.add_argument('--sha256', required=True)
        if action != 'verify': p.add_argument('--prefix', type=Path, default=Path('/'))
    args = parser.parse_args()
    try:
        if args.action == 'build':
            result = build(args.binaries, args.output)
        elif args.action == 'verify':
            result, _ = verify(args.archive, args.sha256)
            result = {**result, 'files': len(result['files']), 'verification': 'INTEGRITY_ONLY', 'provenance': 'NOT_AUTHENTICATED'}
        else:
            result = install(args.archive, args.sha256, args.prefix, args.action == 'remove')
        print(encode(result).decode(), end='')
        return 0
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(encode({'status': 'REFUSED', 'reason': str(error)}).decode(), end='')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
