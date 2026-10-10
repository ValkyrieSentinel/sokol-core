#!/usr/bin/env python3
"""Project one draft contract to Markdown and bounded AI JSON; never adopt or execute it."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'docs/contracts/IPC-A1.shadow.json'
INPUTS = (SOURCE, 'docs/INVARIANTS.md', 'docs/witness-manifest.json',
          'docs/witness-manifest.json.sig', '.github/witness-signers',
          'orchestrator/src/delivery.rs', 'scripts/witness-pin.py', 'scripts/contract-shadow.py')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(root, name):
    path = root / name
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Symlink input refused')
    with path.open('rb') as stream:
        data = stream.read(2_097_153)
    if len(data) > 2_097_152:
        raise ValueError('Input exceeds bound')
    return data


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def project(root, signers=None):
    inputs = {name: read(root, name) for name in INPUTS}
    contract = json.loads(inputs[SOURCE])
    if contract['profile'] != 'sokol.contract-shadow.v1' or contract['id'] != 'IPC-A1':
        raise ValueError('Unsupported pilot contract')
    a = contract['annotations']
    if a['status'] != 'UNSIGNED_EXPLANATORY_DRAFT':
        raise ValueError('Annotations must remain unsigned draft')
    if a['owner_path'] != 'orchestrator/src/delivery.rs':
        raise ValueError('Unsupported witness source')
    spec = importlib.util.spec_from_file_location('shadow_pin', root / 'scripts/witness-pin.py')
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    generated_row = checker.contract_row(contract)
    document = inputs['docs/INVARIANTS.md'].decode()
    if checker.DECLARATION in document:
        lines = document.splitlines(keepends=True)
        slots = [i for i, line in enumerate(lines) if line.startswith('| IPC-A1 |')]
        if len(slots) != 1:
            raise ValueError('Missing or ambiguous generated IPC-A1 row')
        lines[slots[0]] = generated_row + '\n'
        document = ''.join(lines)
    else:
        document = checker.project_invariants(document, contract)
    pin = json.loads(inputs['docs/witness-manifest.json'])
    trust = Path(signers).resolve() if signers else root / '.github/witness-signers'
    trust_bytes = read(trust.parent, trust.name)
    if not checker.verify_manifest(root / 'docs/witness-manifest.json',
                                   root / 'docs/witness-manifest.json.sig', trust):
        raise ValueError('Owner signature verification failed')
    row_pin = pin['rows']['IPC-A1']
    statement_hash = checker.sha(' '.join(contract['statement'].split()))
    witnesses = contract['witnesses']
    named = sorted(set(re.findall(r'`([^`]+)`', contract['evidence_text'])))
    if statement_hash != row_pin['statement'] or witnesses != row_pin['witnesses'] or named != witnesses:
        raise ValueError('Contract differs from pinned statement or witness list')
    bodies = checker.rust_witness_hashes(inputs[a['owner_path']].decode(), a['owner_path'], set(witnesses))
    for witness in witnesses:
        if not bodies.get(witness) or sorted(bodies[witness]) != pin['witnesses'][witness]:
            raise ValueError('Witness body differs from pin: ' + witness)
    hashes = {name: digest(data) for name, data in inputs.items()}
    body = {'profile': 'sokol.agent.contract-shadow.v1', 'contract': contract,
            'source_hashes': hashes, 'pinned_statement_hash': statement_hash,
            'pinned_witness_bodies': {w: pin['witnesses'][w] for w in witnesses},
            'trust': {'signers_sha256': digest(trust_bytes), 'provenance': 'CALLER_SUPPLIED' if signers else 'LOCAL_CHECKOUT'},
            'binding': {'legacy_row': 'GENERATED_FROM_CONTRACT', 'manifest_statement': 'MATCH',
                        'manifest_witness_bodies': 'MATCH', 'owner_signature': 'VERIFIED_AGAINST_SUPPLIED_SIGNERS',
                        'draft_acceptance': 'NOT_ESTABLISHED', 'annotations': 'UNSIGNED'},
            'execution': {'status': 'UNKNOWN', 'performed': 'NONE',
                          'snapshot': 'sha256:' + digest(encode(hashes)),
                          'verifier': None, 'configuration': None},
            'semantic_adequacy': 'NOT_ESTABLISHED'}
    packet = {'id': 'sha256:' + digest(encode(body)), 'body': body}
    if len(encode(packet)) > 16384:
        raise ValueError('Essential packet exceeds 16384-byte bound')
    md = '\n'.join([
        '# IPC-A1 — ' + a['question'], '', a['answer'], '',
        '**Shadow example. Explanations are unsigned; contract adoption is not established.**', '',
        '## Preserved contract', '', contract['statement'], '',
        '## What was checked while generating', '',
        '- Invariant row: GENERATED_FROM_CONTRACT.', '- Statement digest and the two witness bodies: MATCH.',
        '- Owner signature: VERIFIED against the supplied signer file. Native execution: UNKNOWN (not run).',
        '- Signer trust: caller-supplied file or local checkout; no independent authority discovery.',
        '- Adequacy of witnesses for the whole statement: NOT_ESTABLISHED.', '',
        '## Witnesses', '', *['- `' + w + '`' for w in witnesses], '',
        '## Scope and remaining questions (unsigned annotations)', '', a['scope'], '',
        a['coverage_gap'], '', *['- ' + x for x in a['non_claims']], '',
        '## Agent task (unsigned proposal)', '', a['agent_objective'], '',
        *['- ' + x for x in a['stop_conditions']], '',
        '## Legacy table projection', '',
        '| ID | Invariant and enforcement point | Executable evidence |', '|---|---|---|', generated_row, '',
        '## Provenance', '',
        'Input snapshot: `' + body['execution']['snapshot'] + '`.',
        'Packet: `' + packet['id'] + '`. Exact input digests are in IPC-A1.agent.json.',
        'The source JSON is a draft; the existing owner-signed manifest remains authoritative.', ''])
    if any(read(root, name) != data for name, data in inputs.items()) or read(trust.parent, trust.name) != trust_bytes:
        raise ValueError('Inputs moved during projection')
    return md, packet, document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--signers', type=Path, help='Trusted owner signer file; default is local checkout')
    args = parser.parse_args()
    try:
        md, packet, document = project(ROOT, args.signers)
        output = Path(tempfile.mkdtemp(prefix='sokol-contract-shadow-')).resolve()
        (output / 'IPC-A1.md').write_text(md)
        (output / 'INVARIANTS.md').write_text(document)
        (output / 'IPC-A1.agent.json').write_bytes(encode(packet) + b'\n')
        print(output)
        return 0
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'REFUSED', 'reason': str(error)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
