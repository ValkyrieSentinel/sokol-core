#!/usr/bin/env python3
"""The only way to change an invariant row (ADR-0024).

    contract.py regenerate
        Render every contract-backed row of docs/INVARIANTS.md from docs/contracts/<ID>.shadow.json.
    contract.py propose <ID> --because TEXT [--statement S] [--witness NAME]... [--after ID]
        Record an unsigned intent in docs/contracts/proposals/. Nothing it says is accepted.
        --after places a new invariant's row after an existing one.
    contract.py accept <PROPOSAL-FILE> [--key OWNER_KEY]
        Apply an intent to its contract if the contract is still the one the intent was made
        against, append the decision to the contract's history, regenerate, and with --key
        re-pin through scripts/witness-pin.py sign. Without the owner's signature the gate
        refuses the change, so accepting is the owner's act, not the proposer's.
    contract.py list
        Open proposals.

A proposal names the reason (a counterexample, a measurement, a requirement). The gate reads
the contract, never the proposal; an open proposal is reported as a note.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / 'docs/contracts'
PROPOSALS = CONTRACTS / 'proposals'
INVARIANTS = ROOT / 'docs/INVARIANTS.md'
PROFILE = 'sokol.contract-shadow.v1'
PROPOSAL_PROFILE = 'sokol.contract-proposal.v1'

spec = importlib.util.spec_from_file_location('witness_pin', ROOT / 'scripts/witness-pin.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dump(value) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + '\n'


def contract_path(rid: str) -> pathlib.Path:
    gate.contract_marker(rid)
    return CONTRACTS / f'{rid}.shadow.json'


def render(text: str, contracts: dict) -> str:
    if gate.DECLARATION in text:
        lines = text.splitlines(keepends=True)
        for i, line in enumerate(lines):
            m = gate.ROW.match(line)
            if m and m.group(1) in contracts:
                lines[i] = gate.contract_row(contracts[m.group(1)]) + '\n'
        text = ''.join(lines)
    else:
        for contract in contracts.values():
            text = gate.project_invariants(text, contract)
    return gate.generated_invariants(text, ROOT)


def regenerate() -> int:
    before = INVARIANTS.read_text()
    after = render(before, gate.load_contracts(ROOT))
    if after != before:
        INVARIANTS.write_text(after)
    print(f"{'regenerated' if after != before else 'unchanged'} {INVARIANTS.relative_to(ROOT)}")
    return 0


def witnesses_exist(names: list[str]) -> list[str]:
    rust = gate.rust_bodies({n for n in names if gate.RUST_TEST.fullmatch(n)})
    py = gate.py_bodies({n for n in names if gate.PY_TEST.fullmatch(n)})
    return [n for n in names if not (rust.get(n) or py.get(n))]


def propose(rid: str, because: str, statement: str | None, witnesses: list[str], after: str | None) -> int:
    path = contract_path(rid)
    current = json.loads(path.read_text()) if path.exists() else None
    if current is None and not (statement and witnesses and after):
        print('FAIL a new invariant needs --statement, at least one --witness and --after')
        return 1
    if current is not None and after:
        print('FAIL --after places a new row; ' + rid + ' already has one')
        return 1
    if after and not any(line.startswith('| ' + after + ' |') for line in INVARIANTS.read_text().splitlines()):
        print('FAIL --after ' + after + ' is not a row of ' + str(INVARIANTS.relative_to(ROOT)))
        return 1
    if not because.strip():
        print('FAIL a proposal names its reason (--because)')
        return 1
    names = sorted(set(witnesses)) if witnesses else current['witnesses']
    bad = [n for n in names if not (gate.RUST_TEST.fullmatch(n) or gate.PY_TEST.fullmatch(n))]
    missing = witnesses_exist(names)
    if bad or missing:
        print('FAIL witnesses must be existing tests: ' + ', '.join(bad + missing))
        return 1
    if current and set(current['witnesses']) <= set(names):
        added = [n for n in names if n not in current['witnesses']]
        evidence = ', '.join([current['evidence_text'].rstrip('. ')] + [f'`{n}`' for n in added]) \
            if added else current['evidence_text']
    else:
        evidence = ', '.join(f'`{n}`' for n in names)
    body = {
        'profile': PROPOSAL_PROFILE, 'id': rid, 'status': 'UNSIGNED_INTENT', 'because': because.strip(),
        'base_contract_sha256': sha(path.read_bytes()) if current else None,
        'statement': statement if statement is not None else current['statement'],
        'evidence_text': evidence, 'witnesses': names, 'after': after,
    }
    gate.contract_row({'id': rid, 'profile': PROFILE, **{k: body[k] for k in ('statement', 'evidence_text')}})
    PROPOSALS.mkdir(parents=True, exist_ok=True)
    data = dump(body).encode()
    out = PROPOSALS / f'{rid}-{sha(data)[:12]}.proposal.json'
    out.write_bytes(data)
    print(out.relative_to(ROOT))
    return 0


def accept(file: str, key: str | None) -> int:
    ppath = pathlib.Path(file).resolve()
    if ppath.parent != PROPOSALS.resolve() or not ppath.name.endswith('.proposal.json'):
        print('FAIL a proposal is a file in docs/contracts/proposals/')
        return 1
    data = ppath.read_bytes()
    p = json.loads(data)
    if p.get('profile') != PROPOSAL_PROFILE:
        print('FAIL not a contract proposal')
        return 1
    path = contract_path(p['id'])
    base = sha(path.read_bytes()) if path.exists() else None
    if base != p['base_contract_sha256']:
        print('FAIL stale proposal: the contract changed after it was made; propose again')
        return 1
    contract = json.loads(path.read_text()) if path.exists() else {
        'profile': PROFILE, 'id': p['id'],
        'annotations': {'status': 'UNSIGNED_EXPLANATORY_DRAFT'}}
    contract.setdefault('decisions', []).append({
        'proposal_sha256': sha(data), 'because': p['because'],
        'previous_statement_sha256': sha(contract['statement'].encode()) if 'statement' in contract else None,
    })
    contract.update({k: p[k] for k in ('statement', 'evidence_text', 'witnesses')})
    text = INVARIANTS.read_text()
    if p['after']:
        lines = text.splitlines(keepends=True)
        at = [i for i, line in enumerate(lines) if line.startswith('| ' + p['after'] + ' |')]
        if len(at) != 1 or gate.DECLARATION not in text:
            print('FAIL --after needs exactly one existing row in a fully generated document')
            return 1
        lines.insert(at[0] + 1, gate.contract_row(contract) + '\n')
        text = ''.join(lines)
    path.write_text(dump(contract))
    INVARIANTS.write_text(render(text, gate.load_contracts(ROOT)))
    ppath.unlink()
    print(f"accepted {p['id']}: contract, history and {INVARIANTS.relative_to(ROOT)} updated")
    if key:
        return subprocess.run([sys.executable, str(ROOT / 'scripts/witness-pin.py'), 'sign', '--key', key]).returncode
    print('not signed: the gate refuses this change until the owner runs scripts/witness-pin.py sign')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('regenerate')
    sub.add_parser('list')
    pp = sub.add_parser('propose')
    pp.add_argument('id')
    pp.add_argument('--because', required=True)
    pp.add_argument('--statement')
    pp.add_argument('--witness', action='append', default=[])
    pp.add_argument('--after')
    pa = sub.add_parser('accept')
    pa.add_argument('proposal')
    pa.add_argument('--key')
    a = parser.parse_args()
    try:
        if a.command == 'regenerate':
            return regenerate()
        if a.command == 'list':
            for name in gate.open_proposals(ROOT):
                print(name)
            return 0
        if a.command == 'propose':
            return propose(a.id, a.because, a.statement, a.witness, a.after)
        return accept(a.proposal, a.key)
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print('FAIL', error)
        return 1


if __name__ == '__main__':
    sys.exit(main())
