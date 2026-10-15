#!/usr/bin/env python3
"""Owner-pinned witnesses for docs/INVARIANTS.md (ADR-0023).

scripts/check-claims.sh shows that a cited test exists. It cannot show that the test still
tests what the row claims: a witness can be weakened under its old name and still pass.
This pins, for every invariant row, its statement, its list of witnesses and the normalized
body of each witness, in docs/witness-manifest.json signed by the owner (ssh-keygen -Y).

    witness-pin.py check [--signers FILE] [--every-pin] [--executed CARGO_TEST_LOG]
        # CI: exit 1 on an unsigned change; with --every-pin (a push to main) also on anything
        # new that is not pinned yet; with --executed also when a pinned witness did not run
        # and pass (the Rust ones in that `cargo test` log; the Python ones are run here)
    witness-pin.py sign --key PRIVATE_KEY   # owner: re-pin the current tree and sign it
    witness-pin.py sign-provisional --key AGENT_KEY
                                            # agent: pin the provisional rows (ADR-0028)
    witness-pin.py closure WITNESS          # the test items pinned with a witness
    witness-pin.py --root CANDIDATE check   # trusted checker, candidate bytes left intact
    witness-pin.py run-python               # run the pinned Python witnesses, print a log for
                                            # check --executed-python (the base workflow)

Comments and formatting do not change a body's hash; any other byte of the body does.
A witness's closure is pinned too: its attributes (#[ignore], #[cfg(..)], decorators) and every
test-only item it reaches by name, transitively (helpers, fixtures, constants, setUp). An
unchanged body whose helper stopped sending anything, or that no longer runs, is a change.
A row or witness that is new and not yet pinned is reported, not refused: it guards nothing
the owner has accepted yet. Removing or changing what is pinned is refused.
"""
from __future__ import annotations

import ast
import hashlib
import json
from itertools import islice
import pathlib
import re
import stat
import subprocess
import sys
import unicodedata

ROOT = pathlib.Path(__file__).resolve().parent.parent
INVARIANTS = ROOT / "docs/INVARIANTS.md"
MANIFEST = ROOT / "docs/witness-manifest.json"
SIGNATURE = ROOT / "docs/witness-manifest.json.sig"
PROVISIONAL = ROOT / "docs/witness-provisional.json"
PROVISIONAL_SIG = ROOT / "docs/witness-provisional.json.sig"
SIGNERS = ROOT / ".github/witness-signers"
NAMESPACE = "sokol-witness"
ROW = re.compile(r"^\| ([A-Z][A-Z0-9]*-[A-Z0-9-]+) \|")
RUST_TEST = re.compile(r"[a-z][a-z0-9]*(_[a-z0-9]+){3,}")  # the same shape check-claims.sh cites
PY_TEST = re.compile(r"(\w+)\.(test_\w+)")


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def git_files(pattern: str) -> list[pathlib.Path]:
    out = subprocess.run(["git", "ls-files", pattern], cwd=ROOT, capture_output=True, text=True, check=True)
    return [ROOT / p for p in out.stdout.split()]


MAX_CONTRACTS = 256
MAX_CONTRACT_BYTES = 2_097_152
CONTRACT_ID = re.compile(r'[A-Z][A-Z0-9]*-[A-Z0-9-]+')
GENERATED_MARKER = re.compile(
    r'^<!-- Generated ([A-Z][A-Z0-9]*-[A-Z0-9-]+) from docs/contracts/\1\.shadow\.json; '
    r'edit the contract, then regenerate\. -->$', re.M)


def contract_marker(rid: str) -> str:
    if not isinstance(rid, str) or not CONTRACT_ID.fullmatch(rid):
        raise ValueError('Invalid contract ID')
    return f'<!-- Generated {rid} from docs/contracts/{rid}.shadow.json; edit the contract, then regenerate. -->'


def contract_row(contract: dict) -> str:
    """Public legacy table projection; the signed statement hash format stays unchanged."""
    rid = contract['id']
    contract_marker(rid)
    if contract['profile'] != 'sokol.contract-shadow.v1':
        raise ValueError('Unsupported contract profile')
    for field in ('statement', 'evidence_text'):
        if not isinstance(contract[field], str) or any(c in contract[field] for c in '\n\r|'):
            raise ValueError('Invalid contract table cell')
    marker = '[provisional] ' if contract.get('tier') == 'provisional' else ''
    return '| ' + rid + ' | ' + marker + contract['statement'] + ' | ' + contract['evidence_text'] + ' |'


def project_invariants(text: str, contract: dict) -> str:
    """Render one contract into its marked slot; other rows keep their current owners."""
    rid = contract['id']
    marker = contract_marker(rid)
    lines = text.splitlines(keepends=True)
    indices = [i for i, line in enumerate(lines) if line.startswith('| ' + rid + ' |')]
    if len(indices) != 1 or text.count(marker) != 1:
        raise ValueError('Missing or ambiguous generated ' + rid + ' slot')
    index = indices[0]
    if index + 1 >= len(lines) or lines[index + 1].rstrip('\r\n') != marker:
        raise ValueError('Generated marker must follow ' + rid)
    lines[index] = contract_row(contract) + '\n'
    return ''.join(lines)


# Once a document carries this line, every invariant row is rendered from its contract and no
# per-row marker is used: a marker line after a row in the middle of a table would end the table.
DECLARATION = ('<!-- Every invariant row is generated from docs/contracts/<ID>.shadow.json; '
               'change a contract with scripts/contract.py, never this table by hand. -->')


RETIREMENT_MODES = ('SUPERSEDED', 'WITHDRAWN', 'REFUTED', 'ARCHIVED')


def check_retirement(contract: dict) -> None:
    """A retired contract is the tombstone of its row (ADR-0024, retiring a row). Predicates:
    R1 the mode is one of RETIREMENT_MODES; R2 the loss is a non-empty list of non-empty texts
    (an empty loss reads as an unmeasured one, never as none); R3 SUPERSEDED names a
    replacement and only SUPERSEDED does; R4 REFUTED names its counterexample tests and only
    REFUTED does. R5 and R6 (no row; the replacement is an active row) need the table and are
    checked by generated_invariants."""
    status, retired = contract.get('status'), contract.get('retirement')
    if status is None and retired is None:
        return
    if status != 'retired' or not isinstance(retired, dict):
        raise ValueError(contract['id'] + ': a retirement needs status "retired" and a retirement record')
    if set(retired) != {'mode', 'loss', 'replacement', 'counterexamples'}:
        raise ValueError(contract['id'] + ': a retirement has exactly mode, loss, replacement, counterexamples')
    mode, loss = retired['mode'], retired['loss']
    if mode not in RETIREMENT_MODES:
        raise ValueError(contract['id'] + ': retirement mode must be one of ' + ', '.join(RETIREMENT_MODES))
    if not isinstance(loss, list) or not loss or not all(isinstance(x, str) and x.strip() for x in loss):
        raise ValueError(contract['id'] + ': a retirement names what is lost (a non-empty loss)')
    if (mode == 'SUPERSEDED') != isinstance(retired['replacement'], str):
        raise ValueError(contract['id'] + ': SUPERSEDED, and only SUPERSEDED, names a replacement')
    examples = retired['counterexamples']
    if not isinstance(examples, list) or (mode == 'REFUTED') != bool(examples) or not all(
            isinstance(w, str) and (RUST_TEST.fullmatch(w) or PY_TEST.fullmatch(w)) for w in examples):
        raise ValueError(contract['id'] + ': REFUTED, and only REFUTED, names its counterexample tests')


def retired(contract: dict) -> bool:
    return contract.get('status') == 'retired'


def load_contracts(root: pathlib.Path) -> dict:
    """Bounded local contract sources by ID; proposals live in a subdirectory and are not sources."""
    directory = root / 'docs/contracts'
    if directory.is_symlink():
        raise ValueError('Symlink contract directory refused')
    sources = list(islice(directory.glob('*.shadow.json'), MAX_CONTRACTS + 1))
    if len(sources) > MAX_CONTRACTS:
        raise ValueError('Too many contracts')
    contracts = {}
    for path in sorted(sources):
        if path.is_symlink():
            raise ValueError('Symlink contract source refused')
        with path.open('rb') as stream:
            data = stream.read(MAX_CONTRACT_BYTES + 1)
        if len(data) > MAX_CONTRACT_BYTES:
            raise ValueError('Contract exceeds bound')
        contract = json.loads(data)
        rid = contract['id']
        contract_marker(rid)
        if path.name != rid + '.shadow.json':
            raise ValueError('Contract filename differs from ID')
        names = sorted({w for w in re.findall(r'`([^`]+)`', contract['evidence_text'])
                        if RUST_TEST.fullmatch(w) or PY_TEST.fullmatch(w)})
        if not names or names != contract['witnesses']:
            raise ValueError('Contract witness list differs from its evidence text')
        contract_row(contract)
        check_retirement(contract)
        if contract.get('tier', 'provisional') != 'provisional' or (contract.get('tier') and retired(contract)):
            raise ValueError(rid + ': tier is absent (owner-accepted) or "provisional", and a provisional row is not retired')
        contracts[rid] = contract
    return contracts


def generated_invariants(text: str, root: pathlib.Path) -> str:
    """Validate all source-backed rows using bounded local contract data only."""
    marker_ids = [m.group(1) for m in GENERATED_MARKER.finditer(text)]
    if len(marker_ids) != text.count('<!-- Generated ') or len(set(marker_ids)) != len(marker_ids):
        raise ValueError('Malformed or duplicate generated contract marker')
    contracts = load_contracts(root)
    if DECLARATION in text:
        if marker_ids or text.count(DECLARATION) != 1:
            raise ValueError('A generated document has one declaration and no per-row markers')
        hidden = [(m.start(), m.end()) for m in re.finditer(r"<!--.*?(?:-->|\Z)", text, re.S)]
        offset, fenced = 0, False
        for line in text.splitlines(keepends=True):
            stripped = line.strip()
            if stripped.startswith(("```", "~~~")):
                fenced = not fenced
            elif ROW.match(line) and (fenced or any(a <= offset < b for a, b in hidden)):
                raise ValueError('A row is hidden in a comment or code block: ' + ROW.match(line).group(1))
            elif stripped.startswith("|") and not ROW.match(line) and not (fenced or any(a <= offset < b for a, b in hidden)):
                cell = unicodedata.normalize("NFKC", stripped.strip("|").split("|")[0]).strip()
                cell = re.sub(r"[\u2010-\u2015\u2212]", "-", cell)
                if CONTRACT_ID.fullmatch(cell):
                    raise ValueError('A table line names ' + cell + ' but is not a row (| ID | ...)')
            offset += len(line)
        row_ids = [m.group(1) for m in map(ROW.match, text.splitlines()) if m]
        for rid in row_ids:
            if rid not in contracts:
                raise ValueError(rid + ' has no contract source; every row is generated')
        for rid, contract in contracts.items():
            if retired(contract):
                if rid in row_ids:
                    raise ValueError('Retired ' + rid + ' still has a row')
                new = contract['retirement']['replacement']
                if new is not None and (new not in contracts or retired(contracts[new]) or new not in row_ids):
                    raise ValueError('Retired ' + rid + ' is superseded by ' + new + ', which is not an active row')
                continue
            if row_ids.count(rid) != 1:
                raise ValueError('Contract ' + rid + ' needs exactly one row')
            if contract_row(contract) not in text.splitlines():
                raise ValueError('Generated ' + rid + ' is stale; regenerate from its contract')
        return text
    for contract in contracts.values():
        if project_invariants(text, contract) != text:
            raise ValueError('Generated ' + contract['id'] + ' is stale; regenerate from its contract')
    if set(contracts) != set(marker_ids):
        raise ValueError('Generated markers and contract sources differ')
    return text


def provisional(contract: dict) -> bool:
    return contract.get('tier') == 'provisional'


def contract_pins(root: pathlib.Path, tier: str = "owner") -> dict:
    """What a signer accepts about each contract of its tier: the rendered row and its decision
    history. Unsigned explanations (annotations) are left out on purpose."""
    pins = {}
    for rid, c in load_contracts(root).items():
        if provisional(c) != (tier == "provisional"):
            continue
        accepted = {k: c.get(k) for k in ('statement', 'evidence_text', 'witnesses', 'decisions')}
        if retired(c):
            # Only a retired contract carries these keys, so the pins of active ones keep the
            # bytes earlier checkers compute.
            accepted.update(status=c['status'], retirement=c['retirement'])
        pins[rid] = sha(json.dumps(accepted, sort_keys=True, ensure_ascii=False, separators=(',', ':')))
    return pins


def open_proposals(root: pathlib.Path) -> list[str]:
    directory = root / 'docs/contracts/proposals'
    return sorted(p.name for p in islice(directory.glob('*.proposal.json'), MAX_CONTRACTS)) if directory.is_dir() else []


def rows() -> dict:
    found = {}
    text = generated_invariants(INVARIANTS.read_text(), ROOT)
    for line in text.splitlines():
        m = ROW.match(line)
        if not m:
            continue
        if m.group(1) in found:
            raise ValueError('Duplicate invariant row: ' + m.group(1))
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        spans = re.findall(r"`([^`]+)`", cells[-1])
        found[m.group(1)] = {
            "statement": sha(" ".join(" | ".join(cells[1:-1]).split())),
            "witnesses": sorted({s for s in spans if RUST_TEST.fullmatch(s) or PY_TEST.fullmatch(s)}),
        }
    return found


RUST_RAW = re.compile(r'b?r(#*)"')
RUST_CHAR = re.compile(r"'(\\.[^']*|[^\\'])'")
RUST_SPECIAL = re.compile(r"""[/"'br]""")


def rust_parts(src: str) -> list[tuple[bool, str]]:
    """Comment-free code/literal segments; literal bytes never enter layout normalization.
    Code between comments is one segment; plain code is copied in runs, not per character."""
    out, code, i, n = [], [], 0, len(src)

    def flush() -> None:
        if code:
            out.append((False, "".join(code)))
            code.clear()

    while i < n:
        m = RUST_SPECIAL.search(src, i)
        j = m.start() if m else n
        if j > i:
            code.append(src[i:j])
            i = j
        if i >= n:
            break
        c = src[i]
        if src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i < 0 else i
        elif src.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif src.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
        elif (m := RUST_RAW.match(src, i)) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            flush()
            end = src.find('"' + m.group(1), m.end())
            end = n if end < 0 else end + 1 + len(m.group(1))
            out.append((True, src[i:end]))
            i = end
        elif c == '"':
            flush()
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append((True, src[i:j + 1]))
            i = j + 1
        elif c == "'" and (m := RUST_CHAR.match(src, i)):
            flush()
            out.append((True, m.group(0)))
            i = m.end()
        else:
            code.append(c)
            i += 1
    flush()
    return out


def strip_rust(src: str) -> str:
    return "".join(text for _, text in rust_parts(src))


def rust_layout(code: str) -> str:
    return json.dumps([(literal, text if literal else squeeze(text))
                       for literal, text in rust_parts(code)], ensure_ascii=True, separators=(",", ":"))


def rust_mask(code: str) -> str:
    # Preserve offsets, but literal braces and function-looking text are not code.
    return "".join(" " * len(text) if literal else text for literal, text in rust_parts(code))


def squeeze(code: str) -> str:
    """Whitespace only where it separates two words, so rustfmt line breaks do not count."""
    code = re.sub(r"\s+", " ", code)
    return re.sub(r" (?=\W)|(?<=\W) ", "", code)


def rust_witness_hashes(source: str, relative_path: str, names: set[str]) -> dict[str, list[str]]:
    """Public byte-to-pin API: same normalizer as the gate, no file reads or subprocesses."""
    bodies: dict[str, list[str]] = {}
    src = strip_rust(source)
    masked = rust_mask(src)
    for m in re.finditer(r"\bfn ([a-z][a-z0-9_]*)\s*[(<]", masked):
        if m.group(1) not in names:
            continue
        start = masked.find("{", m.end())
        depth, j = 0, start
        for j in range(start, len(src)):
            depth += {"{": 1, "}": -1}.get(masked[j], 0)
            if depth == 0:
                break
        rel = relative_path
        bodies.setdefault(m.group(1), []).append(f"{rel}:{sha(rust_layout(src[m.start():j + 1]))}")
    return bodies


def rust_bodies(names: set[str]) -> dict[str, list[str]]:
    bodies = {}
    for path in git_files("*.rs"):
        found = rust_witness_hashes(path.read_text(), path.relative_to(ROOT).as_posix(), names)
        for name, hashes in found.items():
            bodies.setdefault(name, []).extend(hashes)
    return bodies


CFG_TEST = re.compile(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]")
RUST_HEAD = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?\s+)?(?:(?:async|unsafe|const|default|extern)\s+"
    r"(?=(?:async|unsafe|const|extern|fn|impl|trait)\b))*"
    r"(fn|const|static|struct|enum|type|trait|mod|union|impl|macro_rules\s*!|use)\s*")
RUST_IMPL = re.compile(r"(?:<[^{]*?>)?\s*(?:[^{;]*?\bfor\s+)?(?:[\w]+::)*([A-Za-z_]\w*)")
TEST_ATTR = re.compile(r"#\[\s*(?:tokio::)?test\b")
MACRO_CALL = re.compile(r"(?:\w+::)*\w+\s*!\s*\{")
IDENT = re.compile(r"[A-Za-z_]\w*")


def rust_close(masked: str, at: int, open_: str, close: str) -> int:
    depth = 0
    for j in range(at, len(masked)):
        if masked[j] == open_:
            depth += 1
        elif masked[j] == close:
            depth -= 1
            if depth == 0:
                return j
    return len(masked) - 1


def rust_items(masked: str, lo: int, hi: int) -> list[tuple[int, int, int]]:
    """Items of masked[lo:hi] as (start with attributes, start of the item proper, end)."""
    items, i = [], lo
    while i < hi:
        while i < hi and (masked[i].isspace() or masked[i] == ";"):
            i += 1
        if i >= hi:
            break
        start = i
        while masked.startswith("#", i) and masked[i + 1:i + 2] in ("[", "!"):
            i = rust_close(masked, masked.find("[", i), "[", "]") + 1
            while i < hi and masked[i].isspace():
                i += 1
        depth, assigned, j, end = 0, False, i, hi - 1
        while j < hi:
            c = masked[j]
            if c == "{" and depth == 0 and not assigned:
                end = rust_close(masked, j, "{", "}")
                break
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif c == "=" and depth == 0 and masked[j + 1:j + 2] not in ("=", ">") and masked[j - 1] not in "=!<>":
                assigned = True
            elif c == ";" and depth == 0:
                end = j
                break
            j += 1
        items.append((start, i, end + 1))
        i = end + 1
    return items


def rust_item_name(masked: str, head: int, end: int) -> tuple[str | None, str | None]:
    """(keyword, name) of the item at `head`: an impl is named by its self type."""
    m = RUST_HEAD.match(masked, head, end)
    if not m:
        return None, None
    keyword = m.group(1).replace(" ", "")
    if keyword == "use":
        # `use helper as h;` must reach `helper` from a witness that calls `h`: a use item is
        # named by the name it binds (the alias, or the last segment).
        bound = [n for n in re.findall(r"([A-Za-z_]\w*)\s*[,;}]", masked[m.end():end])
                 if n not in ("self", "super", "crate")]
        return keyword, ",".join(bound) or None
    if keyword == "impl":
        # Named by its self type: `impl Blocklist for FakeLists` belongs to FakeLists, so a
        # witness using FakeLists reaches the behaviour it gets (2026-10-14: since #22 this
        # branch was unreachable and impls were named by their trait or module path).
        n = RUST_IMPL.match(masked, m.end(), end)
        return keyword, n.group(1) if n else None
    n = IDENT.match(masked, m.end(), end)
    return keyword, n.group(0) if n else None


def rust_inner_attributes(masked: str, body: int, hi: int) -> int:
    """End of the inner attributes (#![...]) at the start of a block whose `{` is at `body`."""
    i = body + 1
    while True:
        j = i
        while j < hi and masked[j].isspace():
            j += 1
        if not masked.startswith("#!", j):
            return i
        i = rust_close(masked, masked.find("[", j), "[", "]") + 1


def rust_test_items(masked: str, integration: bool) -> list[tuple[int, int, int, str, bool, tuple]]:
    """Test-only items: those under #[cfg(test)] (a module's items, or one item, at any depth)
    and, in an integration test file, every top-level item; items inside a macro call there
    (proptest!) too. (start, head, end, name, is_test, contexts): `contexts` are the spans of
    every enclosing module's or macro call's head and inner attributes (#![cfg(..)],
    #![proptest_config]), pinned with the item: they decide whether and how it runs."""
    spans: list[tuple[int, int, int, tuple]] = []

    def block(lo: int, hi: int, contexts: tuple) -> None:
        for start, head, end in rust_items(masked, lo, hi):
            keyword, _ = rust_item_name(masked, head, end)
            if keyword == "mod" and masked[end - 1] == "}":
                body = masked.find("{", head, end)
                inner = rust_inner_attributes(masked, body, end)
                block(inner, end - 1, contexts + ((start, inner),))
            elif keyword is None and MACRO_CALL.match(masked, head, end):
                body = masked.find("{", head, end)
                inner = rust_inner_attributes(masked, body, end)
                block(inner, end - 1, contexts + ((start, inner),))
            else:
                spans.append((start, head, end, contexts))

    if integration:
        block(0, len(masked), ())
    for m in CFG_TEST.finditer(masked):
        for start, head, end in rust_items(masked, m.start(), len(masked))[:1]:
            if rust_item_name(masked, head, end)[0] == "mod" and masked[end - 1] == "}":
                body = masked.find("{", head, end)
                inner = rust_inner_attributes(masked, body, end)
                block(inner, end - 1, ((start, inner),))
            else:
                spans.append((start, head, end, ()))
    out, seen = [], set()
    for start, head, end, contexts in spans:
        if (start, end) in seen:
            continue
        seen.add((start, end))
        _, name = rust_item_name(masked, head, end)
        for one in (name or "").split(","):
            if one:
                out.append((start, head, end, one, bool(TEST_ATTR.search(masked, start, head)), contexts))
    return out


def rust_declarations(files: dict) -> dict[str, list[str]]:
    """For each file, the `mod name;` items (with attributes) that include it in a crate: a
    `#[cfg_attr(test, path = ..)]` or `#[cfg(not(test))]` there would drop its tests."""
    found: dict[str, list[str]] = {}
    for rel, (src, masked, _) in files.items():
        here = pathlib.PurePosixPath(rel)
        for start, head, end in rust_items(masked, 0, len(masked)):
            keyword, name = rust_item_name(masked, head, end)
            if keyword != "mod" or masked[end - 1] != ";" or not name:
                continue
            attrs = src[start:head]
            m = re.search(r'path\s*=\s*"([^"]+)"', attrs)
            if m:
                target = here.parent / m.group(1)
            elif here.name in ("main.rs", "lib.rs", "mod.rs"):
                target = here.parent / f"{name}.rs"
            else:
                target = here.parent / here.stem / f"{name}.rs"
            target = pathlib.PurePosixPath(*[p for p in target.parts if p != "."])
            parts: list[str] = []
            for part in target.parts:
                if part == ".." and parts:
                    parts.pop()
                else:
                    parts.append(part)
            found.setdefault("/".join(parts), []).append(f"{rel}:{rust_layout(src[start:end])}")
    return found


REACHED: dict[str, list[str]] = {}


def rust_closures(names: set[str]) -> dict[str, list[str]]:
    """Per witness, one hash over its item with attributes and every test-only item it reaches
    by name, transitively: in its own file, or in another file only through a path naming that
    file's module (`p2p::tests::frame_of`), so a local variable called `dir` reaches nothing."""
    files = {}
    for path in git_files("*.rs"):
        rel = path.relative_to(ROOT).as_posix()
        src = strip_rust(path.read_text())
        masked = rust_mask(src)
        files[rel] = (src, masked, rust_test_items(masked, "/tests/" in f"/{rel}"))
    declarations = rust_declarations(files)
    helpers: dict[str, dict[str, list[tuple[str, int, int]]]] = {}
    for rel, (_, _, items) in files.items():
        for start, _, end, name, is_test, _ in items:
            if not is_test:
                helpers.setdefault(rel, {}).setdefault(name, []).append((rel, start, end))
    stems: dict[str, list[str]] = {}
    for rel in helpers:
        stems.setdefault(pathlib.PurePosixPath(rel).stem.replace("-", "_"), []).append(rel)

    def reach(rel: str, text: str) -> list[tuple[str, int, int]]:
        hits = []
        for ident in set(IDENT.findall(text)):
            hits += helpers.get(rel, {}).get(ident, [])
        for stem, ident in set(re.findall(r"\b(\w+)::(?:\w+::)*?(\w+)\b", text)):
            for other in stems.get(stem, []):
                if other != rel:
                    hits += helpers[other].get(ident, [])
        return hits

    out: dict[str, list[str]] = {}
    for rel, (src, masked, items) in files.items():
        for start, _, end, name, is_test, contexts in items:
            if name not in names or not is_test:
                continue
            reached, queue, seen = [], [(rel, start, end)], {(rel, start, end)}
            while queue:
                r, s, e = queue.pop()
                for hit in reach(r, files[r][1][s:e]):
                    if hit not in seen:
                        seen.add(hit)
                        reached.append(hit)
                        queue.append(hit)
            parts = [rust_layout(src[start:end])]
            parts += [rust_layout(src[a:b]) for a, b in contexts]
            parts += declarations.get(rel, [])
            parts += [f"{r}:{rust_layout(files[r][0][s:e])}" for r, s, e in sorted(reached)]
            out.setdefault(name, []).append(f"{rel}:{sha(json.dumps(parts))}")
            REACHED.setdefault(name, []).extend(
                f"{r}:{files[r][0].count(chr(10), 0, s) + 1} {rust_item_name(files[r][1], s, e)[1] or '?'}"
                for r, s, e in sorted(reached))
    return out


def py_closures(names: set[str]) -> dict[str, list[str]]:
    """Per witness, one hash over the method with its and its class's decorators, the class's
    fixtures (setUp/tearDown) and every module-level or class item it reaches by name."""
    out: dict[str, list[str]] = {}
    for path in git_files("*.py"):
        text = path.read_text()
        lines = text.splitlines(keepends=True)
        tree = ast.parse(text)
        module: dict[str, ast.AST] = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                module[node.name] = node
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                    for n in ast.walk(target):
                        if isinstance(n, ast.Name):
                            module[n.id] = node

        # `from helper_module import x` / `import helper_module` of a module beside this file:
        # its import-time code runs before any witness, and what the witness takes from it is
        # part of what the witness checks (2026-10-14).
        local_modules: dict[str, pathlib.Path] = {}
        imported: dict[str, tuple[str, str]] = {}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                if (path.parent / f"{node.module}.py").exists():
                    local_modules[node.module] = path.parent / f"{node.module}.py"
                    for alias in node.names:
                        imported[alias.asname or alias.name] = (node.module, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if (path.parent / f"{alias.name}.py").exists():
                        local_modules[alias.asname or alias.name] = path.parent / f"{alias.name}.py"

        def import_time(closure: set[int]) -> str:
            """The module as it runs on import: every statement, with the bodies of functions
            outside the closure left out. A module-level `setattr(Class, 'test_x', ...)`, a
            class-body assignment shadowing a witness or a `__main__` block are all in it."""
            drop: set[int] = set()
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and id(n) not in closure:
                    drop.update(range(n.body[0].lineno, n.end_lineno + 1))
            kept = "".join(line for i, line in enumerate(lines, 1) if i not in drop)
            return py_layout(strip_py(kept))

        def segment(node: ast.AST) -> str:
            first = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
            return py_layout(strip_py("".join(lines[first - 1:node.end_lineno])))

        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            methods = {f.name: f for f in cls.body if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))}
            for fn in methods.values():
                key = f"{cls.name}.{fn.name}"
                if key not in names:
                    continue
                fixtures = [methods[n] for n in ("setUp", "tearDown", "setUpClass", "tearDownClass") if n in methods]
                reached, queue = [], [fn, *fixtures]
                seen = {id(fn), *map(id, fixtures)}
                while queue:
                    node = queue.pop()
                    for n in ast.walk(node):
                        ident = n.id if isinstance(n, ast.Name) else n.attr if isinstance(n, ast.Attribute) else None
                        for hit in (methods.get(ident), module.get(ident)):
                            if hit is not None and id(hit) not in seen and hit is not cls:
                                seen.add(id(hit))
                                reached.append(hit)
                                queue.append(hit)
                parts = [segment(fn), *(segment(f) for f in fixtures)]
                parts += [ast.dump(d) for d in cls.decorator_list]
                parts += sorted(segment(n) for n in reached)
                parts.append(import_time({id(fn), *map(id, fixtures), *map(id, reached)}))
                used: dict[str, set[str]] = {}
                for x in (fn, *fixtures, *reached):
                    for n in ast.walk(x):
                        if isinstance(n, ast.Name) and n.id in imported:
                            used.setdefault(imported[n.id][0], set()).add(imported[n.id][1])
                        elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id in local_modules:
                            used.setdefault(n.value.id, set()).add(n.attr)
                rel = path.relative_to(ROOT).as_posix()
                for alias in sorted(set(local_modules) | set(used)):
                    module_path = local_modules[alias] if alias in local_modules else path.parent / f"{alias}.py"
                    parts.append(py_module_part(module_path, used.get(alias, set())))
                    REACHED.setdefault(key, []).append(
                        f"{module_path.relative_to(ROOT).as_posix()} import-time code"
                        + "".join(f", {n}" for n in sorted(used.get(alias, set()))))
                REACHED.setdefault(key, []).extend(
                    f"{rel}:{n.lineno} {getattr(n, 'name', None) or type(n).__name__}"
                    for n in [*fixtures, *reached])
                out.setdefault(key, []).append(f"{rel}:{sha(json.dumps(parts))}")
    return out


def py_module_part(path: pathlib.Path, names: set[str]) -> str:
    """A local module a witness's file imports: its import-time code (function bodies left out)
    and the full source of the items the witness takes from it. Items those reach inside that
    module are not followed; their bodies run only through the named items, whose source is
    pinned, and execution evidence covers the rest."""
    text = path.read_text()
    lines = text.splitlines(keepends=True)
    tree = ast.parse(text)
    keep = {node.name: node for node in tree.body if getattr(node, "name", None) in names}
    drop: set[int] = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n not in keep.values():
            drop.update(range(n.body[0].lineno, n.end_lineno + 1))
    skeleton = "".join(line for i, line in enumerate(lines, 1) if i not in drop)
    rel = path.relative_to(ROOT).as_posix()
    return f"{rel}:{py_layout(strip_py(skeleton))}"


TEST_LINE = re.compile(r"^test (\S+)(?: - should panic)? \.\.\. (\w+)", re.M)


def ci_arguments(rel: str) -> list[str]:
    """The arguments CI passes to a Python test file (adapter tests take a binary path). The
    base workflow points WITNESS_PIN_CI at the base's ci.yml: a pull request's own ci.yml must
    not choose the arguments its pinned witnesses run with."""
    import os
    path = pathlib.Path(os.environ.get("WITNESS_PIN_CI") or ROOT / ".github/workflows/ci.yml")
    ci = path.read_text() if path.exists() else ""
    m = re.search(rf"python3 {re.escape(rel)}((?: [^\s|&;]+)*)", ci)
    return m.group(1).split() if m else []


def run_python_witnesses(pinned: dict) -> dict[tuple[str, str], str]:
    """Runs each pinned Python witness as CI runs it: (witness, file) -> unittest's output."""
    out, files = {}, {}
    for w, where in sorted(pinned.items()):
        if not PY_TEST.fullmatch(w):
            continue
        for loc in where:
            rel = loc.split(":", 1)[0]
            args = ci_arguments(rel)
            if args:
                # Its own main parses the arguments and runs the file verbosely.
                if rel not in files:
                    files[rel] = subprocess.run([sys.executable, rel, *args], cwd=ROOT, capture_output=True,
                                                text=True, stdin=subprocess.DEVNULL, timeout=1800)
                r = files[rel]
            else:
                module = pathlib.Path(rel)
                r = subprocess.run([sys.executable, "-m", "unittest", "-v", f"{module.stem}.{w}"],
                                   cwd=ROOT / module.parent, capture_output=True, text=True,
                                   stdin=subprocess.DEVNULL, timeout=600)
            out[(w, rel)] = r.stderr
    return out


PY_SEGMENT = re.compile(r"^== witness (\S+) (\S+)$", re.M)


def python_log(text: str) -> dict[tuple[str, str], str]:
    """The output of `witness-pin.py run-python`, per (witness, file)."""
    heads = list(PY_SEGMENT.finditer(text))
    return {(h.group(1), h.group(2)): text[h.end():heads[i + 1].start() if i + 1 < len(heads) else len(text)]
            for i, h in enumerate(heads)}


def executed(log: pathlib.Path, pinned: dict, python: pathlib.Path | None = None) -> list[str]:
    """Pinned witnesses that did not run and pass: Rust ones by the `cargo test` log (every
    definition of the name must pass); Python ones by the `run-python` log if given (the base
    workflow runs them in the untrusted job), else by running them here as CI runs them."""
    results: dict[str, list[str]] = {}
    for path, outcome in TEST_LINE.findall(log.read_text()):
        results.setdefault(path.rsplit("::", 1)[-1], []).append(outcome)
    problems = []
    for w, where in sorted(pinned.items()):
        if RUST_TEST.fullmatch(w):
            outcomes = results.get(w, [])
            if outcomes.count("ok") < len(where) or any(o != "ok" for o in outcomes):
                problems.append(f"witness {w} did not run and pass in {log} ({', '.join(outcomes) or 'absent'})")
    ran = python_log(python.read_text()) if python else run_python_witnesses(pinned)
    for w, where in sorted(pinned.items()):
        if not PY_TEST.fullmatch(w):
            continue
        method = w.split(".", 1)[1]
        for loc in where:
            rel = loc.split(":", 1)[0]
            if not re.search(rf"^{re.escape(method)} \(.*\) \.\.\. ok$", ran.get((w, rel), ""), re.M):
                problems.append(f"witness {w} did not run and pass ({rel})")
    return problems


def strip_py(code: str) -> str:
    """Source without comments. Comment tokens are the same in every Python version; the text
    that ast.unparse prints is not (3.9 and 3.12 differ), so a hash of it differed in CI."""
    import io
    import textwrap
    import tokenize
    code = textwrap.dedent(code)
    lines = code.splitlines(keepends=True)
    for tok in reversed(list(tokenize.generate_tokens(io.StringIO(code).readline))):
        if tok.type == tokenize.COMMENT:
            (row, col), (_, end) = tok.start, tok.end
            lines[row - 1] = lines[row - 1][:col] + lines[row - 1][end:]
    return "".join(lines)


def py_bodies(names: set[str]) -> dict[str, list[str]]:
    bodies: dict[str, list[str]] = {}
    for path in git_files("*.py"):
        text = path.read_text()
        lines = text.splitlines(keepends=True)
        for cls in (n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.ClassDef)):
            for fn in cls.body:
                key = f"{cls.name}.{getattr(fn, 'name', '')}"
                if key in names and isinstance(fn, ast.FunctionDef):
                    rel = path.relative_to(ROOT).as_posix()
                    code = strip_py("".join(lines[fn.lineno - 1:fn.end_lineno]))
                    bodies.setdefault(key, []).append(f"{rel}:{sha(py_layout(code))}")
    return bodies


def py_layout(code: str) -> str:
    import io
    import textwrap
    import tokenize
    code = textwrap.dedent(code)
    lines = code.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    source_tokens = iter(tokenize.generate_tokens(io.StringIO(code).readline))
    # The owner pins already use Python 3.9 token IDs. Python 3.13 moved OP
    # and splits f-strings into several tokens: keep the same source identity.
    canonical = {"NAME": 1, "NUMBER": 2, "STRING": 3, "NEWLINE": 4,
                 "INDENT": 5, "DEDENT": 6, "OP": 54, "ERRORTOKEN": 60}
    tokens = []
    for token in source_tokens:
        kind = tokenize.tok_name[token.type]
        if token.type in (tokenize.COMMENT, tokenize.NL, tokenize.ENDMARKER):
            continue
        if kind == "FSTRING_START":
            start = offsets[token.start[0] - 1] + token.start[1]
            depth = 1
            for part in source_tokens:
                part_kind = tokenize.tok_name[part.type]
                depth += int(part_kind == "FSTRING_START") - int(part_kind == "FSTRING_END")
                if depth == 0:
                    end = offsets[part.end[0] - 1] + part.end[1]
                    tokens.append((3, code[start:end]))
                    break
            else:
                raise ValueError("Unterminated f-string")
            continue
        if kind not in canonical:
            raise ValueError("Unsupported Python token: " + kind)
        value = "" if token.type in (tokenize.INDENT, tokenize.DEDENT, tokenize.NEWLINE) else token.string
        tokens.append((canonical[kind], value))
    return json.dumps(tokens, ensure_ascii=True, separators=(",", ":"))


CARGO_SECTION = re.compile(r"^\[\[?([^\]]+)\]\]?\s*$")
TARGET_SECTIONS = ("lib", "bin", "test", "bench", "example", "workspace")


# Current pin fields. A change of rule gets a new field; the earlier fields stay in the manifest
# as pinned, so the base branch's checker (which computes them) still accepts the change.
CLOSURES = "closures_v4"
BUILD = "build_v3"
TRUST = "trust_root_v1"
TRUST_PATHS = (".github/witness-signers", "scripts/witness-pin.py",
               ".github/workflows/witness-gate.yml")
MAX_TRUST_BYTES = 262_144


def trust_pins() -> dict:
    """The proposed NEXT base, authenticated by the current owner's manifest and trust.

    Always inspect candidate bytes, even when this checker is executed outside that tree.
    Missing optional workflow files in small fixtures are pinned as absent, not omitted.
    """
    pins = {}
    for rel in TRUST_PATHS:
        path = ROOT / rel
        for component in (path, *path.parents):
            if component == ROOT:
                break
            if component.is_symlink():
                raise ValueError('Symlink trust root refused: ' + rel)
        if not path.exists():
            pins[rel] = None
            continue
        mode = path.stat().st_mode
        if not stat.S_ISREG(mode):
            raise ValueError('Non-regular trust root refused: ' + rel)
        with path.open('rb') as stream:
            data = stream.read(MAX_TRUST_BYTES + 1)
        if len(data) > MAX_TRUST_BYTES:
            raise ValueError('Oversized trust root refused: ' + rel)
        pins[rel] = {'sha256': hashlib.sha256(data).hexdigest(), 'executable': bool(mode & 0o111)}
    return pins


def configure_root(root: pathlib.Path) -> None:
    """CLI boundary: run a trusted checker without replacing candidate source files."""
    global ROOT, INVARIANTS, MANIFEST, SIGNATURE, PROVISIONAL, PROVISIONAL_SIG, SIGNERS
    ROOT = root.resolve(strict=True)
    INVARIANTS = ROOT / 'docs/INVARIANTS.md'
    MANIFEST = ROOT / 'docs/witness-manifest.json'
    SIGNATURE = ROOT / 'docs/witness-manifest.json.sig'
    PROVISIONAL = ROOT / 'docs/witness-provisional.json'
    PROVISIONAL_SIG = ROOT / 'docs/witness-provisional.json.sig'
    SIGNERS = ROOT / '.github/witness-signers'


def build_pins() -> dict[str, str]:
    """What decides whether and how tests are built and run, and how they are checked, outside
    the test code: Cargo
    target sections, [workspace], [patch.*] and `auto*` keys, whole .cargo/config files (a
    `runner` there could print any test output) and build scripts (they could rewrite sources
    before the crate compiles)."""
    pins = {}
    for path in git_files("*Cargo.toml"):
        kept, section = [], ""
        for line in path.read_text().splitlines():
            m = CARGO_SECTION.match(line.strip())
            if m:
                section = m.group(1).strip()
            keep = section.split(".")[0] in TARGET_SECTIONS or section.startswith("patch") \
                or (section == "package" and line.strip().startswith("auto"))
            if keep and line.strip() and not line.strip().startswith("#"):
                kept.append(" ".join(line.split()))
        pins[path.relative_to(ROOT).as_posix()] = sha("\n".join(kept))
    for pattern in (".cargo/config", ".cargo/config.toml", "*/.cargo/config", "*/.cargo/config.toml", "build.rs", "*/build.rs",
                    "rust-toolchain", "rust-toolchain.toml", "*/rust-toolchain", "*/rust-toolchain.toml",
                    # The gate a change cannot edit runs from main; a change to it must not
                    # take effect after a merge without the owner having signed it.
                    ".github/workflows/witness-gate.yml"):
        for path in git_files(pattern):
            pins[path.relative_to(ROOT).as_posix()] = sha(path.read_text())
    return pins


def current(tier: str = "owner") -> dict:
    """The pins of one tier (ADR-0028): the owner's rows, or the agent's provisional rows. A
    witness that an owner row cites belongs to the owner's pins only."""
    contracts = load_contracts(ROOT)
    every = rows()
    agent = {rid for rid, c in contracts.items() if provisional(c)}
    table = {rid: r for rid, r in every.items() if (rid in agent) == (tier == "provisional")}
    cited = {w for r in table.values() for w in r["witnesses"]}
    if tier == "provisional":
        cited -= {w for rid, r in every.items() if rid not in agent for w in r["witnesses"]}
    else:
        # A REFUTED row's counterexamples are the evidence its tombstone rests on: pinned too.
        cited |= {w for c in contracts.values() if retired(c) for w in c['retirement']['counterexamples']}
    bodies = {**rust_bodies({w for w in cited if RUST_TEST.fullmatch(w)}),
              **py_bodies({w for w in cited if PY_TEST.fullmatch(w)})}
    closures = {**rust_closures({w for w in cited if RUST_TEST.fullmatch(w)}),
                **py_closures({w for w in cited if PY_TEST.fullmatch(w)})}
    return {"rows": table, "witnesses": {w: sorted(bodies.get(w, [])) for w in sorted(cited)},
            CLOSURES: {w: sorted(closures.get(w, [])) for w in sorted(cited)},
            BUILD: build_pins() if tier == "owner" else {},
            TRUST: trust_pins() if tier == "owner" else {},
            "contracts": contract_pins(ROOT, tier)}


def verify_manifest(manifest: pathlib.Path, signature: pathlib.Path, signers: pathlib.Path,
                    principal: str = "owner") -> bool:
    """Verify owner against the supplied trust file; callers choose its trusted provenance."""
    if not (manifest.exists() and signature.exists() and signers.exists()):
        return False
    r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", principal, "-n", NAMESPACE,
                        "-s", str(signature)], input=manifest.read_bytes(), capture_output=True, timeout=10)
    return r.returncode == 0


def verify(signers: pathlib.Path) -> bool:
    return verify_manifest(MANIFEST, SIGNATURE, signers)


def compare(pinned: dict, now: dict, who: str) -> tuple[list[str], list[str]]:
    """What changed in one tier against what its signer pinned."""
    problems, notes = [], []
    for rid, row in pinned["rows"].items():
        cur = now["rows"].get(rid)
        if cur is None:
            problems.append(f"{rid}: pinned invariant row was removed")
            continue
        if cur["statement"] != row["statement"]:
            problems.append(f"{rid}: invariant statement changed")
        for w in sorted(set(row["witnesses"]) - set(cur["witnesses"])):
            problems.append(f"{rid}: witness {w} was dropped from the row")
        for w in sorted(set(cur["witnesses"]) - set(row["witnesses"])):
            notes.append(f"{rid}: witness {w} is new and not pinned yet")
    for w, where in pinned["witnesses"].items():
        if w in now["witnesses"] and now["witnesses"][w] != where:
            problems.append(f"witness {w} changed: its body is not the one the {who} pinned")
    # closures (#21), closures_v2 (#22), closures_v3 (#40) and build (#22) are earlier rules,
    # kept frozen for checkers of those versions; closures_v4 follows Python imports of local
    # modules, build_v2 adds the Rust toolchain file, build_v3 the base gate workflow.
    closures = pinned.get(CLOSURES)
    if closures is None:
        if pinned["witnesses"]:
            notes.append("witness closures (attributes, helpers) are not pinned yet")
    else:
        for w, where in closures.items():
            if w in now[CLOSURES] and now[CLOSURES][w] != where and now["witnesses"].get(w) == pinned["witnesses"].get(w):
                problems.append(f"witness {w} changed: its attributes or a test item it reaches are not the ones the {who} pinned")
    for rid in sorted(set(now["rows"]) - set(pinned["rows"])):
        notes.append(f"{rid}: new invariant row, not pinned yet")
    for rid, pin in pinned.get("contracts", {}).items():
        if rid not in now["contracts"]:
            problems.append(f"{rid}: pinned contract was removed")
        elif now["contracts"][rid] != pin:
            problems.append(f"{rid}: contract statement, witnesses or decision history changed")
    for rid in sorted(set(now["contracts"]) - set(pinned.get("contracts", {}))):
        notes.append(f"{rid}: contract is not pinned yet")
    return problems, notes


def check(signers: pathlib.Path, every_pin: bool = False, executed_log: pathlib.Path | None = None,
          python_log_path: pathlib.Path | None = None) -> int:
    now, agent_now = current("owner"), current("provisional")
    problems, notes = [], []
    for w, where in {**now["witnesses"], **agent_now["witnesses"]}.items():
        if not where:
            problems.append(f"witness {w} is cited but no test function has that name")
    if not verify(signers):
        problems.append(f"{MANIFEST.relative_to(ROOT)} is not signed by a key in {signers}")
        pinned = {"rows": {}, "witnesses": {}}
    else:
        pinned = json.loads(MANIFEST.read_text())
    found, noted = compare(pinned, now, "owner")
    problems += found
    notes += noted
    if TRUST not in pinned:
        problems.append('trust root is not pinned by the owner; bootstrap requires owner acceptance')
    elif pinned[TRUST] != now[TRUST]:
        problems.append('trust root changed without the current owner authorizing its exact bytes')
    build = pinned.get(BUILD)
    if build is None:
        if pinned["witnesses"]:
            notes.append("build configuration (Cargo targets, .cargo/config, build.rs, toolchain) is not pinned yet")
    elif build != now[BUILD]:
        for f in sorted(set(build) | set(now[BUILD])):
            if build.get(f) != now[BUILD].get(f):
                problems.append(f"{f}: build configuration changed (how tests are built or run)")
    # The agent's tier (ADR-0028): provisional rows, signed by the `agent` principal of the
    # same signers file. It cannot hold an owner row: those are not in agent_now, so pinning
    # one there reads as a removed row.
    agent_pinned = {"rows": {}, "witnesses": {}}
    if PROVISIONAL.exists() or agent_now["rows"]:
        if PROVISIONAL.exists() and verify_manifest(PROVISIONAL, PROVISIONAL_SIG, signers, "agent"):
            agent_pinned = json.loads(PROVISIONAL.read_text())
        elif PROVISIONAL.exists():
            problems.append(f"{PROVISIONAL.relative_to(ROOT)} is not signed by the agent key in {signers}")
        # A row the owner has promoted is the owner's now: the agent's old pin of it lapses.
        promoted = set(pinned["rows"]) | set(pinned.get("contracts", {}))
        agent_pinned = {**agent_pinned,
                        "rows": {r: v for r, v in agent_pinned["rows"].items() if r not in promoted},
                        "contracts": {r: v for r, v in agent_pinned.get("contracts", {}).items() if r not in promoted},
                        "witnesses": {k: v for k, v in agent_pinned["witnesses"].items() if k not in now["witnesses"]},
                        CLOSURES: {k: v for k, v in agent_pinned.get(CLOSURES, {}).items() if k not in now["witnesses"]}}
        found, noted = compare(agent_pinned, agent_now, "agent")
        problems += found
        notes += [x.replace(": new invariant row, not pinned yet", ": new provisional row, not pinned yet") for x in noted]
    if executed_log is not None:
        problems += executed(executed_log, {**pinned["witnesses"], **agent_pinned["witnesses"]}, python_log_path)
    for name in open_proposals(ROOT):
        notes.append(f"open proposal {name}: unsigned intent, not accepted")
    if every_pin:
        # On main nothing may stand unpinned: a merge that kept another branch's manifest would
        # otherwise leave a row only noted, as MESH-K1 was after #7 and #8 (ADR-0023).
        problems += [x for x in notes if x.endswith("not pinned yet")]
        notes = [x for x in notes if not x.endswith("not pinned yet")]
    for x in notes:
        print("note", x)
    for x in problems:
        print("FAIL", x)
    if problems:
        print("A pinned witness or invariant changes only with a new owner signature: scripts/witness-pin.py sign")
        return 1
    extra = f"; {len(agent_pinned['rows'])} provisional rows match the agent's" if agent_pinned["rows"] else ""
    print(f"ok   {len(pinned['rows'])} invariant rows and {len(pinned['witnesses'])} witnesses match the owner's pins{extra}")
    return 0


def write_signed(path: pathlib.Path, signature: pathlib.Path, value: dict, key: str) -> None:
    """Signs a staged copy and replaces the manifest and its signature only once signing has
    succeeded: a wrong passphrase used to leave a rewritten manifest with its signature gone."""
    staged = path.with_name(path.name + ".staged")
    staged.write_text(json.dumps(value, indent=1, sort_keys=True) + "\n")
    staged_sig = pathlib.Path(str(staged) + ".sig")
    # ssh-keygen asks before overwriting a signature and, without a terminal, keeps the old
    # one and still exits 0: a re-pin would leave the previous signature in place.
    staged_sig.unlink(missing_ok=True)
    try:
        subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", key, "-n", NAMESPACE, str(staged)],
                       stdin=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError:
        staged.unlink(missing_ok=True)
        staged_sig.unlink(missing_ok=True)
        raise SystemExit(f"FAIL not signed ({key}); {path.name} and its signature are unchanged")
    staged.replace(path)
    staged_sig.replace(signature)


def sign(key: str, tier: str = "owner") -> int:
    """The owner pins the owner tier (promoted rows included); the agent's key pins only the
    provisional tier, in its own manifest (ADR-0028)."""
    now = current(tier)
    missing = [w for w, where in now["witnesses"].items() if not where]
    if missing:
        print("FAIL refusing to pin witnesses that do not exist:", ", ".join(missing))
        return 1
    path, signature = (MANIFEST, SIGNATURE) if tier == "owner" else (PROVISIONAL, PROVISIONAL_SIG)
    if tier == "owner" and MANIFEST.exists():
        # Checkers of earlier rules still read their own fields; each stays as pinned.
        for field, value in json.loads(MANIFEST.read_text()).items():
            now.setdefault(field, value)
    write_signed(path, signature, now, key)
    print(f"signed {len(now['rows'])} {'provisional ' if tier != 'owner' else ''}rows, {len(now['witnesses'])} witnesses")
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ['--root'] and len(args) >= 3:
        configure_root(pathlib.Path(args[1]))
        args = args[2:]
    if args[:1] == ["sign"] and "--key" in args:
        sys.exit(sign(args[args.index("--key") + 1]))
    if args[:1] == ["sign-provisional"] and "--key" in args:
        sys.exit(sign(args[args.index("--key") + 1], "provisional"))
    if args[:1] == ["closure"] and len(args) == 2:
        w = args[1]
        (rust_closures if RUST_TEST.fullmatch(w) else py_closures)({w})
        print("\n".join(REACHED.get(w, [])) or "(the witness alone)")
        sys.exit(0)
    if args[:1] == ["run-python"]:
        # The untrusted job of the base workflow: run the pinned Python witnesses, print a log.
        # Both tiers' witnesses (ADR-0028): the gate requires each pinned one to have passed.
        witnesses = json.loads(MANIFEST.read_text())["witnesses"]
        if PROVISIONAL.exists():
            witnesses = {**json.loads(PROVISIONAL.read_text())["witnesses"], **witnesses}
        ran = run_python_witnesses(witnesses)
        for (w, rel), text in ran.items():
            print(f"== witness {w} {rel}\n{text}")
        sys.exit(0)
    if args[:1] == ["check"]:
        sys.exit(check(pathlib.Path(args[args.index("--signers") + 1]) if "--signers" in args else SIGNERS,
                       every_pin="--every-pin" in args,
                       executed_log=pathlib.Path(args[args.index("--executed") + 1]) if "--executed" in args else None,
                       python_log_path=pathlib.Path(args[args.index("--executed-python") + 1])
                       if "--executed-python" in args else None))
    print(__doc__)
    sys.exit(2)
