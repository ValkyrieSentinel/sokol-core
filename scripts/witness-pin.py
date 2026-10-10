#!/usr/bin/env python3
"""Owner-pinned witnesses for docs/INVARIANTS.md (ADR-0023).

scripts/check-claims.sh shows that a cited test exists. It cannot show that the test still
tests what the row claims: a witness can be weakened under its old name and still pass.
This pins, for every invariant row, its statement, its list of witnesses and the normalized
body of each witness, in docs/witness-manifest.json signed by the owner (ssh-keygen -Y).

    witness-pin.py check [--signers FILE]   # CI: exit 1 on an unsigned change
    witness-pin.py sign --key PRIVATE_KEY   # owner: re-pin the current tree and sign it

Comments and formatting do not change a body's hash; any other byte of the body does.
A row or witness that is new and not yet pinned is reported, not refused: it guards nothing
the owner has accepted yet. Removing or changing what is pinned is refused.
"""
import ast
import hashlib
import json
from itertools import islice
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
INVARIANTS = ROOT / "docs/INVARIANTS.md"
MANIFEST = ROOT / "docs/witness-manifest.json"
SIGNATURE = ROOT / "docs/witness-manifest.json.sig"
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
    return '| ' + rid + ' | ' + contract['statement'] + ' | ' + contract['evidence_text'] + ' |'


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


def generated_invariants(text: str, root: pathlib.Path) -> str:
    """Validate all source-backed slots using bounded local contract data only."""
    marker_ids = [m.group(1) for m in GENERATED_MARKER.finditer(text)]
    if len(marker_ids) != text.count('<!-- Generated ') or len(set(marker_ids)) != len(marker_ids):
        raise ValueError('Malformed or duplicate generated contract marker')
    directory = root / 'docs/contracts'
    if directory.is_symlink():
        raise ValueError('Symlink contract directory refused')
    sources = list(islice(directory.glob('*.shadow.json'), MAX_CONTRACTS + 1))
    if len(sources) > MAX_CONTRACTS:
        raise ValueError('Too many contracts')
    sources.sort()
    source_ids = set()
    for path in sources:
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
        projected = project_invariants(text, contract)
        if projected != text:
            raise ValueError('Generated ' + rid + ' is stale; regenerate from its contract')
        source_ids.add(rid)
    if source_ids != set(marker_ids):
        raise ValueError('Generated markers and contract sources differ')
    return text


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


def rust_parts(src: str) -> list[tuple[bool, str]]:
    """Comment-free code/literal segments; literal bytes never enter layout normalization."""
    out, i, n = [], 0, len(src)
    while i < n:
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
        elif (m := re.match(r'b?r(#*)"', src[i:])) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            end = src.find('"' + m.group(1), i + m.end())
            end = n if end < 0 else end + 1 + len(m.group(1))
            out.append((True, src[i:end]))
            i = end
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append((True, src[i:j + 1]))
            i = j + 1
        elif c == "'" and (m := re.match(r"'(\\.[^']*|[^\\'])'", src[i:])):
            out.append((True, m.group(0)))
            i += m.end()
        else:
            if out and not out[-1][0]:
                out[-1] = (False, out[-1][1] + c)
            else:
                out.append((False, c))
            i += 1
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


def current() -> dict:
    table = rows()
    cited = {w for r in table.values() for w in r["witnesses"]}
    bodies = {**rust_bodies({w for w in cited if RUST_TEST.fullmatch(w)}),
              **py_bodies({w for w in cited if PY_TEST.fullmatch(w)})}
    return {"rows": table, "witnesses": {w: sorted(bodies.get(w, [])) for w in sorted(cited)}}


def verify_manifest(manifest: pathlib.Path, signature: pathlib.Path, signers: pathlib.Path) -> bool:
    """Verify owner against the supplied trust file; callers choose its trusted provenance."""
    if not (manifest.exists() and signature.exists() and signers.exists()):
        return False
    r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", "owner", "-n", NAMESPACE,
                        "-s", str(signature)], input=manifest.read_bytes(), capture_output=True, timeout=10)
    return r.returncode == 0


def verify(signers: pathlib.Path) -> bool:
    return verify_manifest(MANIFEST, SIGNATURE, signers)


def check(signers: pathlib.Path) -> int:
    now = current()
    problems, notes = [], []
    for w, where in now["witnesses"].items():
        if not where:
            problems.append(f"witness {w} is cited but no test function has that name")
    if not verify(signers):
        problems.append(f"{MANIFEST.relative_to(ROOT)} is not signed by a key in {signers}")
        pinned = {"rows": {}, "witnesses": {}}
    else:
        pinned = json.loads(MANIFEST.read_text())
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
            problems.append(f"witness {w} changed: its body is not the one the owner pinned")
    for rid in sorted(set(now["rows"]) - set(pinned["rows"])):
        notes.append(f"{rid}: new invariant row, not pinned yet")
    for x in notes:
        print("note", x)
    for x in problems:
        print("FAIL", x)
    if problems:
        print("A pinned witness or invariant changes only with a new owner signature: scripts/witness-pin.py sign")
        return 1
    print(f"ok   {len(pinned['rows'])} invariant rows and {len(pinned['witnesses'])} witnesses match the owner's pins")
    return 0


def sign(key: str) -> int:
    now = current()
    missing = [w for w, where in now["witnesses"].items() if not where]
    if missing:
        print("FAIL refusing to pin witnesses that do not exist:", ", ".join(missing))
        return 1
    MANIFEST.write_text(json.dumps(now, indent=1, sort_keys=True) + "\n")
    # ssh-keygen asks before overwriting a signature and, without a terminal, keeps the old
    # one and still exits 0: a re-pin would leave the previous signature in place.
    SIGNATURE.unlink(missing_ok=True)
    subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", key, "-n", NAMESPACE, str(MANIFEST)],
                   stdin=subprocess.DEVNULL, check=True)
    pathlib.Path(str(MANIFEST) + ".sig").replace(SIGNATURE)
    print(f"signed {len(now['rows'])} rows, {len(now['witnesses'])} witnesses")
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["sign"] and "--key" in args:
        sys.exit(sign(args[args.index("--key") + 1]))
    if args[:1] == ["check"]:
        sys.exit(check(pathlib.Path(args[args.index("--signers") + 1]) if "--signers" in args else SIGNERS))
    print(__doc__)
    sys.exit(2)
