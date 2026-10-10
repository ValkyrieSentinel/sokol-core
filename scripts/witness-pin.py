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


def rows() -> dict:
    found = {}
    for line in INVARIANTS.read_text().splitlines():
        m = ROW.match(line)
        if not m:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        spans = re.findall(r"`([^`]+)`", cells[-1])
        found[m.group(1)] = {
            "statement": sha(" ".join(" | ".join(cells[1:-1]).split())),
            "witnesses": sorted({s for s in spans if RUST_TEST.fullmatch(s) or PY_TEST.fullmatch(s)}),
        }
    return found


def strip_rust(src: str) -> str:
    """Source without comments; string and char literals kept byte for byte."""
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
            out.append(src[i:end])
            i = end
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        elif c == "'" and (m := re.match(r"'(\\.[^']*|[^\\'])'", src[i:])):
            out.append(m.group(0))
            i += m.end()
        else:
            out.append(c)
            i += 1
    return "".join(out)


def squeeze(code: str) -> str:
    """Whitespace only where it separates two words, so rustfmt line breaks do not count."""
    code = re.sub(r"\s+", " ", code)
    return re.sub(r" (?=\W)|(?<=\W) ", "", code)


def rust_bodies(names: set[str]) -> dict[str, list[str]]:
    bodies: dict[str, list[str]] = {}
    for path in git_files("*.rs"):
        src = strip_rust(path.read_text())
        for m in re.finditer(r"\bfn ([a-z][a-z0-9_]*)\s*[(<]", src):
            if m.group(1) not in names:
                continue
            start = src.find("{", m.end())
            depth, j = 0, start
            for j in range(start, len(src)):
                depth += {"{": 1, "}": -1}.get(src[j], 0)
                if depth == 0:
                    break
            rel = path.relative_to(ROOT).as_posix()
            bodies.setdefault(m.group(1), []).append(f"{rel}:{sha(squeeze(src[m.start():j + 1]))}")
    return bodies


def py_bodies(names: set[str]) -> dict[str, list[str]]:
    bodies: dict[str, list[str]] = {}
    for path in git_files("*.py"):
        tree = ast.parse(path.read_text())
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
            for fn in cls.body:
                key = f"{cls.name}.{getattr(fn, 'name', '')}"
                if key in names and isinstance(fn, ast.FunctionDef):
                    rel = path.relative_to(ROOT).as_posix()
                    bodies.setdefault(key, []).append(f"{rel}:{sha(ast.unparse(fn))}")
    return bodies


def current() -> dict:
    table = rows()
    cited = {w for r in table.values() for w in r["witnesses"]}
    bodies = {**rust_bodies({w for w in cited if RUST_TEST.fullmatch(w)}),
              **py_bodies({w for w in cited if PY_TEST.fullmatch(w)})}
    return {"rows": table, "witnesses": {w: sorted(bodies.get(w, [])) for w in sorted(cited)}}


def verify(signers: pathlib.Path) -> bool:
    if not (MANIFEST.exists() and SIGNATURE.exists() and signers.exists()):
        return False
    r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", "owner", "-n", NAMESPACE,
                        "-s", str(SIGNATURE)], input=MANIFEST.read_bytes(), capture_output=True)
    return r.returncode == 0


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
