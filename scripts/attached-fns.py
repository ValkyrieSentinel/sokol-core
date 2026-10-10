#!/usr/bin/env python3
"""Names of the Rust functions that carry an attribute: the attribute must be attached to the
function, not merely near it.

    scripts/attached-fns.py '#[kani::proof]' FILE...

A function carries the attributes directly above it, with only other attributes, comments and
blank lines in between; any other line (the end of the previous function, a statement) breaks
the chain. A text search a few lines up from `fn name` accepted a helper defined just after a
proof as that proof. This reads the source as written and does not expand macros: a function
generated inside a macro body (proptest!) is listed only if the attribute is written there.
"""
import re
import sys

FN = re.compile(r'^\s*(pub(\([^)]*\))?\s+)?((const|async|unsafe|extern\s+"[^"]*")\s+)*fn\s+([A-Za-z_][A-Za-z0-9_]*)')


def attached(attr, text):
    names, pending, depth, current = [], [], 0, ''
    for line in text.splitlines():
        stripped = line.strip()
        if depth:                       # inside a multi-line attribute
            current += ' ' + stripped
            depth += stripped.count('[') - stripped.count(']')
            if depth <= 0:
                pending.append(current)
                depth = 0
            continue
        if stripped.startswith('#[') or stripped.startswith('#!['):
            depth = stripped.count('[') - stripped.count(']')
            if depth <= 0:
                pending.append(stripped)
                depth = 0
            else:
                current = stripped
            continue
        if not stripped or stripped.startswith('//'):
            continue
        m = FN.match(line)
        if m and any(a.startswith(attr) for a in pending):
            names.append(m.group(5))
        pending = []
    return names


def main(argv):
    if len(argv) < 2:
        sys.exit('usage: attached-fns.py ATTRIBUTE FILE...')
    attr = argv[0]
    for path in argv[1:]:
        with open(path, encoding='utf-8') as f:
            for name in attached(attr, f.read()):
                print(name)


if __name__ == '__main__':
    main(sys.argv[1:])
