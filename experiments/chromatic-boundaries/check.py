#!/usr/bin/env python3
"""Bounded source inventory + proposed port contracts; NOT a Rust effect checker."""
import argparse
import copy
import hashlib
import html
import json
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
# Lexical indicators are deliberately named signals, never proven effects.
PATTERNS = {
    'host_read': r'\b(?:libc::getifaddrs|std::fs::read_to_string)\b',
    'disk': r'\b(?:std::fs::|File::|OpenOptions::)',
    'network': r'\b(?:TcpStream|TcpListener|UdpSocket)\b',
    'ipc': r'\bUnixStream\b',
    'kernel': r'\baya::',
    'process': r'\b(?:tokio|std)::process::',
    'clock': r'\b(?:Instant|SystemTime)::now\b',
    'log': r'\b(?:(?:log::)?(?:warn|error|info|debug|trace)|println|eprintln)!',
    'unsafe': r'\bunsafe\s*\{',
    'sign': r'\bdetached_sign\s*\(',
}
# Not an ordered privilege scale. RGB is the presence of three effect families.
FAMILIES = ({'host_read', 'disk', 'kernel', 'process', 'unsafe'},
            {'network', 'ipc'}, {'clock', 'log', 'sign'})


def scrub(source):
    """Mask comments/literals preserving offsets. Handles nested Rust block comments."""
    out = list(source)
    i = 0
    while i < len(source):
        end = None
        if source.startswith('//', i):
            end = source.find('\n', i)
            if end < 0:
                end = len(source)
        elif source.startswith('/*', i):
            j, depth = i + 2, 1
            while j < len(source) and depth:
                if source.startswith('/*', j):
                    depth += 1
                    j += 2
                elif source.startswith('*/', j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            end = j
        else:
            raw = re.match(r'(?:br|r)(#*)"', source[i:])
            if raw:
                closing = '"' + raw[1]
                j = source.find(closing, i + len(raw[0]))
                end = len(source) if j < 0 else j + len(closing)
            elif source[i] == '"':
                j = i + 1
                while j < len(source):
                    if source[j] == '\\':
                        j += 2
                    elif source[j] == '"':
                        j += 1
                        break
                    else:
                        j += 1
                end = j
            elif source[i] == "'":
                char = re.match(r"'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'", source[i:])
                if char:
                    end = i + len(char[0])
        if end is not None:
            for k in range(i, min(end, len(source))):
                if out[k] != '\n':
                    out[k] = ' '
            i = end
        else:
            i += 1
    return ''.join(out)


def surface(source):
    code = scrub(source)
    # Exact trailing test module convention in sampled files; other cfgs stay included.
    test = re.search(r'#\[cfg\(test\)\]\s*mod\s+tests\s*\{', code)
    return code[:test.start()] if test else code


def inspect_source(source, names, aliases):
    code = surface(source)
    signals = []
    for kind, pattern in PATTERNS.items():
        for m in re.finditer(pattern, code):
            signals.append({'kind': kind, 'line': code.count('\n', 0, m.start()) + 1,
                            'token': m[0]})
    deps, unresolved = set(), set()
    for m in re.finditer(r'\bcrate::([A-Za-z_]\w*)', code):
        name = aliases.get(m[1], m[1])
        (deps if name in names else unresolved).add(name)
    for m in re.finditer(r'(?m)^\s*(?:pub\s+)?mod\s+(\w+)\s*;', code):
        if m[1] in names:
            deps.add(m[1])
        else:
            unresolved.add(m[1])
    if re.search(r'\bcommon::audit_log\b', code) and 'audit_log' in names:
        deps.add('audit_log')
    return {'signals': signals, 'dependencies': sorted(deps), 'unresolved': sorted(unresolved)}


def closure(graph, source):
    paths = {source: [source]}
    todo = [source]
    while todo:
        node = todo.pop(0)
        for dep in graph[node]:
            if dep not in paths:
                paths[dep] = paths[node] + [dep]
                todo.append(dep)
    return paths


def rgb(kinds):
    return '#' + ''.join('F' if set(kinds) & family else '0' for family in FAMILIES)


def check_ports(model):
    errors = []
    endpoints = model['endpoints']
    for a, b in model['connections']:
        if a not in endpoints or b not in endpoints:
            errors.append(f'unknown endpoint: {a} -> {b}')
            continue
        sender, receiver = endpoints[a], endpoints[b]
        if sender['direction'] != 'out' or receiver['direction'] != 'in':
            errors.append(f'direction: {a} -> {b}')
            continue
        if sender['schema'] != receiver['schema']:
            errors.append(f'schema: {a} -> {b}')
        missing = set(receiver['requires']) - set(sender['grants'])
        if missing:
            errors.append(f'authority: {a} -> {b}; missing {sorted(missing)}')
        excess = set(receiver['effects']) - set(sender['allows_effects'])
        if excess:
            errors.append(f'effect budget: {a} -> {b}; excess {sorted(excess)}')
    return errors


def audit(root, manifest):
    nodes = {}
    names = set(manifest['modules'])
    for name, spec in manifest['modules'].items():
        data = (root / spec['path']).read_bytes()
        nodes[name] = dict(path=spec['path'], sha256=hashlib.sha256(data).hexdigest(),
                           **inspect_source(data.decode(), names, manifest['aliases']))
    graph = {n: v['dependencies'] for n, v in nodes.items()}
    for name, node in nodes.items():
        paths = closure(graph, name)
        direct = sorted({s['kind'] for s in node['signals']})
        reachable = sorted({s['kind'] for dep in paths for s in nodes[dep]['signals']})
        node.update(direct=direct, reachable=reachable, rgb=rgb(reachable),
                    alpha='F' if direct else '?')
    components, seen = [], set()
    for n in sorted(nodes):
        if n in seen:
            continue
        component = sorted(m for m in closure(graph, n) if n in closure(graph, m))
        seen.update(component)
        if len(component) > 1 or n in graph[n]:
            components.append(component)
    hypotheses = []
    for name in manifest['pure_module_hypotheses']:
        paths = closure(graph, name)
        witnesses = [{'path': path, 'signals': nodes[dep]['signals']}
                     for dep, path in paths.items() if nodes[dep]['signals']]
        hypotheses.append({'module': name, 'status': 'not_supported' if witnesses else 'unknown',
                           'witnesses': witnesses})
    return {'nodes': nodes, 'module_cycles': components, 'hypotheses': hypotheses,
            'port_errors': check_ports(manifest['ports'])}


def render(result, ports):
    rows = []
    for name, node in result['nodes'].items():
        color = '#' + ''.join(c * 2 for c in node['rgb'][1:])
        rows.append('<tr><td><span class="swatch" style="background:' + color + '"></span>'
                    + html.escape(name) + '</td><td>' + html.escape(node['rgb'])
                    + '</td><td>' + html.escape(node['alpha']) + '</td><td>'
                    + html.escape(', '.join(node['direct']) or 'none detected — unknown')
                    + '</td><td>' + html.escape(', '.join(node['dependencies'])) + '</td></tr>')
    port_rows = []
    for name, port in ports['endpoints'].items():
        effects = port.get('effects', port.get('allows_effects', []))
        caps = port.get('requires', port.get('grants', []))
        port_rows.append('<tr>' + ''.join('<td>' + html.escape(str(x)) + '</td>' for x in (name, port['direction'], port['schema'], rgb(effects), ', '.join(caps) or 'none')) + '</tr>')
    port_table = '<h2>Proposed logical ports</h2><p>Color encodes effect categories only. Equal colors do not grant authority. These are design fixtures, not TCP/UDP assignments.</p><table><tr><th>Port</th><th>Direction</th><th>Schema</th><th>Effect RGB</th><th>Granted / required capabilities</th></tr>' + ''.join(port_rows) + '</table>'
    return '''<!doctype html><html lang="uk"><meta charset="utf-8"><title>Chromatic boundaries</title>
<style>body{font:16px system-ui;max-width:1200px;margin:40px auto;padding:0 20px;background:#111820;color:#e9edf3}table{border-collapse:collapse;width:100%}td,th{padding:12px;text-align:left;border-bottom:1px solid #425063}.swatch{display:inline-block;width:18px;height:18px;border:1px solid #aaa;margin-right:10px}pre{white-space:pre-wrap}small{color:#bdc9db}</style>
<h1>Chromatic boundaries · experiment</h1>
<p>RGB: R=host/system, G=communication, B=context/observation. Presence bits, not privilege levels.
Alpha F = a lexical signal exists; ? = unknown, never a purity proof. No opacity hides text.</p>
<p>Module dependency reachability over-approximates use. This is not a call graph or a runtime authority check.</p>
<table><tr><th>Module</th><th>Reachable RGB</th><th>Alpha (direct)</th><th>Direct signals</th><th>Dependencies in sample</th></tr>''' + ''.join(rows) + '</table><h2>Cycles at module granularity</h2><pre>' + html.escape(json.dumps(result['module_cycles'], indent=2)) + '</pre>' + port_table + '<p>Full evidence and paths: result.json. Port contracts are proposed fixtures, not extracted live endpoints.</p></html>'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=HERE / 'manifest.json')
    parser.add_argument('--out', type=Path, default=HERE / 'results')
    parser.add_argument('--ports-only', action='store_true')
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    if args.ports_only:
        errors = check_ports(manifest['ports'])
        print(json.dumps({'errors': errors}, indent=2))
        return bool(errors)
    result = audit(ROOT, manifest)
    result['source_commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    result['manifest_sha256'] = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    result['checker_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result['scope'] = 'lexical inventory; proposed ports; no runtime/purity/capability proof'
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    (args.out / 'map.html').write_text(render(result, manifest['ports']))
    print(json.dumps({'modules': len(result['nodes']), 'module_cycles': result['module_cycles'],
                      'hypotheses': [{k:v for k,v in h.items() if k != 'witnesses'} for h in result['hypotheses']],
                      'port_errors': result['port_errors']}, indent=2))
    return bool(result['port_errors'])


if __name__ == '__main__':
    sys.exit(main())
