#!/usr/bin/env python3
"""Summarise gcov line coverage for product sources (libs/, nf/, ctl/), ignoring tests, generated code and fuzz drivers."""
import json, os, subprocess, sys, gzip, collections

build, root, minpct = sys.argv[1], sys.argv[2], float(sys.argv[3])
gcdas = [os.path.join(d, f) for d, _, fs in os.walk(build) for f in fs if f.endswith('.gcda')]
cov = collections.defaultdict(dict)  # file -> line -> max count
for g in gcdas:
    out = subprocess.run(['gcov', '--json-format', '--stdout', '-o', os.path.dirname(g), g], capture_output=True, cwd=build)
    if out.returncode != 0 or not out.stdout:
        continue
    for chunk in out.stdout.decode().splitlines():
        if not chunk.strip():
            continue
        try:
            doc = json.loads(chunk)
        except ValueError:
            continue
        for f in doc.get('files', []):
            path = os.path.normpath(os.path.join(doc.get('current_working_directory', build), f['file']))
            for ln in f['lines']:
                cov[path][ln['line_number']] = max(cov[path].get(ln['line_number'], 0), ln['count'])
skip = ('/tests/', '/fuzz/', '/testkit/', '/generated', '.gen.c', 'ngap/src/schema.c', 'defs.c', 'ngap_ids', 'perf_')
rows = []
for path, lines in cov.items():
    rel = os.path.relpath(path, root)
    if rel.startswith('..') or not rel.startswith(('libs/', 'nf/', 'ctl/')) or any(s in '/' + rel for s in skip):
        continue
    tot = len(lines); hit = sum(1 for c in lines.values() if c > 0)
    rows.append((rel, hit, tot))
rows.sort()
bydir = collections.defaultdict(lambda: [0, 0])
for rel, hit, tot in rows:
    d = '/'.join(rel.split('/')[:2]); bydir[d][0] += hit; bydir[d][1] += tot
print('%-46s %6s %6s %7s' % ('file', 'hit', 'lines', 'cover'))
for rel, hit, tot in rows:
    print('%-46s %6d %6d %6.1f%%' % (rel, hit, tot, 100.0 * hit / max(tot, 1)))
print()
for d, (h, t) in sorted(bydir.items()):
    print('%-46s %6d %6d %6.1f%%' % (d, h, t, 100.0 * h / max(t, 1)))
H = sum(r[1] for r in rows); T = sum(r[2] for r in rows)
print('%-46s %6d %6d %6.1f%%' % ('TOTAL', H, T, 100.0 * H / max(T, 1)))
if os.environ.get('COV_JSON'):
    json.dump({'total': {'hit': H, 'lines': T}, 'dirs': {d: {'hit': h, 'lines': t} for d, (h, t) in sorted(bydir.items())},
               'files': {r[0]: {'hit': r[1], 'lines': r[2]} for r in rows}}, open(os.environ['COV_JSON'], 'w'), indent=1)
bad = [r for r in rows if r[2] and 100.0 * r[1] / r[2] < minpct]
if minpct and bad:
    print('\nbelow %.0f%%: %s' % (minpct, ', '.join(r[0] for r in bad)))
    sys.exit(1)

want = os.environ.get('MISSING')
if want:
    for path, lines in sorted(cov.items()):
        rel = os.path.relpath(path, root)
        if want in rel:
            miss = sorted(n for n, c in lines.items() if c == 0)
            runs, start = [], None
            for n in miss:
                if start is not None and n == prev + 1:
                    prev = n; continue
                if start is not None:
                    runs.append((start, prev))
                start = prev = n
            if start is not None:
                runs.append((start, prev))
            print(rel, ' '.join('%d' % a if a == b else '%d-%d' % (a, b) for a, b in runs))
