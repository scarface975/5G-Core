#!/usr/bin/env python3
"""Performance history per release (backlog E-06): the numbers of a regression run, kept release by release, a regression flagged against the earlier ones, a chart.

  perf_history.py record [--summary build/regress-summary.txt] [--version V] [--note TEXT]   append the run to docs/perf/history.jsonl (a run of the same version replaces the earlier one)
  perf_history.py check  [--tolerance 0.4] [--last 5]                                      exit 1 when the newest entry is worse than the median of the earlier ones by more than the tolerance
  perf_history.py chart  [--out docs/perf/history.html]                                    a self-contained page with one line per metric

The numbers come from the summary that scripts/g5c_regress.sh writes (the SLO lines of the cluster load runs and the UPF benchmark). A shared host swings by a factor of three between
runs (docs/ops/slo.md), so the default tolerance is wide: the check catches a collapse, not a few percent."""
import argparse
import datetime
import html
import json
import re
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HIST = ROOT / "docs" / "perf" / "history.jsonl"
# metric -> (label, unit, higher_is_better)
METRICS = {
    "reg_per_s": ("Registrations with a session per second", "UE/s", True),
    "reg_per_s_tls": ("Same, mutual TLS", "UE/s", True),
    "p99_registration_ms": ("Registration p99", "ms", False),
    "p99_registration_ms_tls": ("Registration p99, mutual TLS", "ms", False),
    "upf_uplink_gbit": ("UPF uplink, one core", "Gbit/s", True),
    "upf_downlink_gbit": ("UPF downlink, one core", "Gbit/s", True),
}


def version_now():
    v = ROOT / "VERSION"
    return v.read_text().strip() if v.exists() else "unknown"


def parse_summary(text):
    m = {}
    for tag, suffix in (("cluster-load", ""), ("cluster-load-tls", "_tls")):
        r = re.search(r"SLO \(%s\):.*?throughput (\d+) UE/s, p99 registration ([0-9.]+) ms" % re.escape(tag), text)
        if r:
            m["reg_per_s" + suffix] = float(r.group(1))
            m["p99_registration_ms" + suffix] = float(r.group(2))
    for key, word in (("upf_uplink_gbit", "uplink"), ("upf_downlink_gbit", "downlink")):
        r = re.search(r"UPF %s\s+best: ([0-9.]+) Gbit/s delivered" % word, text)
        if r:
            m[key] = float(r.group(1))
    return m


def load():
    if not HIST.exists():
        return []
    return [json.loads(l) for l in HIST.read_text().splitlines() if l.strip()]


def save(entries):
    HIST.parent.mkdir(parents=True, exist_ok=True)
    HIST.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))


def regress(entries, tol, last):
    """List of (metric, newest, median of the earlier ones) that got worse by more than tol."""
    if len(entries) < 2:
        return []
    new, old = entries[-1], entries[-1 - last:-1]
    bad = []
    for k, (_, _, higher) in METRICS.items():
        prev = [e["metrics"][k] for e in old if k in e["metrics"]]
        if k not in new["metrics"] or not prev:
            continue
        med, cur = statistics.median(prev), new["metrics"][k]
        worse = cur < med * (1 - tol) if higher else cur > med * (1 + tol)
        if worse:
            bad.append((k, cur, med))
    return bad


def chart(entries):
    rows = []
    for k, (label, unit, _) in METRICS.items():
        pts = [(e["version"], e["metrics"][k]) for e in entries if k in e["metrics"]]
        if not pts:
            continue
        w, h, pad = 420, 120, 28
        lo, hi = min(v for _, v in pts), max(v for _, v in pts)
        span = (hi - lo) or max(hi, 1.0)
        xs = [pad + (i * (w - 2 * pad) / max(len(pts) - 1, 1)) for i in range(len(pts))]
        ys = [h - pad - ((v - lo) / span) * (h - 2 * pad) for _, v in pts]
        poly = " ".join("%.1f,%.1f" % (x, y) for x, y in zip(xs, ys))
        dots = "".join('<circle cx="%.1f" cy="%.1f" r="3"><title>%s: %g %s</title></circle>' % (x, y, html.escape(ver), v, unit) for x, y, (ver, v) in zip(xs, ys, pts))
        names = "".join('<text x="%.1f" y="%d" text-anchor="middle" font-size="9">%s</text>' % (x, h - 8, html.escape(ver)) for x, (ver, _) in zip(xs, pts))
        rows.append('<figure><figcaption>%s (%s): %g now, range %g to %g</figcaption><svg viewBox="0 0 %d %d" width="%d"><polyline fill="none" stroke="currentColor" stroke-width="2" points="%s"/>%s%s</svg></figure>'
                    % (html.escape(label), unit, pts[-1][1], lo, hi, w, h, w, poly, dots, names))
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>g5c performance history</title>'
            '<style>body{font:14px system-ui;margin:16px;max-width:900px}figure{margin:0 0 18px}figcaption{font-weight:600;margin-bottom:4px}svg{max-width:100%%;height:auto;color:#2a7f8e}'
            'circle{fill:#1f3a5f}@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}svg{color:#6cc}circle{fill:#9bd}}</style>'
            '<h1>Performance history</h1><p>One point per release, from the regression summary of that release. A shared host swings by a factor of three between runs: read the trend, not the last digit.</p>%s</html>'
            % "".join(rows))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record")
    r.add_argument("--summary", default=str(ROOT / "build" / "regress-summary.txt"))
    r.add_argument("--version")
    r.add_argument("--note", default="")
    c = sub.add_parser("check")
    c.add_argument("--tolerance", type=float, default=0.4)
    c.add_argument("--last", type=int, default=5)
    h = sub.add_parser("chart")
    h.add_argument("--out", default=str(ROOT / "docs" / "perf" / "history.html"))
    a = ap.parse_args()
    entries = load()
    if a.cmd == "record":
        m = parse_summary(Path(a.summary).read_text(errors="replace"))
        if not m:
            print("perf_history: no performance numbers in %s" % a.summary, file=sys.stderr)
            return 1
        ver = a.version or version_now()
        entry = {"version": ver, "date": datetime.date.today().isoformat(), "metrics": m, "note": a.note}
        entries = [e for e in entries if e["version"] != ver] + [entry]
        save(entries)
        print("recorded %s: %s" % (ver, ", ".join("%s=%g" % kv for kv in sorted(m.items()))))
        return 0
    if a.cmd == "check":
        bad = regress(entries, a.tolerance, a.last)
        for k, cur, med in bad:
            print("REGRESSION %s: %g against a median of %g" % (METRICS[k][0], cur, med))
        print("perf: %s (%d entries)" % ("FAIL" if bad else "PASS", len(entries)))
        return 1 if bad else 0
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(chart(entries))
    print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
