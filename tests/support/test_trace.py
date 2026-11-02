#!/usr/bin/env python3
"""tools/g5c-trace: text and JSON logs are joined by trace id across files, filtered by identity, and ordered in time."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent.parent / "tools" / "g5c-trace"
T1, T2 = "0af7651916cd43dd8448eb211c80319c", "11111111111111111111111111111111"


def run(*a):
    return subprocess.run([sys.executable, str(TOOL), *a], capture_output=True, text=True)


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "amf.log").write_text(
            "2026-11-02T10:00:00.000100Z  INFO g5c_amf: registration of imsi-001010000000001 accepted trace=%s\n"
            "2026-11-02T10:00:00.500000Z  INFO g5c_amf: unrelated line without a trace\n"
            "2026-11-02T10:00:01.000000Z  INFO g5c_amf: registration of imsi-001010000000002 accepted trace=%s\n" % (T1, T2))
        (d / "udm.log").write_text("2026-11-02T10:00:00.050000Z  INFO g5c_udm: imsi-001010000000001: AMF registration stored trace=%s\n" % T1)
        (d / "smf.log").write_text(json.dumps({"timestamp": "2026-11-02T10:00:00.300000Z", "level": "INFO", "target": "g5c_smf", "message": "session for imsi-001010000000001 created", "trace_id": T1, "span_id": "ab"}) + "\n"
                                   + json.dumps({"timestamp": "2026-11-02T10:00:00.400000Z", "level": "INFO", "target": "g5c_smf", "message": "no trace here"}) + "\n")
        p = run(str(d))
        check("two traces listed, the first across three functions", p.returncode == 0 and "2 traces" in p.stdout and "amf, smf, udm" in p.stdout, p.stdout)
        p = run(str(d), "--id", T1[:8])
        lines = [l for l in p.stdout.splitlines() if l.startswith("  +")]
        check("one trace's timeline: 3 lines in time order from three functions", len(lines) == 3 and "amf" in lines[0] and "udm" in lines[1] and "smf" in lines[2], p.stdout)
        check("the span covers 0.3 s", "0.300 s" in p.stdout or "0.299 s" in p.stdout or "0.300" in p.stdout, p.stdout)
        p = run(str(d), "--supi", "imsi-001010000000002")
        check("--supi keeps the trace that mentions the identity", "1 traces" in p.stdout and T2 in p.stdout and T1 not in p.stdout, p.stdout)
        check("--min-functions 3 keeps only the wide trace", "1 traces" in run(str(d), "--min-functions", "3").stdout)
        check("a missing trace id: exit 1", run(str(d), "--id", "ffff").returncode == 1)
        check("JSON output is parseable", set(json.loads(run(str(d), "--json").stdout)) == {T1, T2})
    print("trace: PASS" if ok else "trace: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
