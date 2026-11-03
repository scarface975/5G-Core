#!/usr/bin/env python3
"""tools/cli/g5c-cdr: the totals of a small hand-made CDR file, every grouping, roaming, the period, CSV export, and the data quality checks (a gap in the sequence, a duplicate, an unreadable line,
a session without a measurement) with the exit code."""
import csv
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent.parent / "tools" / "cli" / "g5c-cdr"
INST = "11111111-2222-3333-4444-555555555555"


def rec(seq, supi, dnn, sst, start, end, dur, ul, dl, cause="released by the AMF", upf="upf-1", measured=True, sd=None):
    s = {"sst": sst}
    if sd:
        s["sd"] = sd
    return {"recordType": "pduSession", "recordSequenceNumber": seq, "smfInstanceId": INST, "supi": supi, "pduSessionId": 1, "dnn": dnn, "snssai": s, "ueIpv4Address": "10.45.0.%d" % seq, "upf": upf,
            "startTime": start, "endTime": end, "duration": dur, "usageReported": measured, "uplinkOctets": ul, "downlinkOctets": dl, "totalOctets": ul + dl, "uplinkPackets": ul // 100,
            "downlinkPackets": dl // 100, "closeCause": cause}


GOOD = [
    rec(1, "imsi-001010000000001", "internet", 1, "2026-11-03T10:00:00Z", "2026-11-03T10:10:00Z", 600, 1000000, 9000000),
    rec(2, "imsi-001010000000002", "internet", 1, "2026-11-03T10:30:00Z", "2026-11-03T10:31:00Z", 60, 100000, 400000, cause="the UE asked to release it"),
    rec(3, "imsi-001010000000001", "ims", 2, "2026-11-03T11:05:00Z", "2026-11-03T11:05:03Z", 3, 0, 0, upf="upf-2", sd="010203"),
    rec(4, "imsi-001020000000009", "internet", 1, "2026-11-03T11:20:00Z", "2026-11-03T11:30:00Z", 600, 2000000, 8000000),  # a roamer (PLMN 00102)
]


def run(*a):
    return subprocess.run([sys.executable, str(TOOL), *a], capture_output=True, text=True)


def write(path, records, extra=()):
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
        for x in extra:
            f.write(x + "\n")


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "cdr.jsonl")
        write(f, GOOD)
        p = run("report", f, "--json", "--home", "00101")
        r = json.loads(p.stdout)
        t = r["totals"]
        check("totals: 4 sessions, 3 subscribers, 21.5 MB", p.returncode == 0 and t["sessions"] == 4 and t["subscribers"] == 3 and t["uplinkOctets"] == 3100000 and t["downlinkOctets"] == 17400000
              and t["totalOctets"] == 20500000, t)
        check("session length and throughput", t["sessionSeconds"] == 1263 and t["durationP50"] == 60 and t["durationP95"] == 600 and abs(t["avgThroughputKbps"] - 129.9) < 0.2, t)
        check("by dnn", r["groups"]["internet"]["sessions"] == 3 and r["groups"]["ims"]["sessions"] == 1 and r["groups"]["internet"]["totalOctets"] == 20500000, r["groups"])
        check("by slice shows the SD", set(json.loads(run("report", f, "--json", "--by", "slice").stdout)["groups"]) == {"1", "2-010203"})
        check("by upf", set(json.loads(run("report", f, "--json", "--by", "upf").stdout)["groups"]) == {"upf-1", "upf-2"})
        check("by hour", set(json.loads(run("report", f, "--json", "--by", "hour").stdout)["groups"]) == {"2026-11-03 10:00", "2026-11-03 11:00"})
        check("by day", list(json.loads(run("report", f, "--json", "--by", "day").stdout)["groups"]) == ["2026-11-03"])
        check("by subscriber", len(json.loads(run("report", f, "--json", "--by", "supi").stdout)["groups"]) == 3)
        check("why sessions ended", r["closeCauses"] == {"released by the AMF": 3, "the UE asked to release it": 1}, r["closeCauses"])
        check("roaming: one inbound session from PLMN 00102, 25 %", r["roaming"]["inboundSessions"] == 1 and r["roaming"]["byPlmn"] == {"00102": 1} and r["roaming"]["inboundShare"] == 25.0, r["roaming"])
        check("the heaviest subscriber first", r["topSubscribers"][0] == {"supi": "imsi-001010000000001", "totalOctets": 10000000} or r["topSubscribers"][0]["supi"] == "imsi-001020000000009", r["topSubscribers"])
        check("clean data: no quality problem", r["quality"]["missingRecords"] == 0 and r["quality"]["duplicateRecords"] == 0 and r["quality"]["zeroTrafficSessions"] == 1 and r["quality"]["shortSessions"] == 1, r["quality"])
        check("the text report reads", "4 sessions of 3 subscribers" in run("report", f).stdout and "roaming" not in run("report", f).stdout)

        p = run("report", f, "--json", "--from", "2026-11-03T11:00:00Z", "--to", "2026-11-03T12:00:00Z")
        check("--from and --to bound the period by the end time of a session", json.loads(p.stdout)["totals"]["sessions"] == 2, p.stdout[:200])
        check("an empty period says so", "no records" in run("report", f, "--from", "2030-01-01T00:00:00Z").stdout)
        check("a bad time is a usage error", run("report", f, "--from", "yesterday").returncode == 2)

        out = os.path.join(d, "all.csv")
        p = run("export", f, "--csv", out)
        rows = list(csv.reader(open(out)))
        check("CSV: header and one line per record, the slice as text", p.returncode == 0 and len(rows) == 5 and rows[0][0] == "recordSequenceNumber" and rows[3][rows[0].index("snssai")] == "2-010203", rows[:2])

        # the data itself is wrong
        bad = os.path.join(d, "bad.jsonl")
        write(bad, [GOOD[0], GOOD[1], GOOD[3]], extra=["{ not json"])
        r = json.loads(run("report", bad, "--json").stdout)
        p = run("report", bad)
        check("a gap in the sequence and an unreadable line are found, exit 1", r["quality"]["missingRecords"] == 1 and r["quality"]["unreadableLines"] == 1 and p.returncode == 1, r["quality"])
        write(bad, GOOD + [GOOD[1]])
        r = json.loads(run("report", bad, "--json").stdout)
        check("a duplicate is found", r["quality"]["duplicateRecords"] == 1 and run("report", bad).returncode == 1, r["quality"])
        write(bad, [rec(1, "imsi-001010000000001", "internet", 1, "2026-11-03T10:00:00Z", "2026-11-03T10:00:30Z", 30, 0, 0, measured=False)])
        r = json.loads(run("report", bad, "--json").stdout)
        check("a session without a usage measurement is counted (not an error by itself)", r["quality"]["withoutUsageMeasurement"] == 1 and run("report", bad).returncode == 0, r["quality"])
        two = os.path.join(d, "two.jsonl")
        write(two, [rec(1, "imsi-001010000000003", "internet", 1, "2026-11-03T12:00:00Z", "2026-11-03T12:01:00Z", 60, 10, 10)])
        check("several files are one period", json.loads(run("report", f, two, "--json").stdout)["totals"]["sessions"] == 5)

    real = os.environ.get("G5C_CDR_FILE")
    if real and os.path.exists(real):
        p = run("report", real, "--home", "00101")
        check("a real CDR file is read", p.returncode in (0, 1) and "sessions of" in p.stdout and "Traceback" not in p.stderr, p.stderr[-200:])
    print("cdr: PASS" if ok else "cdr: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
