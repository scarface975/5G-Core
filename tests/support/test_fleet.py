#!/usr/bin/env python3
"""tools/cli/g5c-fleet: groups by prefix or list, the per-group report over a window (active, silent, never seen, volume), the silent list and its exit code, the template applied to a device
list (and refused for devices of another group or with bad keys), the three inventory formats, and bad input."""
import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-fleet"
K = "465b5ce8b199b49faa5f0a2ee238a6bc"
OPC = "e8ed289deba952e4283b54e88e6183ca"


def run(args):
    return subprocess.run([sys.executable, str(TOOL)] + args, capture_output=True, text=True)


def rec(supi, start, end, octets):
    return json.dumps({"supi": supi, "startTime": start, "endTime": end, "totalOctets": octets})


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        groups = d / "groups.json"
        groups.write_text(json.dumps({"groups": {"meters": {"prefix": "imsi-0010100", "slices": "1:000001", "dnns": "iot", "ue_ambr_ul": "100 Kbps", "ue_ambr_dl": "100 Kbps"},
                                                 "trackers": {"supis": ["imsi-001019000000001", "imsi-001019000000002"], "slices": "1", "dnns": "iot;internet"}}}))
        # 5 meters, 2 trackers, one device in no group
        meters = ["imsi-00101000000000%d" % i for i in range(1, 6)]
        inv = d / "inv.json"
        inv.write_text(json.dumps([{"supi": s} for s in meters + ["imsi-001019000000001", "imsi-001019000000002", "imsi-001018000000001"]]))
        cdr = d / "cdr.jsonl"
        cdr.write_text("\n".join([
            rec(meters[0], "2026-11-04T08:00:00Z", "2026-11-04T08:30:00Z", 1000),   # active
            rec(meters[1], "2026-11-04T01:00:00Z", "2026-11-04T01:10:00Z", 500),     # silent (11 h ago for a 6 h window)
            rec(meters[2], "2026-11-03T08:00:00Z", "2026-11-03T08:10:00Z", 700),     # silent, a day ago
            rec(meters[0], "2026-11-04T07:00:00Z", "2026-11-04T07:10:00Z", 250),     # active again
            rec("imsi-001019000000001", "2026-11-04T09:00:00Z", "2026-11-04T09:05:00Z", 40),
        ]) + "\n")
        base = ["--groups", str(groups), "--inventory", str(inv), "--cdr", str(cdr), "--now", "2026-11-04T12:00:00Z", "--silent-hours", "6"]

        r = run(["report"] + base + ["--json"])
        rep = json.loads(r.stdout)
        m, t = rep["groups"]["meters"], rep["groups"]["trackers"]
        check("meters: 5 devices, 1 active, 2 silent, 2 never seen", (m["devices"], m["active"], m["silent"], m["neverSeen"]) == (5, 1, 2, 2), m)
        check("meters: the sessions and volume inside the window", m["sessions"] == 2 and m["octets"] == 1250, m)
        check("trackers: 2 devices, 1 active, 1 never seen", (t["devices"], t["active"], t["neverSeen"]) == (2, 1, 1), t)
        check("a device in no group is counted under (none), and the total adds up", rep["groups"]["(none)"]["devices"] == 1 and rep["total"]["devices"] == 8, rep["total"])

        r = run(["report"] + base)
        check("the text report has a line per group and a total", r.returncode == 0 and "meters" in r.stdout and "total" in r.stdout and "window 6 h" in r.stdout, r.stdout)

        r = run(["silent"] + base + ["--group", "meters"])
        lines = r.stdout.strip().splitlines()
        check("silent lists the silent and the never seen with the time last seen, and exits 1", r.returncode == 1 and len(lines) == 4 and any("2026-11-04T01:10:00Z" in x for x in lines) and
              sum("never seen" in x for x in lines) == 2, r.stdout)
        r = run(["silent"] + base[:-2] + ["--silent-hours", "100000"])
        check("with a window wide enough only the never seen remain", sum("never seen" in x for x in r.stdout.splitlines()) == 4 and "2026-11-0" not in r.stdout, r.stdout)

        # the other inventory formats
        (d / "inv.csv").write_text("supi,authenticationMethod\n" + "\n".join("%s,X" % s for s in meters) + "\n")
        (d / "inv.txt").write_text("\n".join(meters) + "\n")
        for name in ("inv.csv", "inv.txt"):
            r = run(["report", "--groups", str(groups), "--inventory", str(d / name), "--cdr", str(cdr), "--now", "2026-11-04T12:00:00Z", "--silent-hours", "6", "--json"])
            check("inventory format %s" % name, r.returncode == 0 and json.loads(r.stdout)["groups"]["meters"]["devices"] == 5, r.stderr)

        # provisioning with the group's template
        devs = d / "devices.csv"
        devs.write_text("supi,k,opc\n%s,%s,%s\n%s,%s,%s,+4912345\n" % (meters[0], K, OPC, meters[1], K, OPC))
        out = d / "out.csv"
        r = run(["provision", "--groups", str(groups), "--group", "meters", "--devices", str(devs), "--out", str(out)])
        rows = list(csv.DictReader(out.open()))
        check("provision: the CSV of g5c-subscribers with the group's slices, DNNs and rates", r.returncode == 0 and len(rows) == 2 and rows[0]["slices"] == "1:000001" and rows[0]["dnns"] == "iot" and
              rows[0]["ue_ambr_ul"] == "100 Kbps" and rows[1]["msisdn"] == "+4912345" and rows[0]["k"] == K, (r.stderr, rows))
        devs.write_text("%s,%s,%s\n" % ("imsi-001019000000001", K, OPC))
        check("a device that is not in the group is refused", run(["provision", "--groups", str(groups), "--group", "meters", "--devices", str(devs)]).returncode == 1)
        devs.write_text("%s,%s,%s\n" % (meters[0], "nothex", OPC))
        r = run(["provision", "--groups", str(groups), "--group", "meters", "--devices", str(devs)])
        check("a bad key is refused and the key is not printed", r.returncode == 1 and "nothex" not in r.stderr and OPC not in r.stderr, r.stderr)

        # bad input
        (d / "bad.json").write_text(json.dumps({"groups": {"x": {"supis": ["nonsense"]}}}))
        check("a group with a malformed SUPI is exit 2", run(["report", "--groups", str(d / "bad.json"), "--inventory", str(inv), "--cdr", str(cdr)]).returncode == 2)
        check("a missing file is exit 2", run(["report", "--groups", str(groups), "--inventory", str(d / "none"), "--cdr", str(cdr)]).returncode == 2)
    print("fleet: PASS" if ok else "fleet: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
