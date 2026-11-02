#!/usr/bin/env python3
"""The control-plane service level objectives of docs/ops/slo.md, checked against the output of a load run (`g5c-cluster.sh ns load`).
   python3 tools/check_slo.py <load log> [--min-ue-per-s N] [--p99-reg-ms N] [--p99-pdu-ms N] [--p99-dereg-ms N]
Exit 1 when an objective is missed. The defaults are the objectives (single host, loopback, WSL2 on 8 vCPU: the margins are wide because a shared host swings by a factor of three)."""
import re
import sys

OBJ = {"min_ue_per_s": 50.0, "p99_reg_ms": 1000.0, "p99_pdu_ms": 500.0, "p99_dereg_ms": 500.0}


def main(argv):
    if not argv or argv[0].startswith("--"):
        print(__doc__)
        return 2
    obj = dict(OBJ)
    for i, a in enumerate(argv[1:], 1):
        k = {"--min-ue-per-s": "min_ue_per_s", "--p99-reg-ms": "p99_reg_ms", "--p99-pdu-ms": "p99_pdu_ms", "--p99-dereg-ms": "p99_dereg_ms"}.get(a)
        if k:
            obj[k] = float(argv[i + 1])
    text = open(argv[0], encoding="utf-8", errors="replace").read()
    rates = [float(m) for m in re.findall(r"registered with a PDU session each in [0-9.]+ s \(([0-9.]+) UE/s\)", text)]
    p99 = {}
    for name in ("registration", "pdu-session", "deregistration"):
        v = [float(m) for m in re.findall(r"^\s*%s\s+n=\d+\s+p50\s+[0-9.]+ ms\s+p95\s+[0-9.]+ ms\s+p99\s+([0-9.]+) ms" % re.escape(name), text, re.M)]
        p99[name] = max(v) if v else None
    bad = []
    if not rates:
        bad.append("no throughput line in the log")
    elif min(rates) < obj["min_ue_per_s"]:
        bad.append("throughput %.0f UE/s < %.0f UE/s" % (min(rates), obj["min_ue_per_s"]))
    for name, key in (("registration", "p99_reg_ms"), ("pdu-session", "p99_pdu_ms"), ("deregistration", "p99_dereg_ms")):
        if p99[name] is None:
            bad.append("no %s latency line in the log" % name)
        elif p99[name] > obj[key]:
            bad.append("%s p99 %.0f ms > %.0f ms" % (name, p99[name], obj[key]))
    print("SLO: %s (throughput %s UE/s, p99 registration %s ms, PDU session %s ms, de-registration %s ms)" % (
        "FAIL: " + "; ".join(bad) if bad else "PASS", "%.0f" % min(rates) if rates else "-", p99["registration"], p99["pdu-session"], p99["deregistration"]))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
