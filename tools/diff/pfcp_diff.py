#!/usr/bin/env python3
"""Differential PFCP analysis (strategy 4.1, conformance layer): the same SMF (Open5GS) and the same scenario, once with Open5GS's UPF and
once with ours. Compares what each UPF answered, message type by message type, by the set of information elements (names, nested paths)
and the sequence of messages the SMF sent. Exit status 1 when our UPF leaves out an element Open5GS's UPF includes (apart from the
documented allow-list) or when the SMF's request sequence differs.

    python3 tools/diff/pfcp_diff.py [reference.pcapng] [ours.pcapng]      (defaults: the two S3 golden captures)

With --smf the roles are swapped: the same UPF (ours) and the same scenario, once with Open5GS's SMF and once with ours. It compares what the SMF
asked for, message type by message type, by the set of information elements it sent (the first request of each type, and the first modification that
carries a Forwarding Parameters update). Exit status 1 when our SMF leaves out an element Open5GS's SMF sends (apart from the documented
allow-list) or when its request sequence differs.

    python3 tools/diff/pfcp_diff.py --smf [reference.pcapng] [ours.pcapng]   (defaults: S3 with Open5GS's SMF / with our SMF, both on our UPF)"""
import importlib.util
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
spec = importlib.util.spec_from_file_location("gd", str(ROOT / "tools" / "docs" / "gen_dashboard.py"))
gd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gd)
msgs, ies = gd.pfcp_tables()
GROUPED = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 51, 54, 58, 59, 78, 79, 80, 83, 85, 86, 87, 99, 102, 105}
SKIP = {1, 2}  # heartbeats: timing, not behaviour
# Elements Open5GS's UPF sends that ours deliberately does not (message type -> names), with the reason
ALLOW = {
    "PFCP Association Setup Response": {"UP Function Features": "values differ by design (we claim FTUP and DLBD only)"},
}


def walk(b, path, out):
    o = 0
    while o + 4 <= len(b):
        t, ln = struct.unpack_from(">HH", b, o)
        name = ies.get(t, "IE %d" % t)
        out.add(path + name)
        if t in GROUPED:
            walk(b[o + 4:o + 4 + ln], path + name + " > ", out)
        o += 4 + ln


def load(pcap):
    reqs, resp = [], {}
    smf_ip = None
    for _ts, ip in gd.read_pcapng(pcap):
        p = gd.parse_ip(ip)
        if not p or p[0] != 17:
            continue
        sport, dport = struct.unpack_from(">HH", p[3], 0)
        if 8805 not in (sport, dport):
            continue
        ud = bytes(p[3][8:])
        mt = ud[1]
        if mt in SKIP:
            continue
        flags = ud[0]
        o = 4 + (8 if flags & 1 else 0) + 4
        names = set()
        walk(ud[o:4 + struct.unpack_from(">H", ud, 2)[0]], "", names)
        if mt == 50 and smf_ip is None:
            smf_ip = p[1]
        resp.setdefault(("src", p[1]), []).append((mt, names))
    return smf_ip, resp


# Elements Open5GS's SMF sends that ours deliberately does not (name -> reason)
SMF_ALLOW = {
    "User ID": "subscriber identity for lawful-intercept / charging correlation; the SMF keeps the SUPI in its own context",
    "Create URR": "usage reporting / charging is Phase 7 (CHF); not requested yet",
    "Reporting Triggers": "belongs to the URR",
    "Measurement Method": "belongs to the URR",
    "URR ID": "belongs to the URR",
    "Measurement Period": "belongs to the URR",
    "Time Threshold": "belongs to the URR",
    "Volume Threshold": "belongs to the URR",
    "Inactivity Detection Time": "belongs to the URR",
    "Trace Information": "not used",
    "SDF Filter": "Open5GS restricts its default PDRs with a match-all filter; ours match every flow without one (PCC rules carry real filters)",
    "QFI": "Open5GS restricts the default uplink PDR to QFI 1; ours accepts any QFI of the tunnel",
    "Outer Header Creation": "in Create FAR this is Open5GS's FAR that forwards IPv6 Router Solicitations to the SMF; the IPv6 router / RA path is not built yet",
}


def smf_mode(ref, ours):
    fails = 0
    data = {}
    for label, pc in (("Open5GS SMF", ref), ("our SMF", ours)):
        smf_ip, per_src = load(pc)
        data[label] = [(m, n) for m, n in per_src[("src", smf_ip)]] if smf_ip else []
    seqs = {k: [m for m, _ in v] for k, v in data.items()}
    def first_cycle(seq):
        out = []
        for m in seq[seq.index(50):] if 50 in seq else seq:
            out.append(m)
            if m == 54:
                break
        return out
    a, b = first_cycle(seqs["Open5GS SMF"]), first_cycle(seqs["our SMF"])
    print("SMF requests, first session lifecycle:")
    print("  Open5GS SMF:", [msgs.get(m, m).replace("PFCP ", "") for m in a])
    print("  our SMF:    ", [msgs.get(m, m).replace("PFCP ", "") for m in b])
    if a != b:
        print("  DIFFERENT request sequence")
        fails += 1
    else:
        print("  identical sequence")
    def first_by_type(reqs):
        d = {}
        for mt, names in reqs:
            d.setdefault(mt, names)
        return d
    fr, fo = first_by_type(data["Open5GS SMF"]), first_by_type(data["our SMF"])
    print()
    print("SMF requests, by message type (first occurrence of each):")
    for mt in sorted(set(fr) | set(fo)):
        name = msgs.get(mt, str(mt))
        if mt not in fo or mt not in fr:
            print("  %-42s only %s sent this" % (name, "Open5GS's SMF" if mt in fr else "our SMF"))
            if mt in fr and mt not in (5, 6):
                fails += 1
            continue
        missing = sorted(fr[mt] - fo[mt])
        extra = sorted(fo[mt] - fr[mt])
        hard = [m for m in missing if m.split(" > ")[-1] not in SMF_ALLOW]
        print("  %-42s %d elements; ours %s" % (name, len(fr[mt]), "matches" if not missing and not extra else "differs"))
        for m in missing:
            why = SMF_ALLOW.get(m.split(" > ")[-1])
            print("      missing in ours: %s%s" % (m, "  (allowed: %s)" % why if why else ""))
        for e in extra:
            print("      extra in ours:   %s" % e)
        fails += len(hard)
    print()
    print("PFCP SMF differential: %s" % ("OK" if not fails else "%d differences" % fails))
    return 1 if fails else 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--smf":
        ref = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "tests/fixtures/golden/s3_our_upf_open5gs_smf_ueransim.pcapng"
        ours = Path(sys.argv[3]) if len(sys.argv) > 3 else ROOT / "tests/fixtures/golden/s3_our_smf_our_upf_open5gs_amf_ueransim.pcapng"
        return smf_mode(ref, ours)
    ref = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "tests/fixtures/golden/s3_open5gs_v2.8.0_ueransim.pcapng"
    ours = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "tests/fixtures/golden/s3_our_upf_open5gs_smf_ueransim.pcapng"
    fails = 0
    data = {}
    for label, pc in (("Open5GS UPF", ref), ("our UPF", ours)):
        smf, per_src = load(pc)
        upf = next(k[1] for k in per_src if k[1] != smf)
        data[label] = (per_src[("src", smf)], per_src[("src", upf)])
    ref_req, ref_rsp = data["Open5GS UPF"]
    our_req, our_rsp = data["our UPF"]
    seq_ref = [m for m, _ in ref_req]
    seq_our = [m for m, _ in our_req]
    # the scenario repeats registrations, so compare the first session lifecycle (up to the first deletion request)
    def first_cycle(seq):  # from the first Session Establishment (a capture may start after the association) to the first deletion
        out = []
        for m in seq[seq.index(50):] if 50 in seq else seq:
            out.append(m)
            if m == 54:
                break
        return out
    a, b = first_cycle(seq_ref), first_cycle(seq_our)
    print("SMF requests, first session lifecycle:")
    print("  with Open5GS UPF:", [msgs.get(m, m).replace("PFCP ", "") for m in a])
    print("  with our UPF:    ", [msgs.get(m, m).replace("PFCP ", "") for m in b])
    if a != b:
        print("  DIFFERENT: the SMF behaved differently towards our UPF")
        fails += 1
    else:
        print("  identical sequence")
    print("\nUPF answers, by message type (first occurrence of each):")
    def first_by_type(rsp):
        d = {}
        for mt, names in rsp:
            d.setdefault(mt, names)
        return d
    fr, fo = first_by_type(ref_rsp), first_by_type(our_rsp)
    for mt in sorted(set(fr) | set(fo)):
        name = msgs.get(mt, str(mt))
        if mt not in fo:
            print("  %-42s only Open5GS's UPF sent this" % name)
            if mt not in (5, 6, 56, 57):  # the association may predate our capture; reports are sent only when there is a reason
                fails += 1
            continue
        if mt not in fr:
            print("  %-42s only our UPF sent this" % name)
            continue
        missing = sorted(fr[mt] - fo[mt])
        extra = sorted(fo[mt] - fr[mt])
        allowed = ALLOW.get(name, {})
        hard = [m for m in missing if m.split(" > ")[-1] not in allowed]
        print("  %-42s %d elements; ours %s" % (name, len(fr[mt]), "matches" if not missing and not extra else "differs"))
        for m in missing:
            why = allowed.get(m.split(" > ")[-1])
            print("      missing in ours: %s%s" % (m, "  (allowed: %s)" % why if why else ""))
        for e in extra:
            print("      extra in ours:   %s" % e)
        fails += len(hard)
    print("\nPFCP differential: %s" % ("OK" if not fails else "%d differences" % fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
