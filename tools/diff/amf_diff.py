#!/usr/bin/env python3
"""Differential N2 / N1 analysis (strategy 4.1, conformance layer): the same UE and gNB (UERANSIM), the same scenario (S3: registration, PDU session,
release, de-registration, re-registration), once against Open5GS's AMF and once against ours. Compares what the AMF sent, message by message:

  * the sequence of AMF-originated NGAP messages (procedure and kind),
  * for each of them, the set of NGAP information elements and, for NAS messages that travel unprotected, the set of NAS information elements.

Exit status 1 when our AMF leaves out an element Open5GS's AMF includes (apart from the documented allow-list) or when its message sequence differs.

    python3 tools/diff/amf_diff.py [--inspect g5c-inspect] [reference.pcapng] [ours.pcapng]
      defaults: the two S3 golden captures; g5c-inspect is looked up in ~/g5c-cbuild/plain/tools/inspect (WSL) or taken from --inspect.
Needs tshark (frame extraction, as tools/gen/pcap_ngap_to_hex.py does)."""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
GOLD = ROOT / "tests" / "fixtures" / "golden"

# (procedure, kind) pairs the AMF originates; everything else in a capture is the gNB's
AMF_SENT = {
    ("NGSetup", "successfulOutcome"), ("NGSetup", "unsuccessfulOutcome"), ("DownlinkNASTransport", "initiatingMessage"),
    ("InitialContextSetup", "initiatingMessage"), ("PDUSessionResourceSetup", "initiatingMessage"),
    ("PDUSessionResourceRelease", "initiatingMessage"), ("PDUSessionResourceModify", "initiatingMessage"),
    ("UEContextRelease", "initiatingMessage"), ("Paging", "initiatingMessage"),
}

# Elements Open5GS's AMF sends that ours deliberately does not (message -> names), with the reason
ALLOW = {
    "InitialContextSetup": {},
    "NGSetup": {},
}
# NAS elements likewise (message name -> names)
ALLOW_NAS = {}
# Messages ours sends that the reference does not, with the reason: after a de-registration our AMF drops the UE context, so a re-registration with the old
# 5G-GUTI starts with an identification (Open5GS keeps the context and authenticates the subscriber it knows by that GUTI).
ALLOW_EXTRA = {"Identity request": "the context is dropped at de-registration; the GUTI of a re-registration is not known"}


def inspect_path(arg):
    if arg:
        return arg
    for c in (os.environ.get("G5C_INSPECT"), str(Path.home() / "g5c-cbuild" / "plain" / "tools" / "inspect" / "g5c-inspect")):
        if c and Path(c).exists():
            return c
    sys.exit("g5c-inspect not found (build the tree or pass --inspect)")


def decode(pcap, inspect):
    hexes = subprocess.run([sys.executable, str(ROOT / "tools" / "gen" / "pcap_ngap_to_hex.py"), str(pcap)], capture_output=True, text=True, check=True).stdout
    out = subprocess.run([inspect, "decode"], input=hexes, capture_output=True, text=True, check=True).stdout
    msgs = []
    for ln in out.splitlines():
        if not ln.strip():
            continue
        j = json.loads(ln)
        msgs.append(j)
    return msgs


def ie_names(m):
    body = m.get("ngap", {})
    for kind in body:
        v = body[kind].get("value", {})
        return {ie.get("name", "id-%s" % ie.get("id")) for ie in v.get("protocolIEs", [])}
    return set()


def nas_names(m):
    nas = m.get("nas")
    if not nas or nas.get("protected"):
        return None
    return {ie["name"] for ie in nas.get("message", {}).get("ies", [])}


def amf_messages(msgs):
    return [m for m in msgs if (m.get("procedure"), m.get("kind")) in AMF_SENT]


def label(m):
    """procedure, with the NAS message name when it travels unprotected (so that the sequences can be compared message by message)"""
    nas = m.get("nas")
    if m["procedure"] == "DownlinkNASTransport" and nas is not None:
        return "%s[%s]" % (m["procedure"], "protected" if nas.get("protected") else nas.get("message", {}).get("name", "?"))
    return m["procedure"]


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    inspect = None
    if "--inspect" in argv:
        inspect = argv[argv.index("--inspect") + 1]
        args = [a for a in args if a != inspect]
    ref = Path(args[0]) if len(args) > 0 else GOLD / "s3_open5gs_v2.8.0_ueransim.pcapng"
    ours = Path(args[1]) if len(args) > 1 else GOLD / "s3_our_amf_open5gs_core_ueransim.pcapng"
    ins = inspect_path(inspect)
    a, b = amf_messages(decode(ref, ins)), amf_messages(decode(ours, ins))
    errors = []
    seq_a = [label(m) for m in a]
    seq_b_all = [label(m) for m in b]
    extras = {"DownlinkNASTransport[%s]" % k for k in ALLOW_EXTRA}
    seq_b = [x for x in seq_b_all if x not in extras]
    print("AMF -> gNB messages: reference %d, ours %d (%d allowed extra: %s)" % (len(seq_a), len(seq_b_all), len(seq_b_all) - len(seq_b),
                                                                             ", ".join(sorted(ALLOW_EXTRA)) or "none"))
    if seq_a != seq_b:
        errors.append("message sequences differ:\n  ref:  %s\n  ours: %s" % (seq_a, seq_b))
    # element sets per (procedure, kind): union over the capture
    def sets(msgs):
        d = {}
        n = {}
        for m in msgs:
            key = (m["procedure"], m["kind"])
            d.setdefault(key, set()).update(ie_names(m))
            nn = nas_names(m)
            if nn is not None:
                n.setdefault(key, {}).setdefault(m["nas"]["message"].get("name", "?"), set()).update(nn)
        return d, n
    da, na = sets(a)
    db, nb = sets(b)
    for key in sorted(da):
        miss = da[key] - db.get(key, set()) - set(ALLOW.get(key[0], {}))
        extra = db.get(key, set()) - da[key]
        line = "%-34s %-20s IEs: ref %d, ours %d" % (key[0], key[1], len(da[key]), len(db.get(key, ())))
        if miss:
            line += "  MISSING in ours: " + ", ".join(sorted(miss))
            errors.append("%s: missing %s" % (key[0], sorted(miss)))
        if extra:
            line += "  (extra in ours: %s)" % ", ".join(sorted(extra))
        print(line)
    for key in sorted(na):
        for name, ref_ies in sorted(na[key].items()):
            our_ies = nb.get(key, {}).get(name, set())
            miss = ref_ies - our_ies - set(ALLOW_NAS.get(name, ()))
            line = "  NAS %-40s IEs: ref %d, ours %d" % (name, len(ref_ies), len(our_ies))
            if miss:
                line += "  MISSING in ours: " + ", ".join(sorted(miss))
                errors.append("NAS %s: missing %s" % (name, sorted(miss)))
            print(line)
    for e in errors:
        print("FAIL", e)
    print("differential: %s" % ("OK" if not errors else "%d differences" % len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
