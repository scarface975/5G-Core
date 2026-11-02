#!/usr/bin/env python3
"""Build the 5G core dashboard from the repository itself.

    python3 tools/gen_dashboard.py            (inside WSL, after scripts/g5c_regress.sh and a build in ~/g5c-cbuild/plain)

Writes build/dashboard/data.json (everything the page shows) and build/dashboard/index.html (data embedded in
tools/dashboard/template.html). Nothing on the page is typed in by hand except the reference-point topology (TS 23.501
figure 4.2.3-1) and the short walk-throughs of the algorithms; routes, metrics, files, coverage, tests, traces, payloads,
the conformance matrix, the phase plan and the quality figures are all read from the tree or from real runs.
Standard library only."""
import collections
import datetime
import glob
import json
import os
import re
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
CBUILD = Path(os.environ.get("G5C_C_BUILD", str(Path.home() / "g5c-cbuild"))) / "plain"
INSPECT = os.environ.get("G5C_INSPECT", str(CBUILD / "tools" / "inspect" / "g5c-inspect"))
OUT = BUILD / "dashboard"


def rd(p):
    return Path(p).read_text(encoding="utf8", errors="replace")


def jload(p, default=None):
    try:
        return json.loads(rd(p))
    except (OSError, ValueError):
        return default


# ------------------------------------------------------------------------------------------------ pcapng ------------

def read_pcapng(path):
    """yield (timestamp seconds, ip packet bytes) for every packet"""
    data = Path(path).read_bytes()
    pos, ifaces, out = 0, [], []
    while pos + 12 <= len(data):
        btype, blen = struct.unpack_from("<II", data, pos)
        if blen < 12 or pos + blen > len(data):
            break
        body = data[pos + 8:pos + blen - 4]
        if btype == 1:  # interface description
            link = struct.unpack_from("<H", body, 0)[0]
            res, o = 1e-6, 8
            while o + 4 <= len(body):
                code, ln = struct.unpack_from("<HH", body, o)
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    v = body[o + 4]
                    res = 10.0 ** -(v & 0x7F) if not v & 0x80 else 2.0 ** -(v & 0x7F)
                o += 4 + ((ln + 3) & ~3)
            ifaces.append((link, res))
        elif btype == 6:  # enhanced packet
            iface, tsh, tsl, cap, _orig = struct.unpack_from("<IIIII", body, 0)
            link, res = ifaces[iface] if iface < len(ifaces) else (1, 1e-6)
            pkt = body[20:20 + cap]
            ip = None
            if link == 1 and len(pkt) > 14:
                et, off = struct.unpack_from(">H", pkt, 12)[0], 14
                if et == 0x8100:
                    et, off = struct.unpack_from(">H", pkt, 16)[0], 18
                if et in (0x0800, 0x86DD):
                    ip = pkt[off:]
            elif link == 113 and len(pkt) > 16:
                ip = pkt[16:]
            elif link == 0 and len(pkt) > 4:
                ip = pkt[4:]
            elif link == 101:
                ip = pkt
            if ip:
                out.append((((tsh << 32) | tsl) * res, ip))
        pos += blen
    return out


def parse_ip(ip):
    """-> (proto, src, dst, payload) for IPv4/IPv6"""
    ver = ip[0] >> 4
    if ver == 4 and len(ip) >= 20:
        ihl = (ip[0] & 15) * 4
        total = struct.unpack_from(">H", ip, 2)[0]
        return ip[9], ".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20])), ip[ihl:total or len(ip)]
    if ver == 6 and len(ip) >= 40:
        return ip[6], ":".join("%02x%02x" % (ip[8 + i], ip[9 + i]) for i in range(0, 16, 2)), ":".join(
            "%02x%02x" % (ip[24 + i], ip[25 + i]) for i in range(0, 16, 2)), ip[40:]
    return None


def sctp_data(payload):
    """yield (ppid, user data) for every DATA chunk"""
    pos = 12
    while pos + 4 <= len(payload):
        ctype, _fl, ln = struct.unpack_from(">BBH", payload, pos)
        if ln < 4:
            break
        if ctype == 0 and ln >= 16:
            ppid = struct.unpack_from(">I", payload, pos + 12)[0]
            yield ppid, payload[pos + 16:pos + ln]
        pos += (ln + 3) & ~3


def pfcp_tables():
    """message and IE names straight from the pinned TS 29.244 text"""
    txt = rd(ROOT / "docs/specs/src/txt/29244-gd0.txt").splitlines()
    msgs, ies = {}, {}
    try:
        a = next(i for i, l in enumerate(txt) if l.startswith("Table 7.3-1: Message Types"))
        for i in range(a, a + 400):
            if txt[i].strip().isdigit() and i + 1 < len(txt) and txt[i + 1].startswith("PFCP"):
                msgs[int(txt[i])] = txt[i + 1].strip()
        b = next(i for i, l in enumerate(txt) if l.startswith("Table 8.1.2-1: Information Element Types"))
        for i in range(b, b + 1500):
            if txt[i].strip().isdigit() and i + 1 < len(txt) and txt[i + 1].strip() and not txt[i + 1].strip().isdigit():
                n = int(txt[i])
                if n not in ies and n < 400:
                    ies[n] = txt[i + 1].strip()
    except StopIteration:
        pass
    return msgs, ies


def parse_pfcp(b, msgs, ies):
    if len(b) < 8:
        return None
    flags, mt = b[0], b[1]
    ln = struct.unpack_from(">H", b, 2)[0]
    o = 4
    seid = None
    if flags & 1:
        seid = "%016x" % struct.unpack_from(">Q", b, o)[0]
        o += 8
    seq = int.from_bytes(b[o:o + 3], "big")
    o += 4
    end = min(len(b), 4 + ln)
    top = []
    while o + 4 <= end:
        t, l = struct.unpack_from(">HH", b, o)
        top.append(ies.get(t, "IE %d" % t))
        o += 4 + l
    return {"type": mt, "name": msgs.get(mt, "PFCP message %d" % mt), "seid": seid, "seq": seq, "ies": top}


def parse_gtpu(b):
    if len(b) < 8:
        return None
    flags, mt = b[0], b[1]
    teid = struct.unpack_from(">I", b, 4)[0]
    o = 8
    if flags & 7:
        nxt = b[11] if len(b) > 11 else 0
        o = 12
        while nxt and o < len(b):
            nxt, o = b[o + b.__getitem__(o) * 4 - 1] if False else (b[o + b[o] * 4 - 1], o + b[o] * 4)
    info = {"msgType": mt, "teid": "%08x" % teid, "len": len(b)}
    if mt == 255 and o < len(b):
        ip = parse_ip(b[o:])
        if ip:
            info["inner"] = {"proto": ip[0], "src": ip[1], "dst": ip[2]}
            if ip[0] == 1 and len(ip[3]) >= 8:
                info["inner"]["icmp"] = {8: "echo request", 0: "echo reply"}.get(ip[3][0], "type %d" % ip[3][0])
                info["inner"]["seq"] = struct.unpack_from(">H", ip[3], 6)[0]
    return info


def decode_ngap(items):
    """items: [(id, hex)] -> {id: decoded}"""
    if not items:
        return {}
    inp = "".join("%s %s\n" % (i, h) for i, h in items)
    res = subprocess.run([INSPECT, "decode"], input=inp, capture_output=True, text=True, check=True).stdout
    return {str(j["id"]): j for j in map(json.loads, res.splitlines() if res else [])}


def learn_roles(pcap):
    """(smf_ip, upf_ip) from the first PFCP Session Establishment Request in a capture, else None"""
    for _ts, ip in read_pcapng(ROOT / "tests/fixtures/golden" / pcap):
        p = parse_ip(ip)
        if p and p[0] == 17 and len(p[3]) > 16:
            sport, dport = struct.unpack_from(">HH", p[3], 0)
            if 8805 in (sport, dport) and p[3][8 + 1] == 50:
                return p[1], p[2]
    return None


def trace_procedure(pcap, title, summary, spec_refs, roles=None):
    msgs, ies = pfcp_tables()
    pk = read_pcapng(ROOT / "tests/fixtures/golden" / pcap)
    events, t0 = [], None
    smf_ip, upf_ip = roles if roles else (None, None)
    for ts, ip in pk:
        p = parse_ip(ip)
        if not p:
            continue
        t0 = ts if t0 is None else t0
        proto, src, dst, pl = p
        t = ts - t0
        if proto == 132 and len(pl) > 12:
            sport, dport = struct.unpack_from(">HH", pl, 0)
            for ppid, ud in sctp_data(pl):
                if ppid == 60:
                    events.append({"t": t, "proto": "NGAP", "up": dport == 38412, "hex": ud.hex()})
        elif proto == 17 and len(pl) > 8:
            sport, dport = struct.unpack_from(">HH", pl, 0)
            ud = pl[8:]
            if 8805 in (sport, dport):
                d = parse_pfcp(ud, msgs, ies)
                if d:
                    d.update({"t": t, "proto": "PFCP", "src": src, "dst": dst})
                    events.append(d)
            elif 2152 in (sport, dport):
                d = parse_gtpu(ud)
                if d:
                    d.update({"t": t, "proto": "GTP-U", "src": src, "dst": dst})
                    events.append(d)
    ids = [("e%d" % i, e["hex"]) for i, e in enumerate(events) if e["proto"] == "NGAP"]
    dec = decode_ngap(ids)
    steps, i = [], 0
    for idx, e in enumerate(events):
        t = round(e["t"], 4)
        if e["proto"] == "NGAP":
            d = dec.get("e%d" % idx, {})
            nas = d.get("nas", {})
            nm = ((nas.get("message") or {}).get("name"))
            label = d.get("procedure", "NGAP")
            if label not in ("InitialUEMessage", "UplinkNASTransport", "DownlinkNASTransport"):
                label += {"initiatingMessage": " Request", "successfulOutcome": " Response", "unsuccessfulOutcome": " Failure"}.get(d.get("kind"), "")
            if nm:
                label += " · " + nm
            elif nas.get("ciphered"):
                label += " · NAS (ciphered)"
            steps.append({"t": t, "from": "gNB" if e["up"] else "AMF", "to": "AMF" if e["up"] else "gNB", "proto": "NGAP",
                          "kind": d.get("kind"), "label": label, "ngap": d.get("ngap"), "nas": nas or None, "error": d.get("error")})
        elif e["proto"] == "PFCP":
            frm, to = ("SMF", "UPF") if e["src"] == smf_ip else ("UPF", "SMF")
            steps.append({"t": t, "from": frm, "to": to, "proto": "PFCP", "label": e["name"].replace("PFCP ", "", 1),
                          "pfcp": {"messageType": e["type"], "seid": e["seid"], "sequence": e["seq"], "topLevelIEs": e["ies"]}})
        else:  # GTP-U: fold runs into one step
            if steps and steps[-1].get("proto") == "GTP-U":
                s = steps[-1]
                s["packets"].append({k: e[k] for k in ("t", "msgType", "teid", "len", "inner") if k in e})
                s["t_end"] = t
                continue
            steps.append({"t": t, "t_end": t, "from": "gNB", "to": "UPF", "proto": "GTP-U", "label": "user-plane traffic (N3)", "packets": [
                {k: e[k] for k in ("t", "msgType", "teid", "len", "inner") if k in e}]})
    for s in steps:
        if s["proto"] == "GTP-U":
            n = len(s["packets"])
            icmp = sum(1 for p in s["packets"] if p.get("inner", {}).get("icmp"))
            s["label"] = "N3 user plane: %d GTP-U packets%s" % (n, " (%d ICMP echo)" % icmp if icmp else "")
            s["packets"] = [{**p, "t": round(p["t"], 4)} for p in s["packets"][:40]]
            s["omitted"] = max(0, n - 40)
    nas_names = [s["label"] for s in steps if s["proto"] == "NGAP"]
    return {"id": pcap.split("_")[0], "title": title, "kind": "capture", "summary": summary, "source": "tests/fixtures/golden/" + pcap,
            "spec": spec_refs, "nodes": ["gNB", "AMF", "SMF", "UPF"], "steps": steps, "stats": {"messages": len(steps), "ngap": len(ids), "ngapLabels": nas_names[:3]}}


# ------------------------------------------------------------------------------------------------ SBI procedures ------

def payload(name):
    return jload(BUILD / "payloads" / (name + ".json"))


def sbi_procedures():
    P = payload
    return [
        {"id": "sbi-aka", "title": "5G-AKA through AUSF, UDM and UDR", "kind": "sbi",
         "summary": "The network side of primary authentication. Every body is the JSON our NFs produced in the test run and validated against the official OpenAPI schema.",
         "spec": ["TS 33.501 6.1.3.2.0", "TS 29.509 5.2.2.2.2", "TS 29.503 5.4.2.2.2", "TS 29.505 5.2.2"],
         "nodes": ["AMF", "AUSF", "UDM", "UDR"],
         "steps": [
             {"from": "AMF", "to": "AUSF", "proto": "SBI", "label": "POST /nausf-auth/v1/ue-authentications", "note": "supiOrSuci (SUCI or SUPI) and servingNetworkName", "body": P("ausf_UEAuthenticationCtx"), "status": 201, "bodyIs": "response UEAuthenticationCtx: RAND, AUTN, HXRES* and the link for the confirmation"},
             {"from": "AUSF", "to": "UDM", "proto": "SBI", "label": "POST /nudm-ueau/v1/{supi|suci}/security-information/generate-auth-data", "note": "UDM de-conceals the SUCI (SIDF), then builds the vector", "body": P("udm_AuthenticationInfoResult"), "status": 200, "bodyIs": "response AuthenticationInfoResult (5G HE AV: RAND, AUTN, XRES*, KAUSF)"},
             {"from": "UDM", "to": "UDR", "proto": "SBI", "label": "GET .../authentication-data/authentication-subscription", "note": "K and OPc come back encrypted (AES-256-GCM, SUPI bound)", "body": P("udr_AuthenticationSubscription"), "status": 200, "bodyIs": "response AuthenticationSubscription"},
             {"from": "UDM", "to": "UDR", "proto": "SBI", "label": "PATCH .../authentication-subscription  [{replace /sequenceNumber/sqn}]", "note": "SQN is advanced and stored before the vector is released, so a crash can never reuse one", "status": 204},
             {"from": "AMF", "to": "AUSF", "proto": "SBI", "label": "PUT {confirmation link}  {resStar}", "note": "RES* from the UE; AUSF compares HRES*/XRES*", "body": P("ausf_ConfirmationDataResponse_success"), "status": 200, "bodyIs": "response ConfirmationDataResponse: SUCCESS, SUPI, KSEAF"},
             {"from": "AUSF", "to": "UDM", "proto": "SBI", "label": "POST /nudm-ueau/v1/{supi}/auth-events", "note": "result of the authentication is recorded", "body": P("udm_AuthEvent"), "status": 201, "bodyIs": "response AuthEvent"},
         ]},
        {"id": "sbi-reg", "title": "Registration: subscriber data for the AMF", "kind": "sbi",
         "summary": "What the AMF asks the UDM after authentication. Served from the UDR; the subscriber was provisioned through the admin API.",
         "spec": ["TS 29.503 5.3.2.2.2", "TS 29.503 5.2.2.2.3", "TS 29.503 5.2.2.2.2", "TS 29.503 5.2.2.2.9"],
         "nodes": ["AMF", "UDM", "UDR"],
         "steps": [
             {"from": "AMF", "to": "UDM", "proto": "SBI", "label": "PUT /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access", "note": "UDM tells the previous AMF (if any) to deregister, then stores this one", "status": 201},
             {"from": "AMF", "to": "UDM", "proto": "SBI", "label": "GET /nudm-sdm/v2/{supi}/am-data?plmn-id=...", "body": P("udm_AccessAndMobilitySubscriptionData"), "status": 200, "bodyIs": "response AccessAndMobilitySubscriptionData"},
             {"from": "AMF", "to": "UDM", "proto": "SBI", "label": "GET /nudm-sdm/v2/{supi}/nssai", "body": P("udm_Nssai"), "status": 200, "bodyIs": "response Nssai"},
             {"from": "AMF", "to": "UDM", "proto": "SBI", "label": "GET /nudm-sdm/v2/{supi}/smf-select-data", "body": P("udm_SmfSelectionSubscriptionData"), "status": 200, "bodyIs": "response SmfSelectionSubscriptionData"},
             {"from": "AMF", "to": "UDM", "proto": "SBI", "label": "GET /nudm-sdm/v2/{supi}?dataset-names=AM,SMF_SEL,SM,UEC_SMF", "note": "retrieval of multiple data sets in one call", "body": P("udm_SubscriptionDataSets"), "status": 200, "bodyIs": "response SubscriptionDataSets"},
             {"from": "AMF", "to": "UDM", "proto": "SBI", "label": "POST /nudm-sdm/v2/{supi}/sdm-subscriptions", "note": "ask to be told when this data changes", "body": P("udm_SdmSubscription"), "status": 201, "bodyIs": "response SdmSubscription"},
         ]},
        {"id": "sbi-pdu", "title": "PDU session: session data and policy for the SMF", "kind": "sbi",
         "summary": "The SMF registers the session, reads the session-management subscription and gets a policy decision. Two DNNs show the layered policy: internet (defaults) and ims (a GBR voice rule).",
         "spec": ["TS 29.503 5.3.2.2.4", "TS 29.503 5.2.2.2.5", "TS 29.512 4.2.2.2", "TS 29.512 4.2.3"],
         "nodes": ["SMF", "UDM", "PCF", "UDR"],
         "steps": [
             {"from": "SMF", "to": "UDM", "proto": "SBI", "label": "PUT /nudm-uecm/v1/{supi}/registrations/smf-registrations/{pduSessionId}", "status": 201},
             {"from": "SMF", "to": "UDM", "proto": "SBI", "label": "GET /nudm-sdm/v2/{supi}/sm-data?single-nssai=...&dnn=internet", "body": P("udm_SessionManagementSubscriptionData_0"), "status": 200, "bodyIs": "response SessionManagementSubscriptionData"},
             {"from": "SMF", "to": "PCF", "proto": "SBI", "label": "POST /npcf-smpolicycontrol/v1/sm-policies  (dnn internet)", "note": "PCF reads per-subscriber overrides from the UDR, then resolves default / per-DNN / per-subscriber layers", "body": P("pcf_SmPolicyDecision_internet"), "status": 201, "bodyIs": "response SmPolicyDecision: one session rule (AMBR, default QoS)"},
             {"from": "SMF", "to": "PCF", "proto": "SBI", "label": "POST /npcf-smpolicycontrol/v1/sm-policies  (dnn ims)", "note": "per-DNN profile adds a voice PCC rule with 5QI 1, GBR and MBR", "body": P("pcf_SmPolicyDecision_ims"), "status": 201, "bodyIs": "response SmPolicyDecision: session rule + PCC rule + QoS data"},
             {"from": "PCF", "to": "SMF", "proto": "SBI", "label": "POST {notificationUri}/update  (policy changed mid-session)", "note": "operator edits the subscriber policy; the PCF pushes the new decision", "body": P("pcf_SmPolicyNotification"), "status": 204, "bodyIs": "request SmPolicyNotification"},
             {"from": "SMF", "to": "PCF", "proto": "SBI", "label": "POST .../sm-policies/{id}/delete", "note": "session release", "status": 204},
         ]},
        {"id": "sbi-prov", "title": "Provisioning and change notification", "kind": "sbi",
         "summary": "An operator provisions or re-provisions a subscriber; every NF holding an sdm-subscription for that SUPI is told.",
         "spec": ["TS 29.503 5.2.2.3.2", "TS 29.503 5.2.2.5.2"],
         "nodes": ["Operator", "UDM", "UDR", "AMF"],
         "steps": [
             {"from": "Operator", "to": "UDM", "proto": "SBI", "label": "POST /admin/v1/subscribers  (g5c-ctl subscriber add)", "note": "bearer token; K/OPc validated; limits of 64 slices and 256 DNNs", "status": 201},
             {"from": "UDM", "to": "UDR", "proto": "SBI", "label": "PUT authentication-subscription, am-data, sm-data, smf-selection...", "note": "K and OPc are wrapped with the master key before they leave the UDM", "body": P("udr_AccessAndMobilitySubscriptionData"), "status": 200, "bodyIs": "stored AccessAndMobilitySubscriptionData"},
             {"from": "UDM", "to": "AMF", "proto": "SBI", "label": "POST {callbackReference}  ModificationNotification", "note": "best effort: an unreachable consumer is counted, never an error for the operator", "body": P("udm_ModificationNotification"), "status": 204, "bodyIs": "request ModificationNotification"},
         ]},
        {"id": "sbi-eap", "title": "EAP-AKA' through AUSF, UDM and UDR", "kind": "sbi",
         "summary": "The EAP-based primary authentication: the AUSF is the EAP server, the AMF carries the EAP packets as base64 in JSON, the UDM supplies an AV' with CK' and IK'. The first packet "
                    "is the EAP-Request/AKA'-Challenge (AT_RAND, AT_AUTN, AT_KDF, AT_KDF_INPUT = the serving network name, AT_MAC); the answer carries AT_RES and AT_MAC; the final packet is EAP-Success with KSEAF. "
                    "Key derivation is checked against the four test vectors of RFC 9048 Annex D, and the whole procedure against UERANSIM's own EAP-AKA' peer.",
         "spec": ["TS 33.501 6.1.3.1", "TS 33.501 Annex F", "TS 29.509 5.2.2.2.3", "RFC 5448", "RFC 4187", "RFC 9048", "TS 24.501 5.4.1.2.2"],
         "nodes": ["AMF", "AUSF", "UDM"],
         "steps": [
             {"from": "AMF", "to": "AUSF", "proto": "SBI", "label": "POST /nausf-auth/v1/ue-authentications", "note": "the same request as for 5G AKA; the UDM's subscription decides the method", "body": P("ausf_UEAuthenticationCtx_eap"), "status": 201, "bodyIs": "response UEAuthenticationCtx: authType EAP_AKA_PRIME, 5gAuthData = the EAP-Request/AKA'-Challenge in base64, the eap-session link"},
             {"from": "AUSF", "to": "UDM", "proto": "SBI", "label": "POST /nudm-ueau/v1/{supi|suci}/security-information/generate-auth-data", "note": "the UDM sets the AMF separation bit and derives CK' and IK' with the serving network name (Annex A.3)", "body": P("udm_AuthenticationInfoResult_eap"), "status": 200, "bodyIs": "response AuthenticationInfoResult with AvEapAkaPrime (rand, autn, xres, ckPrime, ikPrime)"},
             {"from": "AMF", "to": "UE", "proto": "NAS", "label": "Authentication request  {ngKSI, ABBA, EAP message}", "note": "the challenge is in the EAP message IE instead of RAND and AUTN (TS 24.501 5.4.1.2.1)"},
             {"from": "UE", "to": "AMF", "proto": "NAS", "label": "Authentication response  {EAP message: EAP-Response/AKA'-Challenge}", "note": "the USIM checks AUTN, the ME derives CK', IK', MK, K_aut and sends AT_RES and AT_MAC"},
             {"from": "AMF", "to": "AUSF", "proto": "SBI", "label": "POST {eap-session link}  {eapPayload}", "note": "AT_MAC first, then RES against XRES; with AT_RESULT_IND on both sides a notification round follows", "body": P("ausf_EapSession_success"), "status": 200, "bodyIs": "response EapSession: EAP-Success, kSeaf, supi, AUTHENTICATION_SUCCESS"},
             {"from": "AUSF", "to": "UDM", "proto": "SBI", "label": "POST /nudm-ueau/v1/{supi}/auth-events", "note": "authType EAP_AKA_PRIME; the id the UDM returns is kept for the removal of the result", "status": 201},
             {"from": "AMF", "to": "UE", "proto": "NAS", "label": "Security mode command  {EAP message: EAP-Success, ABBA}", "note": "the EAP-success travels in the first NAS message under the new context (TS 24.501 5.4.1.2.1)"},
             {"from": "AMF", "to": "AUSF", "proto": "SBI", "label": "DELETE {eap-session link}  (at de-registration)", "note": "the AUSF has the UDM remove the result (PUT auth-events/{id}, authRemovalInd)", "status": 204},
         ]},
        {"id": "sbi-udr", "title": "UDR: reading, conditional writes, subscribing and being notified", "kind": "sbi",
         "summary": "The UDR serves every operation of the subscription, policy, exposure and application data APIs from one engine generated from the pinned OpenAPI files. Representations carry an entity tag; "
                    "a write can be made conditional; a consumer subscribes to the resources it caches and the UDR tells it when they change. The data is held in PostgreSQL (or a journalled file in development).",
         "spec": ["TS 29.504 5.2.2.2", "TS 29.504 5.2.2.3", "TS 29.504 5.2.2.6", "TS 29.504 5.2.2.8", "TS 29.504 6.1.2.2.4", "TS 29.505 5.2", "TS 29.519 6.2"],
         "nodes": ["Operator", "UDM", "UDR"],
         "steps": [
             {"from": "Operator", "to": "UDR", "proto": "SBI", "label": "PUT .../{supi}/00101/provisioned-data/am-data  (provisioning token)", "note": "the permanent subscription data has no create operation in TS 29.505: a provisioning extension of the same URI, validated against the schema of the GET answer", "status": 201},
             {"from": "UDM", "to": "UDR", "proto": "SBI", "label": "GET .../{supi}/context-data", "note": "the composite ContextDataSets is assembled from the registrations that exist; ?fields=/amf3Gpp restricts it", "body": P("udr_ContextDataSets"), "status": 200, "bodyIs": "response ContextDataSets"},
             {"from": "UDM", "to": "UDR", "proto": "SBI", "label": "PUT .../context-data/amf-3gpp-access  If-Match: \"3f\"", "note": "the entity tag is the revision; a stale tag is 412 and changes nothing, the check is part of the storage operation", "status": 412, "body": P("udr_ProblemDetails_412"), "bodyIs": "response ProblemDetails"},
             {"from": "UDM", "to": "UDR", "proto": "SBI", "label": "POST /nudr-dr/v2/subscription-data/subs-to-notify", "note": "the UDR chooses the expiry (at most the configured maximum, spread so that subscriptions made together do not expire together)", "body": P("udr_SubscriptionDataSubscriptions"), "status": 201, "bodyIs": "response SubscriptionDataSubscriptions with the subscriptionId"},
             {"from": "UDR", "to": "UDM", "proto": "SBI", "label": "POST {callbackReference}  DataChangeNotify", "note": "queued for a delivery thread: a slow consumer never delays the writer; retried, then given up on and counted", "body": P("udr_DataChangeNotify"), "status": 204, "bodyIs": "request DataChangeNotify"},
         ]},
        {"id": "sbi-ausf-prot", "title": "SoR and UPU protection by the AUSF", "kind": "sbi",
         "summary": "What the UDM asks the AUSF for when it delivers steering information or UE parameters. The AUSF holds the latest KAUSF of the UE (stored when it authenticated) and computes the MACs of "
                    "TS 33.501 A.17 to A.20 with a counter that goes up with every MAC.",
         "spec": ["TS 29.509 5.3.2.2", "TS 29.509 5.4.2.2", "TS 33.501 6.14", "TS 33.501 6.15", "TS 33.501 A.17", "TS 33.501 A.19"],
         "nodes": ["UDM", "AUSF"],
         "steps": [
             {"from": "UDM", "to": "AUSF", "proto": "SBI", "label": "POST /nausf-sorprotection/v1/{supi}/ue-sor/generate-sor-data", "note": "ackInd and the steering list: PLMN identities with access technologies", "body": P("ausf_SorSecurityInfo"), "status": 200, "bodyIs": "response SorSecurityInfo: SoR-MAC-IAUSF, CounterSoR, SoR-XMAC-IUE"},
             {"from": "UDM", "to": "AUSF", "proto": "SBI", "label": "POST /nausf-upuprotection/v1/{supi}/ue-upu/generate-upu-data", "note": "the UE parameters update data: default configured NSSAI, routing indicator, secured packet", "body": P("ausf_UpuSecurityInfo"), "status": 200, "bodyIs": "response UpuSecurityInfo: UPU-MAC-IAUSF, CounterUPU, UPU-XMAC-IUE"},
             {"from": "UDM", "to": "AUSF", "proto": "SBI", "label": "POST .../generate-sor-data  for a UE without a security context", "note": "nothing to protect with", "body": P("ausf_ProblemDetails"), "status": 404, "bodyIs": "response ProblemDetails (CONTEXT_NOT_FOUND)"},
         ]},
        {"id": "sbi-nrf-reg", "title": "NRF: registration, heart-beat and status notification", "kind": "sbi",
         "summary": "How an NF becomes known in the core. The AMF subscribes to UDM changes, the UDM registers and gets the profile back with a heart-beat timer, a PATCH keeps it alive, and deregistration is notified. Every body is what our NRF produced in the test run, validated against the pinned TS 29.510 OpenAPI.",
         "spec": ["TS 29.510 5.2.2.2", "TS 29.510 5.2.2.3.2", "TS 29.510 5.2.2.4", "TS 29.510 5.2.2.5", "TS 29.510 5.2.2.6"],
         "nodes": ["AMF", "NRF", "UDM"],
         "steps": [
             {"from": "AMF", "to": "NRF", "proto": "SBI", "label": "POST /nnrf-nfm/v1/subscriptions", "note": "asks to be told when a UDM registers or deregisters", "body": P("nrf_SubscriptionData"), "status": 201, "bodyIs": "response SubscriptionData (subscriptionId, validityTime)"},
             {"from": "UDM", "to": "NRF", "proto": "SBI", "label": "PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId}", "note": "the profile the UDM registers: services, addresses, PLMN", "body": P("nrf_NFProfile"), "status": 201, "bodyIs": "request NFProfile"},
             {"from": "NRF", "to": "UDM", "proto": "SBI", "label": "201 Created + Location", "note": "the NRF fills defaults (priority, capacity, load) and sets heartBeatTimer", "body": P("nrf_NFProfile_registered"), "status": 201, "bodyIs": "response NFProfile with heartBeatTimer"},
             {"from": "NRF", "to": "AMF", "proto": "SBI", "label": "POST {nfStatusNotificationUri}  NF_REGISTERED", "note": "queued and sent by worker threads, so a slow subscriber never blocks registration", "body": P("nrf_NotificationData"), "status": 204, "bodyIs": "request NotificationData"},
             {"from": "UDM", "to": "NRF", "proto": "SBI", "label": "PATCH /nnrf-nfm/v1/nf-instances/{id}  [{replace /nfStatus}]", "note": "the heart-beat; a load-only change is not announced. Missing heart-beats make the profile SUSPENDED and later purge it", "status": 204},
             {"from": "UDM", "to": "NRF", "proto": "SBI", "label": "DELETE /nnrf-nfm/v1/nf-instances/{id}", "note": "graceful shutdown", "status": 204},
             {"from": "NRF", "to": "AMF", "proto": "SBI", "label": "POST {nfStatusNotificationUri}  NF_DEREGISTERED", "note": "carries the URI of the profile that went away", "body": P("nrf_NotificationData_deregistered"), "status": 204, "bodyIs": "request NotificationData"},
         ]},
        {"id": "sbi-nrf-disc", "title": "NRF: discovery and access token", "kind": "sbi",
         "summary": "How the AMF finds a UDM and gets permission to call it. Filters, ordering by priority and load, a validity period for the consumer cache, then an ES256 access token whose key set is published at /oauth2/jwks.",
         "spec": ["TS 29.510 5.3.2.2", "TS 29.510 5.4.2.2", "TS 33.501 13.4.1", "RFC 7519"],
         "nodes": ["AMF", "NRF"],
         "steps": [
             {"from": "AMF", "to": "NRF", "proto": "SBI", "label": "GET /nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=AMF&service-names=nudm-sdm", "note": "only profiles that offer the service and are REGISTERED; the AMF caches the result for validityPeriod", "body": P("nrf_SearchResult"), "status": 200, "bodyIs": "response SearchResult (nfServices trimmed to the requested service)"},
             {"from": "AMF", "to": "NRF", "proto": "SBI", "label": "GET /nnrf-disc/v1/nf-instances?requester-nf-type=AMF", "note": "a mandatory parameter is missing", "body": P("nrf_ProblemDetails"), "status": 400, "bodyIs": "response ProblemDetails with invalidParams"},
             {"from": "AMF", "to": "NRF", "proto": "SBI", "label": "POST /oauth2/token  grant_type=client_credentials&scope=nudm-sdm...", "note": "the NRF checks the requester is registered and allowed, then signs a JWT (iss, sub, aud, scope, exp) with ES256", "body": P("nrf_AccessTokenRsp"), "status": 200, "bodyIs": "response AccessTokenRsp"},
         ]},
    ]


# ------------------------------------------------------------------------------------------------ code facts ------------

SERVICES = [
    (r"^/nudm-ueau/", "Nudm_UEAuthentication", "TS 29.503 5.4"),
    (r"^/nudm-sdm/", "Nudm_SubscriberDataManagement", "TS 29.503 5.2"),
    (r"^/nudm-uecm/", "Nudm_UEContextManagement", "TS 29.503 5.3"),
    (r"^/nnrf-nfm/", "Nnrf_NFManagement", "TS 29.510 5.2"),
    (r"^/nnrf-disc/", "Nnrf_NFDiscovery", "TS 29.510 5.3"),
    (r"^/oauth2/", "Nnrf_AccessToken (token endpoint; the key set is a deployment convenience)", "TS 29.510 5.4 / TS 33.501 13.4.1"),
    (r"^/nudr-dr/", "Nudr_DataRepository", "TS 29.504 / 29.505"),
    (r"^/3gpp-traffic-influence/", "NEF northbound: TrafficInfluence", "TS 29.522 5.4"),
    (r"^/3gpp-monitoring-event/", "NEF northbound: MonitoringEvent", "TS 29.122 5.3"),
    (r"^/3gpp-as-session-with-qos/", "NEF northbound: AsSessionWithQoS", "TS 29.122 5.14"),
    (r"^/nbsf-management/", "Nbsf_Management", "TS 29.521 5"),
    (r"^/nnef-callback/", "NEF callbacks of the AMF and the PCF (not an SBI service)", "TS 29.518 / TS 29.514"),
    (r"^/npcf-policyauthorization/", "Npcf_PolicyAuthorization", "TS 29.514 4.2"),
    (r"^/nnssf-nsselection/", "Nnssf_NSSelection", "TS 29.531 5.2"),
    (r"^/nnssf-nssaiavailability/", "Nnssf_NSSAIAvailability", "TS 29.531 5.3"),
    (r"^/nausf-auth/", "Nausf_UEAuthentication", "TS 29.509 5.2"),
    (r"^/nausf-sorprotection/", "Nausf_SoRProtection", "TS 29.509 5.3"),
    (r"^/nausf-upuprotection/", "Nausf_UPUProtection", "TS 29.509 5.4"),
    (r"^/npcf-smpolicycontrol/", "Npcf_SMPolicyControl", "TS 29.512 4.2"),
    (r"^/npcf-am-policy-control/", "Npcf_AMPolicyControl", "TS 29.507 4.2"),
    (r"^/nsmf-pdusession/", "Nsmf_PDUSession", "TS 29.502 5.2.2"),
    (r"^/namf-comm/", "Namf_Communication", "TS 29.518 5.2"),
    (r"^/namf-evts/", "Namf_EventExposure", "TS 29.518 5.3"),
    (r"^/namf-callback/", "AMF callbacks (SM context status, de-registration, AM policy, subscriber data)", "TS 29.502 / 29.503 / 29.507"),
    (r"^/nsmf-callback/", "SMF callbacks (SM policy notifications)", "TS 29.512 4.2.3"),
    (r"^/admin/", "operator admin API", "not a 3GPP interface"),
    (r"^/(health|metrics)", "platform (health, Prometheus)", "libs/nfcore"),
]
NF_DIRS = {"udm": ["nf/udm"], "pcf": ["nf/pcf"], "upf": ["nf/upf"], "smf": ["nf/smf"], "amf": ["nf/amf"], "nrf": ["nf/nrf"], "udr": ["nf/udr"], "ausf": ["nf/ausf"], "nssf": ["nf/nssf"], "nef": ["nf/nef"], "scp": ["nf/scp"], "bsf": ["nf/bsf"]}
LIB_DIRS = ["libs/base", "libs/config", "libs/crypto", "libs/gtpu", "libs/pfcp", "libs/nas", "libs/ngap", "libs/sbi", "libs/nfcore", "ctl", "tools/inspect"]


def classify(path):
    for pat, svc, spec in SERVICES:
        if re.search(pat, path):
            return svc, spec
    return "other", ""


def file_facts(rel, cov):
    text = rd(ROOT / rel)
    lines = text.splitlines()
    code = sum(1 for l in lines if l.strip() and not l.strip().startswith(("/*", "*", "//")))
    funcs = []
    for i, l in enumerate(lines[:-1]):
        m = re.match(r"^(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\([^;]*$", l)
        if m and not l.startswith((" ", "\t", "#", "typedef", "return", "if", "else", "for", "while", "switch")) and (
                lines[i + 1].strip() == "{" or l.rstrip().endswith("{")):
            funcs.append(m.group(1))
    c = cov.get("files", {}).get(rel)
    first = ""
    for l in lines[:6]:
        m = re.match(r"^/\*\s*(?!SPDX)(.*)", l)
        if m:
            first = m.group(1).strip(" */")
            break
    return {"path": rel, "lines": len(lines), "code": code, "funcs": funcs, "doc": first,
            "cov": None if not c else {"hit": c["hit"], "lines": c["lines"]}}


def sources(dirs, cov, tests=False):
    out = []
    for d in dirs:
        for f in sorted(glob.glob(str(ROOT / d / "src" / "*.c")) + glob.glob(str(ROOT / d / "include" / "g5c" / "*.h")) + glob.glob(str(ROOT / d / "*.c"))):
            out.append(file_facts(str(Path(f).relative_to(ROOT)).replace("\\", "/"), cov))
        if tests:
            for f in sorted(glob.glob(str(ROOT / d / "tests" / "*.c"))):
                out.append(file_facts(str(Path(f).relative_to(ROOT)).replace("\\", "/"), cov))
    return out


def metrics_of(dirs):
    out = {}
    for d in dirs:
        for f in glob.glob(str(ROOT / d / "src" / "*.c")):
            for m in re.finditer(r'"(g5c_[a-z0-9_]+)"\s*,\s*\n?\s*"([^"]+)"', rd(f)):
                out[m.group(1)] = m.group(2)
    return [{"name": k, "help": v} for k, v in sorted(out.items())]


def routes():
    try:
        raw = json.loads(subprocess.run([INSPECT, "routes"], capture_output=True, text=True, check=True).stdout)
    except (OSError, subprocess.CalledProcessError, ValueError):
        return {}
    res = {}
    for nf, lst in raw.items():
        rows = []
        for r in lst:
            svc, spec = classify(r["path"])
            rows.append({"method": r["method"], "path": r["path"], "service": svc, "spec": spec})
        res[nf] = rows
    return res


def configs():
    return {p.stem: rd(p) for p in sorted((ROOT / "configs").glob("*.yaml"))}


def adrs():
    out = []
    for p in sorted((ROOT / "docs" / "adr").glob("*.md")):
        t = rd(p)
        title = re.match(r"#\s*(.*)", t)
        st = re.search(r"(?im)^\**status\**:?\s*(.+)$", t)
        out.append({"file": p.name, "title": title.group(1).strip() if title else p.stem, "status": st.group(1).strip("* ") if st else ""})
    return out


def update_board():
    t = rd(ROOT / "docs" / "update.md")
    rows = []
    for l in t.splitlines():
        m = re.match(r"^\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|\s*$", l)
        if m:
            rows.append({"component": m.group(1), "phase": int(m.group(2)), "status": m.group(3), "notes": m.group(4)})
    entries = [{"date": m.group(1), "title": m.group(2)} for m in re.finditer(r"(?m)^##\s+(\d{4}-\d{2}-\d{2})\s+-\s+(.*)$", t)]
    return rows, entries


def tests_info():
    labels = collections.defaultdict(list)
    for lab in ("unit", "component", "integration", "conformance", "fuzz", "perf", "soak"):
        try:
            out = subprocess.run(["ctest", "--test-dir", str(CBUILD), "-N", "-L", lab], capture_output=True, text=True).stdout
        except OSError:
            out = ""
        for n in re.findall(r"Test\s+#\d+:\s+(\S+)", out):
            labels[n].append(lab)
    results = {}
    jp = BUILD / "junit.xml"
    if jp.exists():
        for tc in ET.parse(jp).getroot().iter("testcase"):
            results[tc.get("name")] = {"time": float(tc.get("time") or 0), "status": "fail" if tc.find("failure") is not None else "pass"}
    allnames = sorted(set(labels) | set(results))
    return [{"name": n, "labels": labels.get(n, []), **(results.get(n, {"time": None, "status": "unknown"}))} for n in allnames]


def regress_lines():
    p = BUILD / "regress-summary.txt"
    return [l.strip() for l in rd(p).splitlines() if l.strip()] if p.exists() else []


# ------------------------------------------------------------------------------------------------ curated parts --------

NODES = [
    # id, label, kind, x, y, phase, status, one-line role, spec
    ("UE", "UE", "ran", 70, 70, None, "peer", "Test peer: UERANSIM (never part of the product).", "TS 24.501"),
    ("gNB", "gNB", "ran", 70, 250, None, "peer", "Test peer: UERANSIM or an O-RAN emulator.", "TS 38.413"),
    ("AMF", "AMF", "nf", 300, 250, 5, "built", "Access and Mobility Management: N2 over SCTP, registration, 5G-AKA, NAS security, service request and paging, de-registration, configuration update, Xn and N2 handover, N1N2 transfer, event exposure, persistence.", "TS 23.501 6.2.1"),
    ("SMF", "SMF", "nf", 560, 250, 4, "built", "Session Management: PDU sessions, UE IP allocation, UPF selection and N4 control: create, activate / deactivate, release, PCF-driven modification, paging, UPF recovery, persistence.", "TS 23.501 6.2.2"),
    ("UPF", "UPF", "nf", 820, 250, 3, "built", "User Plane Function: GTP-U (N3), forwarding, QoS enforcement, usage reporting, N6 to the data network.", "TS 23.501 6.2.3"),
    ("DN", "Data network", "ran", 1040, 250, None, "peer", "Internet / operator services behind N6.", ""),
    ("PCF", "PCF", "nf", 560, 400, 2, "built", "Policy Control: session and access policy, PCC rules, QoS, mid-session policy push.", "TS 23.501 6.2.4"),
    ("UDM", "UDM", "nf", 300, 400, 1, "built", "Unified Data Management: authentication vectors, SUCI de-concealment, subscriber data, registrations.", "TS 23.501 6.2.7"),
    ("AUSF", "AUSF", "nf", 300, 540, 7, "built", "Authentication Server: Nausf_UEAuthentication with 5G AKA and EAP-AKA prime (RFC 5448, the 5G profile of TS 33.501 Annex F), the removal of a result, deregister and the FN-RG authentication; Nausf_SoRProtection and Nausf_UPUProtection (the MACs of TS 33.501 6.14 and 6.15); the latest KAUSF per SUPI kept in an encrypted state file.", "TS 23.501 6.2.5"),
    ("UDR", "UDR", "nf", 560, 540, 7, "built", "Unified Data Repository: Nudr_DataRepository (all operations of the subscription, policy, exposure and application data APIs, generated from the pinned OpenAPI files; validation, ETag / preconditions, subscriptions and notifications), Nudr_GroupIDmap, PostgreSQL or a journalled file behind one storage interface.", "TS 23.501 6.2.11"),
    ("NRF", "NRF", "nf", 820, 400, 7, "built", "NF Repository: Nnrf_NFManagement (register, update, heart-beat supervision, deregister, subscriptions and status notifications), Nnrf_NFDiscovery (filters, ordering, Service-Map), Nnrf_AccessToken (ES256 JWT), persistence. Every other function finds its peers here.", "TS 23.501 6.2.6"),
    ("NSSF", "NSSF", "nf", 820, 540, 7, "built", "Network Slice Selection Function: Nnssf_NSSelection (allowed and configured NSSAI, target AMF set, the slice instance of a PDU session, roaming mappings) and Nnssf_NSSAIAvailability (update, subscribe, notify), the slice policy in configuration, generated schema tables from the pinned OpenAPI.", "TS 23.501 6.2.17"),
    ("NEF", "NEF", "nf", 1040, 400, 7, "built", "Network Exposure Function: the northbound APIs of an AF: TrafficInfluence (into the UDR), MonitoringEvent (loss of connectivity, reachability, location from the AMF) and AsSessionWithQoS (authorized at the PCF over N5); access control per AF, state file, generated schema tables.", "TS 23.501 6.2.5A"),
    ("BSF", "BSF", "nf", 820, 70, 7, "built", "Binding Support Function: Nbsf_Management (register, update, deregister and discover the PCF that holds the SM policy association of a UE address; IPv4, IPv6 longest prefix match, MAC, framed routes, overlapping addresses, SamePcf), generated schema tables from the pinned OpenAPI, indexed by address, state file. The PCF registers, the NEF discovers.", "TS 23.501 7.2.15"),
    ("SCP", "SCP", "nf", 1040, 540, 7, "built", "Service Communication Proxy: indirect communication of TS 29.500 6.10 for every function: Model C (the consumer names the producer) and Model D (delegated discovery at the NRF, with a cache), reselection with quarantine of failing producers, loop detection, late request handling, chained SCPs, access control on the targets; the SBI client of every function sends its requests through it (scp_client).", "TS 23.501 6.2.19"),
]
# id, a, b, label, protocol, spec, state, evidence
EDGES = [
    ("NR-Uu", "UE", "gNB", "NR-Uu", "radio", "TS 38.300", "peer", "Simulated by UERANSIM."),
    ("N1", "UE", "AMF", "N1", "NAS over N2", "TS 24.501", "verified", "UERANSIM registers, authenticates, establishes sessions and de-registers through our AMF (S1-S4); the scripted UE of the end-to-end suite verifies every message with independently derived keys."),
    ("N2", "gNB", "AMF", "N2", "NGAP / SCTP", "TS 38.413", "verified", "UERANSIM's gNB sets up, registers UEs and carries sessions through our AMF over SCTP; scripted gNBs cover paging, service request, Xn path switch and N2 handover."),
    ("N3", "gNB", "UPF", "N3", "GTP-U / UDP 2152", "TS 29.281", "verified", "UERANSIM's gNB sends and receives user traffic through our UPF (ping, 0% loss); a downlink G-PDU is byte-identical to the one Open5GS's UPF produces."),
    ("N4", "SMF", "UPF", "N4", "PFCP / UDP 8805", "TS 29.244", "verified", "Both directions are proven: Open5GS's SMF drives our UPF, and our SMF drives our UPF (association, establishment with PCC rules, activate / deactivate, delete). Two differential analyses show identical request sequences and matching elements."),
    ("N6", "UPF", "DN", "N6", "IP via a TUN device", "TS 23.501", "verified", "The UPF runs on a real TUN device in the oracle; a host behind it answers the UE's ping."),
    ("N11", "AMF", "SMF", "N11", "Nsmf_PDUSession", "TS 29.502", "verified", "Open5GS's AMF creates, activates and releases PDU sessions at our SMF in oracle scenarios S1-S4 (OUR_SMF=1), with the N1 and N2 parts carried as multipart bodies; our SMF sends the accept, modification and release commands by N1N2MessageTransfer, which the AMF accepts and forwards to the gNB."),
    ("N8", "AMF", "UDM", "N8", "Nudm_UECM / SDM", "TS 29.503", "verified", "Open5GS's AMF (S3/S4) and our AMF (OUR_AMF=1) register and read subscriber data from our UDM."),
    ("N10", "SMF", "UDM", "N10", "Nudm_UECM / SDM", "TS 29.503", "verified", "Open5GS SMF (S3/S4) and our SMF (S3 with OUR_SMF=1) register PDU sessions and read SM data from our UDM."),
    ("N12", "AMF", "AUSF", "N12", "Nausf_UEAuthentication", "TS 29.509", "verified", "Our AMF authenticates UERANSIM through Open5GS's AUSF (S1-S4) and through ours (5G AKA and EAP-AKA prime: oracle S3-S5 with every function ours, the end-to-end suite with resynchronisation); Open5GS's AMF authenticates through our AUSF (S3)."),
    ("N13", "AUSF", "UDM", "N13", "Nudm_UEAuthentication", "TS 29.503", "verified", "Open5GS AUSF obtains vectors from our UDM; AUTN and RES* bit-exact (S3/S4). Our AUSF obtains them from our UDM (5G AKA and EAP-AKA prime vectors) and from Open5GS's UDM (S3)."),
    ("N7", "SMF", "PCF", "N7", "Npcf_SMPolicyControl", "TS 29.512", "verified", "Open5GS SMF creates, updates and deletes SM policies at our PCF and accepts a mid-session push (S3/S4). Our SMF creates and deletes them (S3) and applies a pushed update on the UPF and towards the UE (S4)."),
    ("N15", "AMF", "PCF", "N15", "Npcf_AMPolicyControl", "TS 29.507", "verified", "Our AMF creates and deletes the AM policy association at our PCF and at Open5GS's PCF (S2-S4); the update / terminate callbacks are accepted."),
    ("N35", "UDM", "UDR", "N35", "Nudr_DataRepository", "TS 29.504 / 29.505", "verified", "Our UDM against our UDR over real sockets, and Open5GS's UDM, AUSF, PCF, SMF and AMF against our UDR in oracle S3 / S4 (OUR_UDR=1); all stored documents validate against the OpenAPI schemas."),
    ("N36", "PCF", "UDR", "N36", "Nudr (policy data)", "TS 29.519", "verified", "Our PCF keeps its per-subscriber policy as operator-specific policy data; Open5GS's PCF reads AmPolicyData and SmPolicyData (with the snssai and dnn filters) from our UDR."),
    ("N22", "AMF", "NSSF", "N22", "Nnssf_NSSelection", "TS 29.531", "tested", "Our NSSF against Open5GS's NSSF (nssf_differential: same status, same NRF for the PDU session procedure) and in oracle S3 as the registered NSSF; our AMF does not consume it yet and Open5GS's AMF asks only on the home-routed roaming path."),
    ("Nnrf", "UDM", "NRF", "Nnrf", "Nnrf_NFManagement / Nnrf_NFDiscovery", "TS 29.510", "verified", "Every function registers, heart-beats and deregisters at our NRF and finds its peers through it (cluster and chaos runs); Open5GS's AUSF, UDR, UDM, BSF, PCF, NSSF, SMF and AMF do the same against it in oracle S3-S5; a differential against Open5GS's NRF has the same status codes."),
    ("Nnrf-p", "PCF", "NRF", "Nnrf", "Nnrf_NFManagement / Nnrf_NFDiscovery", "TS 29.510", "verified", "As above (the PCF finds the UDR through the NRF)."),
    ("N5", "NEF", "PCF", "N5", "Npcf_PolicyAuthorization", "TS 29.514", "verified", "The NEF asks the PCF for a QoS (a media component with a QoS reference); the PCF installs the PCC rule at Open5GS's SMF and at ours in oracle S7, and the allocation outcome returns to the AF."),
    ("N29", "NEF", "UDR", "Nudr", "Nudr_DataRepository (influence data)", "TS 29.519", "verified", "The NEF stores an AF's traffic influence as TrafficInfluData in our UDR (oracle S6)."),
    ("N29m", "NEF", "AMF", "Nnef-AMF", "Namf_EventExposure", "TS 29.518", "verified", "The NEF subscribes at our AMF for a UE's loss of connectivity, reachability and location; UERANSIM's de-registration reaches the AF (oracle S6)."),
    ("Nbsf-reg", "PCF", "BSF", "Nbsf", "Nbsf_Management_Register / Deregister", "TS 29.521", "verified", "The PCF registers the binding of every PDU session that has a UE address and removes it at the release: Open5GS's PCF against our BSF and our PCF against Open5GS's BSF (oracle S8), and with every function ours."),
    ("Nbsf-dis", "NEF", "BSF", "Nbsf", "Nbsf_Management_Discovery", "TS 29.521", "verified", "The NEF asks the BSF which PCF holds the UE address of an AsSessionWithQoS request and calls that PCF (oracle S7 with every function ours); Open5GS's BSF does not list the NEF among its allowed requesters, so there the NEF takes a PCF from the NRF."),
    ("N29u", "NEF", "UDM", "Nnef-UDM", "Nudm_SDM id translation, Nudm_UECM", "TS 29.503", "verified", "The NEF resolves an external identifier to the SUPI and finds the serving AMF of the UE (oracle S6)."),
]
WALKTHROUGHS = [
    {"id": "ausf-eap", "nf": "AUSF", "title": "How the AUSF runs EAP-AKA'", "where": "nf/ausf/src/eap.c: eap_start(), eap_session_post()", "steps": [
        {"t": "Turn the UDM's vector into keys", "d": "The UDM's AV' brings RAND, AUTN, XRES, CK' and IK'. The AUSF checks the AMF separation bit of AUTN (RFC 5448 3.3) and derives MK = PRF'(IK'|CK', \"EAP-AKA'\"|identity) with the IMSI digits as the identity (TS 33.501 Annex F.3): K_aut for AT_MAC, the EMSK for KAUSF.", "code": "load_vector(), g5c_eapaka_prime_keys()", "spec": "RFC 5448 3.3, RFC 9048 5.3.1"},
        {"t": "Send the challenge", "d": "EAP-Request/AKA'-Challenge: AT_RAND, AT_AUTN, AT_KDF (1), AT_KDF_INPUT with the serving network name padded to four octets, AT_RESULT_IND when configured, then AT_MAC computed over the whole packet with the MAC zeroed. It goes to the AMF base64-encoded in 5gAuthData, with the eap-session link.", "code": "build_challenge()", "spec": "RFC 5448 3.1 / 3.2 / 3.4.2"},
        {"t": "Check the response in the right order", "d": "AT_MAC is verified before any other attribute is looked at (RFC 4187 10.15), then AT_RES against XRES. An AT_KDF that asks for another function is as invalid as a bad MAC. A failed round gets a failure notification (no AT_MAC, P bit set) and, once that is acknowledged, EAP-Failure.", "code": "eap_session_post()", "spec": "RFC 4187 6.3, RFC 5448 3.2"},
        {"t": "Reject, error, synchronisation failure", "d": "AKA'-Authentication-Reject and Client-Error end the session with EAP-Failure. A synchronisation failure carries AT_AUTS: the AUSF asks the UDM for a new vector with it and sends a new challenge, at most twice.", "code": "resync()", "spec": "TS 33.501 6.1.3.3.2"},
        {"t": "Protected success indication", "d": "When both sides asked for AT_RESULT_IND the AUSF sends a notification with code 32768 (success) and AT_MAC, and EAP-Success follows its response whatever that response says.", "code": "notify_success()", "spec": "RFC 4187 6.2"},
        {"t": "Finish", "d": "KAUSF is the first 256 bits of the EMSK, KSEAF = KDF(KAUSF, serving network name). The result is POSTed to the UDM, KAUSF is stored for the SoR / UPU protection (counters back to 1), and EAP-Success with KSEAF and the SUPI goes to the AMF.", "code": "succeed(), ue_store()", "spec": "TS 33.501 6.1.3.1 step 10"},
    ]},
    {"id": "ausf-sor", "nf": "AUSF", "title": "How the AUSF computes SoR-MAC-IAUSF", "where": "nf/ausf/src/prot.c: sor_generate()", "steps": [
        {"t": "Find the context and take a counter", "d": "The latest KAUSF of the SUPI is copied out under the table lock and CounterSoR is taken: the current value is used and then incremented, 0x0001 after every new KAUSF. At 0xFFFF the service for the UE is suspended with 503 COUNTER_WRAP until the next authentication.", "code": "grant()", "spec": "TS 33.501 6.14.2.3"},
        {"t": "Build the SoR header", "d": "One octet: bit 1 SOR data type 0, bit 2 list indication, bit 3 list type (PLMN list or secured packet), bit 4 ACK.", "code": "hdr in sor_generate()", "spec": "TS 24.501 9.11.3.51"},
        {"t": "Encode the list", "d": "Five octets per entry: the PLMN identity (MCC2|MCC1, MNC3|MCC3, MNC2|MNC1; 1111 for a missing third MNC digit) and two octets of access technology bits (NG-RAN, satellite NG-RAN, E-UTRAN in WB-S1 / NB-S1 mode, UTRAN, GSM variants, cdma2000). A secured packet is passed as bytes.", "code": "encode_steering(), act_bits()", "spec": "TS 24.008 10.5.1.13, TS 31.102 4.2.5"},
        {"t": "The MACs", "d": "SoR-MAC-IAUSF = the 128 least significant bits of KDF(KAUSF, FC 0x77, header, counter, list). With ackInd the expected SoR-XMAC-IUE = KDF(KAUSF, 0x78, 0x01, counter) is returned as well.", "code": "mac128()", "spec": "TS 33.501 A.17, A.18"},
    ]},
    {"id": "nrf-register", "nf": "NRF", "title": "How the NRF registers and watches an NF", "where": "nf/nrf/src/mgmt.c, store.c: nfm_put(), monitor thread", "steps": [
        {"t": "Parse and check the profile", "d": "PUT /nnrf-nfm/v1/nf-instances/{id}: the id in the URI must equal nfInstanceId, nfType must be known, addresses and services must be well formed. A Service-Map style nfServiceList is accepted as well as the nfServices array.", "code": "nfm_put(), nrf_profile_check()", "spec": "TS 29.510 6.1.6.2.2"},
        {"t": "Fill defaults and store", "d": "Priority 0, capacity 100, load 0 and the PLMN list are filled in; the registry keeps the profile in memory with hash indexes by id and type, and writes a JSON state file behind the request, so a restart restores it.", "code": "store_put(), flush_state()", "spec": "TS 29.510 5.2.2.2"},
        {"t": "Answer with a heart-beat timer", "d": "201 with Location and the stored profile, heartBeatTimer set; a replacement of an existing id answers 200. ETag support allows If-Match on later updates.", "code": "nfm_put()", "spec": "TS 29.510 5.2.2.2.2"},
        {"t": "Tell the subscribers", "d": "Subscriptions are matched on nfType, instance id, service name, GUAMI, TAI and so on; matching ones get a NotificationData on a queue served by two worker threads, so a dead subscriber delays nobody.", "code": "notify_matching()", "spec": "TS 29.510 5.2.2.5"},
        {"t": "Watch the heart-beat", "d": "A monitor thread suspends a profile after its heart-beat timer elapses twice and purges it later; a late PATCH revives it with 200 and the profile. Each state change is notified.", "code": "monitor_main()", "spec": "TS 29.510 5.2.2.3.2"},
    ]},
    {"id": "nrf-discover", "nf": "NRF", "title": "How the NRF answers a discovery query", "where": "nf/nrf/src/disc.c: disc_get()", "steps": [
        {"t": "Parse the query", "d": "target-nf-type and requester-nf-type are mandatory. snssais and tai are JSON, service-names is a comma list (OpenAPI form, explode false); unknown values or malformed JSON are 400 with invalidParams.", "code": "parse_query()", "spec": "TS 29.510 6.2.3.2.3.1"},
        {"t": "Filter", "d": "Type, REGISTERED status, service name, DNN, S-NSSAI, TAI, GUAMI, PLMN, SUPI ranges and patterns, allowedNfTypes of the target against the requester.", "code": "profile_matches()", "spec": "TS 29.510 6.2.3.2.3.1"},
        {"t": "Order and cut", "d": "Same-locality first, then lowest priority value, then lowest load; limit applies after ordering.", "code": "order_cmp()", "spec": "TS 29.510 5.3.2.2.2"},
        {"t": "Answer", "d": "SearchResult with validityPeriod so the consumer can cache, and nrfSupportedFeatures. Profiles are rendered in the consumer's style (map or array) according to supported-features.", "code": "nrf_profile_view()", "spec": "TS 29.510 6.2.6.2.2"},
    ]},
    {"id": "upf-downlink", "nf": "UPF", "title": "How a downlink packet crosses the UPF", "where": "nf/upf/src/dp.c: dl_dispatch(), apply(), forward()", "steps": [
        {"t": "Read from the TUN device", "d": "The runtime drains the N6 descriptor in a bounded loop (256 packets per wake) and hands each IP packet to the engine. Outgoing GTP-U packets are collected and sent with one sendmmsg per batch.", "code": "drain_n6(), flush_tx() in rt.c", "spec": "-"},
        {"t": "Find the session", "d": "The destination address selects the session: the whole 32 bits for IPv4, the /64 prefix for IPv6. No session means the packet is dropped and counted (no_session).", "code": "ptrmap_get(by_ue4 / by_ue6)", "spec": "TS 29.244 5.2.1"},
        {"t": "Pick the PDR", "d": "Among the session's PDRs whose source interface is Core, the lowest precedence value that also matches the SDF filters wins. Filters are IPFilterRules; 'assigned' means the session's UE address.", "code": "upf_sdf_match()", "spec": "TS 29.244 5.2.1"},
        {"t": "Enforce QoS", "d": "Every QER the PDR points at is checked: a closed downlink gate drops, and a token bucket at the MBR drops what exceeds the rate. QERs shared by several PDRs share one bucket, which is how a session-AMBR works.", "code": "qer_pass()", "spec": "TS 29.244 5.2.5"},
        {"t": "Apply the FAR", "d": "Drop, buffer (and tell the SMF once with a Downlink Data Report if NOCP is set), or forward. Forwarding with an Outer Header Creation builds the GTP-U header: TEID of the gNB tunnel and a PDU Session Container carrying the QFI.", "code": "forward(), tx_encap()", "spec": "TS 29.281 5.2.2.7, TS 38.415 5.5.2.1"},
        {"t": "Count", "d": "Usage reporting rules count the packet; a volume threshold, a time threshold or a period queues a Session Report Request to the SMF, which is retransmitted until answered.", "code": "urr_account(), urr_tick(), n4_send_session_report()", "spec": "TS 29.244 5.2.2"},
    ]},
    {"id": "smf-create", "nf": "SMF", "title": "How the SMF creates a PDU session", "where": "nf/smf/src/sm.c: create_ctx()", "steps": [
        {"t": "Read the AMF's request", "d": "multipart/related: a JSON part (SUPI, PDU session id, DNN, slice, the AMF's status URI) and the PDU Session Establishment Request as the N1 binary part. Anything malformed is answered 400 with a reject message for the UE where one can be built.", "code": "parse_request(), smf_gsm_parse_est_req()", "spec": "TS 29.502 5.2.2.2.1, TS 24.501 8.3.1"},
        {"t": "Check the subscription", "d": "Subscribed slice and DNN from the UDM (Nudm_SDM sm-data); the requested PDU session type is matched against the allowed ones and the pools of the DNN, with a single-stack fallback and cause #50 / #51.", "code": "smf_udm_sm_data(), select_type()", "spec": "TS 29.503, TS 24.501 6.4.1.3"},
        {"t": "Select the UPF and allocate the address", "d": "Round-robin over the associated UPFs that serve the DNN and slice; an IPv4 address and/or an IPv6 /64 prefix from the DNN pool.", "code": "smf_n4_select(), smf_pool_alloc4/6()", "spec": "TS 23.501 5.8.2"},
        {"t": "Register and get the policy", "d": "SMF registration at the UDM, SM policy association at the PCF; the decision becomes one default QoS flow plus one flow per distinct QoS data of the PCC rules.", "code": "smf_udm_register(), smf_pcf_create(), smf_policy_from_decision()", "spec": "TS 29.503, TS 29.512 4.2.2.2"},
        {"t": "Establish the N4 session", "d": "Default and per-rule PDRs, uplink and downlink FARs (downlink dropped until the gNB tunnel is known), a session QER and a QER per flow, a BAR. The UPF chooses the uplink TEID, which comes back in Created PDR.", "code": "smf_n4_build_est(), smf_n4_call()", "spec": "TS 29.244 7.5.2, 5.2.1A.2A"},
        {"t": "Answer 201, then send the accept", "d": "The 201 with Location goes out first; a deferred job then sends the accept (N1) and the resource setup request (N2) to the AMF in an N1N2MessageTransfer. If the AMF refuses, everything is given back and the AMF is told the context is released.", "code": "job_n1n2(), smf_amf_n1n2()", "spec": "TS 29.518 5.2.2.3.1, TS 23.502 4.3.2.2.1"},
        {"t": "Activate the user plane", "d": "The gNB's tunnel arrives in Update SM Context (PDU_RES_SETUP_RSP); the downlink FAR is changed to forward to it. Deactivation buffers the downlink and re-activation hands the AN the tunnel again.", "code": "modify_ctx(), smf_n4_build_mod_activate()", "spec": "TS 29.502 5.2.2.3.2"},
    ]},
    {"id": "upf-n4", "nf": "UPF", "title": "How the UPF handles a Session Establishment Request", "where": "nf/upf/src/n4.c: handle_session_establishment()", "steps": [
        {"t": "Check the association", "d": "Only a peer with an established association may create sessions (cause 72 otherwise). Retransmitted requests are answered from a cache so the session is not created twice.", "code": "cache_replay(), n4_find_peer()", "spec": "TS 29.244 6.1, 5.8"},
        {"t": "Parse rules in two passes", "d": "FAR, QER, URR and BAR first, then the PDRs, so every reference resolves. A rule that is malformed, duplicated or refers to something missing fails the whole request with the cause and the offending IE.", "code": "rules_create_*()", "spec": "TS 29.244 7.5.2"},
        {"t": "Allocate F-TEIDs", "d": "A PDR asking the UP function to choose gets a fresh TEID; PDRs with the same choose id share it. The SMF is told which TEID in Created PDR. Explicit TEIDs from the SMF are accepted if unused.", "code": "assign_teid()", "spec": "TS 29.244 5.5"},
        {"t": "Index and answer", "d": "TEIDs and UE addresses go into the lookup tables; a UE address already owned by a stale session moves to the new one. The response carries our F-SEID, Created PDR entries and Cause 1.", "code": "sess_index_pdr(), created_pdrs()", "spec": "TS 29.244 7.5.3"},
        {"t": "Modification is all-or-nothing", "d": "Before a Session Modification the rules are snapshotted; if any element fails, the snapshot is restored and nothing has changed. A FAR that moves from buffering to forwarding releases held packets in order.", "code": "sess_snapshot(), dp_flush_buffer()", "spec": "TS 29.244 7.5.4"},
    ]},
    {"id": "udm-vector", "nf": "UDM", "title": "How the UDM builds an authentication vector", "where": "nf/udm/src/ueau.c: vector_for()", "steps": [
        {"t": "Resolve the identity", "d": "A SUPI is used as is; a SUCI goes through the SIDF: scheme 0 is the null scheme, 1 and 2 are ECIES Profile A (X25519) and B (P-256) with the home-network key chosen by the key id. The MAC tag is checked before any decryption.", "code": "udm_resolve() in nf/udm/src/core.c, libs/crypto/src/suci.c", "spec": "TS 33.501 6.12.5"},
        {"t": "Authorise the serving network", "d": "servingNetworkName must match 5G:mncXXX.mccXXX.3gppnetwork.org, optionally followed by an SNPN network id; otherwise 403 SERVING_NETWORK_NOT_AUTHORIZED.", "code": "udm_valid_snn()", "spec": "TS 29.503 ServingNetworkName"},
        {"t": "Read the credentials from the UDR", "d": "GET authentication-subscription. K and OPc are AES-256-GCM ciphertexts with the SUPI bound as associated data, so a ciphertext copied to another subscriber fails authentication.", "code": "udm_udr_auth_subscription(), udm_unprotect()", "spec": "strategy: envelope encryption hook"},
        {"t": "Resynchronise if asked", "d": "With resynchronizationInfo (RAND, AUTS) the UDM recomputes MAC-S with f1* and only then takes SQNms; a forged AUTS is rejected with 403 and the SQN is untouched.", "code": "udm_resync()", "spec": "TS 33.102 6.3.5"},
        {"t": "Advance and persist the SQN first", "d": "SQN += 32 is written to the UDR with a JSON Patch before the vector is released, so a crash between the two can only skip a value, never reuse one.", "code": "udm_next_sqn(), udm_udr_patch_auth_subscription()", "spec": "TS 33.102 Annex C"},
        {"t": "Milenage and the 5G key hierarchy", "d": "f1-f5 give MAC-A, XRES, CK, IK, AK; AUTN = (SQN xor AK) || AMF || MAC-A. XRES* and KAUSF are derived with the KDF of TS 33.220 using the serving network name.", "code": "udm_generate_av() → libs/crypto milenage.c, aka5g.c", "spec": "TS 35.206/35.208, TS 33.501 A.2, A.4"},
        {"t": "Answer and wipe", "d": "AuthenticationInfoResult with the 5G HE AV; K, OPc and the vector are overwritten with OPENSSL_cleanse before the function returns.", "code": "done: label in vector_for()", "spec": "TS 29.503 AuthenticationInfoResult"},
    ]},
    {"id": "pcf-layers", "nf": "PCF", "title": "How the PCF decides: policy layering", "where": "nf/pcf/src/policy.c: pcf_resolve()", "steps": [
        {"t": "Collect the layers, most specific first", "d": "1. subscriber policy for this DNN, 2. subscriber default, 3. configured policy for this DNN, 4. configured default. Subscriber documents come from the UDR (admin API or g5c-ctl policy put).", "code": "pcf_resolve()", "spec": "TS 29.512 4.2.2.2"},
        {"t": "Session AMBR", "d": "First layer that defines one wins; otherwise the subscribed AMBR the SMF sent in the request; otherwise 1 Gbps.", "code": "layers[i]->has_ambr", "spec": "TS 29.512 4.2.2.5"},
        {"t": "Default QoS", "d": "First layer that defines it wins; otherwise the subscribed default QoS from the SMF; otherwise 5QI 9, ARP priority 8. A default flow must use a non-GBR 5QI (validated when the policy is stored).", "code": "pcf_profile_validate()", "spec": "TS 29.512 4.2.2.6"},
        {"t": "PCC rules", "d": "The first layer that has rules supplies all of them (no merging across layers). GBR 5QIs require GBR rates, non-GBR 5QIs must not carry them; flow descriptions must be IPFilterRules starting with permit.", "code": "pcf_profile_validate()", "spec": "TS 29.512 5.6.2"},
        {"t": "Build SmPolicyDecision", "d": "sessRules with the AMBR and default QoS, pccRules with flow infos and references, qosDecs with 5QI, ARP and bit rates. Mid-session changes are pushed to the SMF notificationUri with the same function.", "code": "pcf_decision(), pcf_repush()", "spec": "TS 29.512 4.2.3"},
    ]},
]
FINDINGS = [
    ("2026-10-13", "AMF", "medium", "Open5GS's PCF refused the AM policy request because the NrLocation carried no ncgi (mandatory in the OpenAPI model).", "The location JSON always carries tai and ncgi (cell id zero-padded to 9 digits).", "oracle S2 (OUR_AMF=1)"),
    ("2026-10-13", "AMF", "medium", "NRF discovery of the SMF with the S-NSSAI as a single JSON object was answered 400 by Open5GS's NRF.", "snssais is sent as a JSON array.", "oracle S2 (OUR_AMF=1)"),
    ("2026-10-13", "AMF", "medium", "A UE that failed security mode negotiation (#23) kept a context after the connection was released.", "Release completion drops every context that never became a registration.", "test_algorithms_and_rejects"),
    ("2026-10-13", "AMF", "low", "ThreadSanitizer: gNB slot flags were written under the send mutex and read under the table mutex; UE state counters were read by the gauges without the UE mutex; the stop flag was a plain bool.", "Nested locking for the slot flags, atomic state fields and stop flag.", "amf_e2e (tsan)"),
    ("2026-10-13", "AMF", "low", "AddressSanitizer: a stray temporary of the UE security capabilities leaked in the path switch.", "Removed.", "amf_e2e (asan)"),
    ("2026-10-09", "SMF", "medium", "A GBR QoS data from the PCF without maximum bit rates (valid: the maximum defaults to the guaranteed rate) made a strict reading reject the whole decision and the session.", "Missing MBR defaults to GBR (TS 29.512); table-driven policy tests.", "test_policy"),
    ("2026-10-09", "SMF", "medium", "The differential against Open5GS's SMF showed our requests lacked the 3GPP Interface Type of the PDRs and FARs and used one Outer Header Removal value only.", "Interface types N3/N6 added and Outer Header Removal set to GTP-U/UDP/IP.", "pfcp_differential_smf"),
    ("2026-10-09", "SMF", "low", "The PCF can send flow descriptions the NAS packet filter cannot express (IPv6, port lists); accepting them would have produced rules the UE cannot match.", "Refused when the decision is read; explicit table of accepted and refused IPFilterRules.", "test_ipfilter, test_policy"),
    ("2026-10-09", "tests", "low", "ThreadSanitizer: the end-to-end test read the UPF engine's counters from another thread (test code).", "upf_rt_snapshot() publishes a copy after each control-plane message and timer tick.", "smf_e2e (TSan)"),
    ("2026-10-08", "UPF", "high", "The UP Function Features bits were set from memory with the wrong bit order: the UPF claimed traffic steering and PFD management instead of F-TEID allocation, so the Open5GS SMF allocated TEIDs itself. The unit test only checked that the element was present.", "Bits taken from the pinned TS 29.244 table (FTUP, EMPU), named constants, exact-bytes assertion, and the differential analysis against Open5GS's UPF.", "test_open5gs_replay, pfcp_differential"),
    ("2026-10-08", "UPF", "medium", "A missing pfcp or gtpu section in the UPF config produced an empty error message.", "Explicit message naming the missing section; 27 bad-configuration cases.", "bad_configs_rejected"),
    ("2026-10-08", "UPF", "low", "UBSan: memcpy from a NULL array when a session snapshot had no rules of a kind.", "Copy only when the count is non-zero; ASan/UBSan run on every test.", "upf_engine (asan)"),
    ("2026-10-08", "UPF", "low", "SMReq flag DROBU (drop buffered packets) was ignored.", "Implemented and tested.", "test_buffering"),
    ("2026-10-08", "JSON", "high", "A request body with tens of thousands of members made the admin API quadratic (every lookup was a linear scan) and timed out.", "Objects above 16 members carry a hash index; model-based test against a naive reference; explicit limits of 64 slices and 256 DNNs per subscriber.", "test_complexity_abuse, test_json_object_index"),
    ("2026-10-08", "JSON", "medium", "A number such as 1e999 was accepted as infinity and later written back as null, silently changing a value.", "Out-of-range numbers are rejected by the parser.", "test_json_properties (mutation), test_json_conformance"),
    ("2026-10-08", "UDM", "medium", "ServingNetworkName with the Release 16 SNPN network-identifier suffix was refused although the schema allows it.", "Validator accepts ':' followed by 11 upper-case hex digits.", "test_util"),
    ("2026-10-08", "udr-lite", "medium", "A store path in a missing or read-only directory was accepted at start-up and failed at the first write.", "The file is created at start-up; an unwritable location is a start-up error.", "test_store_startup, bad_configs_rejected"),
    ("2026-10-08", "platform", "medium", "<nf> --check did not open TLS certificates and keys, so a bad TLS configuration passed the check.", "g5c_nf_check() loads the TLS material.", "bad_configs_rejected"),
    ("2026-10-08", "udr-lite", "low", "JSON Patch into a scalar parent reported 'bad item' instead of 'path not found'.", "Consistent error class; RFC 6902 appendix A cases added.", "test_patch_rfc6902"),
    ("2026-10-08", "UDM", "medium", "Retrieval of multiple data sets (dataset-names) was missing although normative in Release 15.", "Implemented for AM, SMF_SEL, SM, UEC_SMF; validated against the schema.", "test_sdm_multiple_datasets"),
    ("2026-10-08", "tests", "low", "ThreadSanitizer: the SBI test observer wrote a shared buffer from several worker threads (test code, not product code).", "Mutex in the test; the product code is TSan-clean under the 12 s soak.", "sbi_router_h2_tls (tsan)"),
    ("2026-10-07", "UDM", "medium", "Re-provisioning a subscriber did not notify SDM subscribers.", "ModificationNotification sent to every subscription of the SUPI.", "test_sdm_notification"),
    ("2026-10-07", "SBI", "high", "libuv's process-global thread pool deadlocked when the UDM and udr-lite shared a process.", "Per-server worker pool with a completion queue.", "udm_perf_gate"),
    ("2026-10-07", "udr-lite / SBI", "medium", "gcc -fanalyzer: leaked FILE on an error path in the store; fragile connection teardown order in the server.", "Rewritten; analyzer gate in scripts/c_lint.sh.", "c_lint.sh"),
    ("2026-10-28", "SBI / deploy", "medium", "A renewed certificate carried the addresses of the environment of the renewing command, not those of the function (the AMF of the demo is at 127.0.0.5): new connections to it failed the name check.", "`g5c-pki.sh renew` keeps the names of the current certificate.", "host_selftest (renew, then re-attach)"),
    ("2026-10-28", "SMF", "high", "A failed N4 call (the UPF did not answer) left the response unset and the caller read a cause from it: a crash (found by the ThreadSanitizer run of the TLS cluster test).", "A failed call leaves an empty response.", "cluster_tls (tsan)"),
    ("2026-10-28", "UPF", "medium", "SIGHUP terminated the UPF (no handler); the first handler raced with start-up (ThreadSanitizer).", "SIGHUP blocked first thing in main, a thread takes it, a lock orders reload and stop; certificates reload without a restart.", "cluster_tls"),
    ("2026-10-28", "SMF", "medium", "The S-NSSAI of the PFCP Session Establishment was one octet; TS 29.244 8.2.176 fixes it at four (Wireshark showed the packet as malformed in a capture of the demo).", "Always four octets, SD FFFFFF when there is none.", "pfcp_differential_smf, smf_e2e"),
    ("2026-10-28", "AMF", "low", "The gNB retransmitted two N2 messages: the kernel delays SCTP acknowledgements up to 200 ms and the gNB's timer is about 120 ms.", "The AMF acknowledges every packet at once.", "demo capture (no retransmissions)"),
    ("2026-10-28", "NRF", "low", "The NRF's default self URI was http://127.0.0.1 whatever its address and TLS setting.", "Scheme and address of its configuration.", "cluster_tls"),
    ("2026-10-29", "AMF", "medium", "A de-registered UE context stayed for ever when the gNB closed its association right behind the de-registration request (one run in eight of a 10-UE load).", "The context is removed when the connection is already gone.", "cluster_load_small"),
    ("2026-10-29", "SMF", "low", "Found while building the charging records: the usage-report rule flag was wiped by a memset of the N4 context of policy updates.", "Set after the memset.", "smf_e2e (CDR)"),
    ("2026-10-29", "tools", "low", "The redaction filter handled input line by line, so a PEM private key block spanning lines was not removed.", "The whole input is redacted at once.", "redact_tool"),
]
PHASE_STATUS = {0: ("done", "Foundations built in C; Docker image unverified"), 1: ("done", "UDM + the udr-lite and AUSF shims (both replaced in Phase 7), interop-verified"),
                2: ("done", "PCF, interop-verified"), 3: ("done", "UPF Stage A (userspace), interop-verified; Stage B (AF_XDP) later"),
                4: ("done", "SMF: Nsmf_PDUSession, 5GSM, N2 SM, N4 with PCC mapping, PCF-driven modification, paging, UPF recovery, persistence; Open5GS AMF + UERANSIM pass S1-S4 against it"),
                5: ("done", "AMF: N2 / NGAP over SCTP, 5GMM, 5G-AKA, NAS security, service request, paging, Xn and N2 handover, persistence; UERANSIM passes S1-S5 against our AMF with our SMF, UPF, UDM and PCF"),
                7: ("done", "All eleven functions (NRF, AUSF, UDR, NSSF, NEF, SCP built in this phase) and a twelfth, the BSF, built and verified against Open5GS and UERANSIM; the shims are deleted. Carried into Phase 8: the AMF as a consumer of the NSSF (the multi-slice scenario), the PCF's UE policy and usage monitoring, event exposure completion"),
                8: ("next", "Production hardening, in work packages (ADR-0025). Built and tested: OAuth2 access tokens and mutual TLS between all functions (certificate renewal without a restart), secrets hygiene and master key rotation, Prometheus rules / Grafana / runbooks / audit log / SLO gates, charging data records, log level at run time, upgrade and rollback under load, the NSSF used by the AMF for registration and PDU sessions. Open: high availability with shared state, UPF 10-100 Gbit/s (hardware), PCF UE policy and usage monitoring, Nudm_EventExposure, lawful intercept (design only), Nchf, the external penetration test and the 7 day soak (third party / time)"),
                9: ("next", "Productisation and release: release candidate 0.9.0-rc1 built (versioned binaries, signed archives, SBOM, automated licence audit, NOTICE, systemd units and installer, installation / upgrade / administrator guides, API reference, diagnostics bundle, redaction, capture helper, pilot plan, threat model). Open: counsel's sign-off and the patent / FRAND review, a vulnerability scan of the SBOM, signing with the offline key, container and Kubernetes builds (no runtime here), the pilot itself"),
                6: ("done", "System: the daemons as separate processes; 10,000 UEs with PDU sessions in 20.7 s; kill / restart under load recovers; soak harness. Not run: 72 h soak, srsUE / OCUDU / O-RAN emulator (deferred until Phase 7)")}
OPEN_DECISIONS = [
    {"title": "SNOW 3G licence (NEA1/NIA1)", "why": "Needs a director-signed ETSI/SAGE licence. Not needed for a demo with srsUE / UERANSIM (they use NEA2 / NIA2); the AMF refuses SNOW 3G until it is licensed (ADR-0012).", "needs": "director signature"},
    {"title": "UPF Stage B throughput target", "why": "ADR-0014 proposes 10 Gbit/s of 1400-byte packets on a two-NIC host with AF_XDP; it needs a NIC with XDP support before it can be measured. Left as is by the owner (2026-10-14).", "needs": "hardware"},
    {"title": "Counsel's sign-off of the licence audit and the patent / FRAND review", "why": "Phase 9 exit: the automated audit passes and the review is recorded for counsel (docs/legal/patent-frand-review.md); the conclusion, and the licence terms of the product itself (LICENSE is a placeholder), are a legal decision.", "needs": "counsel / owner"},
    {"title": "External penetration test and 7 day soak", "why": "Phase 8 validation needs a third party and a host left alone for a week; the threat model and the pilot plan brief them (docs/security/threat-model.md, docs/pilot-plan.md).", "needs": "third party, a host"},
    {"title": "Containers and Kubernetes", "why": "The Dockerfile, compose file and manifests exist but were never built or applied: no container runtime or cluster was available.", "needs": "a runtime / cluster"},
    {"title": "High availability with shared state", "why": "AMF / SMF contexts in an external store, N4 failover to a second UPF, SCTP multi-homing, autoscaling: a design of its own; today a function that dies loses its connected UEs (registrations and sessions come back from the state file).", "needs": "design decision"},
    {"title": "PCF UE policy and usage monitoring, Nudm_EventExposure", "why": "Carried from Phase 7 (WP10, WP11); they need their own designs and tests.", "needs": "planned"},
    {"title": "72 hour soak", "why": "The harness exists (g5c-cluster.sh ns soak 500 259200); it needs a host left alone for three days.", "needs": "a host"},
]
DECIDED = [
    {"title": "Release 17 track", "why": "Opened by the owner on 2026-10-14 (ADR-0017): starts after Phase 7; pinned spec text and a gate per feature.", "needs": "decided"},
]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    cov = jload(BUILD / "coverage.json", {})
    matrix = {"title": "Conformance matrix", "rows": []}
    for mf in sorted((ROOT / "docs" / "conformance").glob("*.json")):
        matrix["rows"] += (jload(mf, {"rows": []}))["rows"]
    phases = jload(ROOT / "docs/strategy/phases.json", {"phases": []})["phases"]
    for p in phases:
        st, note = PHASE_STATUS.get(p["phase"], ("planned", ""))
        p["status"], p["statusNote"] = st, note
    rt = routes()
    cfgs = configs()
    board, entries = update_board()
    tests = tests_info()
    nf_detail = {}
    for nf, dirs in NF_DIRS.items():
        key = nf
        nf_detail[nf] = {"routes": rt.get(nf, []), "files": sources(dirs, cov, tests=True), "metrics": metrics_of(dirs),
                         "config": cfgs.get(nf), "matrix": [r["id"] for r in matrix["rows"] if r["nf"].lower() in (nf, nf.split("-")[0])]}
    libs = {d: sources([d], cov, tests=False) for d in LIB_DIRS}
    roles = learn_roles("s3_open5gs_v2.8.0_ueransim.pcapng")  # same oracle addresses in every scenario
    procedures = [
        trace_procedure("s1_registration_open5gs_v2.8.0_ueransim.pcapng", "S1: registration with 5G-AKA and SQN resynchronisation",
                        "A real capture of Open5GS v2.8.0 and UERANSIM: NG Setup, registration, authentication (the first vector is rejected by the USIM, so the UE sends an AUTS and the network resynchronises), security mode and initial context setup. Decoded with our own NGAP and NAS codecs.",
                        ["TS 38.413 8.7.1", "TS 24.501 5.4.1", "TS 33.501 6.1.3.2", "TS 33.102 6.3.5"], roles),
        trace_procedure("s3_open5gs_v2.8.0_ueransim.pcapng", "S3: registration, PDU session with traffic, release, de-registration",
                        "The full lifecycle on the wire, including PFCP towards the UPF and GTP-U user plane (a ping through the UPF).",
                        ["TS 24.501 5.4.1", "TS 24.501 6.4.1", "TS 29.244 7.5", "TS 29.281"], roles),
        trace_procedure("s3_our_upf_open5gs_smf_ueransim.pcapng", "S3 again, with OUR UPF",
                        "The same scenario with our UPF instead of Open5GS's: the SMF sends the same N4 requests, our UPF answers (CHOOSE F-TEIDs, Created PDR, usage report), and the ping goes through our GTP-U datapath and TUN device.",
                        ["TS 29.244 7.5", "TS 29.281", "TS 38.415 5.5.2.1"], roles),
    ] + sbi_procedures()
    regress = regress_lines()
    loc = {"product": sum(f["code"] for d in list(NF_DIRS.values()) for dd in d for f in sources([dd], cov)) + sum(f["code"] for fs in libs.values() for f in fs)}
    data = {
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "nodes": [dict(zip(("id", "label", "kind", "x", "y", "phase", "status", "role", "spec"), n)) for n in NODES],
        "edges": [dict(zip(("id", "a", "b", "label", "protocol", "spec", "state", "evidence"), e)) for e in EDGES],
        "nfDetail": nf_detail, "libs": libs, "walkthroughs": WALKTHROUGHS, "procedures": procedures,
        "matrix": matrix, "tests": tests, "coverage": cov, "regress": regress, "findings": [dict(zip(("date", "area", "severity", "what", "fix", "test"), f)) for f in FINDINGS],
        "phases": phases, "decisions": OPEN_DECISIONS, "decided": DECIDED, "adrs": adrs(), "board": board, "log": entries[:12], "loc": loc,
    }
    (OUT / "data.json").write_text(json.dumps(data, separators=(",", ":")), encoding="utf8")
    tpl = ROOT / "tools" / "dashboard" / "template.html"
    if tpl.exists():
        html = rd(tpl).replace("/*__DATA__*/null", json.dumps(data, separators=(",", ":")).replace("</", "<\\/"))
        (OUT / "index.html").write_text(html, encoding="utf8")
    print("data.json %.0f KB; %d procedures (%s); %d routes; %d files; coverage %s" % (
        (OUT / "data.json").stat().st_size / 1024, len(procedures), ", ".join("%d steps" % len(p["steps"]) for p in procedures),
        sum(len(v["routes"]) for v in nf_detail.values()), sum(len(v["files"]) for v in nf_detail.values()),
        (cov.get("total") or {}).get("hit")))


if __name__ == "__main__":
    main()
