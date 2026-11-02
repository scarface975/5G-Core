#!/usr/bin/env python3
"""Writes docs/conformance/phase6-matrix.json (Phase 6: integration and validation of the five-function core as a system). The matrix is data;
tools/check/check_matrix.py validates every reference in it.

    python3 tools/gen/gen_phase6_matrix.py"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

CL = ("cluster_load", "deploy/run/g5c-cluster.sh", "-")
CC = ("cluster_chaos", "deploy/run/g5c-cluster.sh", "-")
CS = ("cluster_soak", "deploy/run/g5c-cluster.sh", "-")
LC = ("load_core_small", "nf/amf/tests/load_core.c", "main")
AE = ("amf_e2e", "nf/amf/tests/test_amf_e2e.c")
SE = ("smf_e2e", "nf/smf/tests/test_smf_e2e.c")
SK = ("soak_core", "tests/soak/soak_core.c", "main")
UD = ("udr_patch_store_routes", "nf/udr/tests/test_udr.c", "test_journal_recovery")

rows = []


def row(rid, nf, proc, spec, clause, status, tests, evidence, also=None):
    r = {"id": rid, "phase": 6, "nf": nf, "procedure": proc, "spec": spec, "clause": clause}
    if also:
        r["also"] = also
    r["status"] = status
    r["tests"] = [{"ctest": c, "file": f, "fn": fn} for (c, f, fn) in tests]
    r["evidence"] = evidence
    rows.append(r)


# ---- the scenarios, on the system -------------------------------------------------------------------------------------------------------
row("P6-SYS-01", "System", "S1: initial registration with 5G-AKA, security mode, GUTI allocation, then UE-initiated de-registration; every function a separate process "
    "(udr, UDM, AUSF-lite, PCF, UPF, SMF, AMF), a scripted gNB over real SCTP and a scripted UE that derives every key itself",
    "TS 23.502", "4.2.2.2.2", "tested", [CL, AE + ("test_registration",)],
    "deploy/run/g5c-cluster.sh ns load: every UE completes and the UE-context, SMF-session and UPF-session counts read from /metrics return to their starting "
    "values. UERANSIM does the same against our AMF with Open5GS's AUSF / NRF (oracle S1-S3).", also=["4.2.2.3.2"])
row("P6-SYS-02", "System", "S2: S1 plus UE-requested PDU session establishment, user plane through the UPF (N3 GTP-U to N6) and release at de-registration",
    "TS 23.502", "4.3.2.2.1", "verified", [CL, AE + ("test_sessions",)],
    "UERANSIM's UE pings through our UPF with our AMF, SMF, UDM and PCF (oracle S2, 0% loss); the scripted gNB and UE do the same with checked tunnel "
    "identifiers and addresses.")
row("P6-SYS-03", "System", "S3: S2 plus UE-requested PDU session release and re-registration with the 5G-GUTI", "TS 23.502", "4.3.4.2", "verified",
    [CL, AE + ("test_sessions",), AE + ("test_context_reuse",)], "Oracle S3 with every function ours except the AUSF and NRF (Open5GS's).")
row("P6-SYS-04", "System", "S4: policy change while the session is up: PCF update -> SMF -> N4 modification -> NAS modification command -> N2 modify request",
    "TS 23.502", "4.3.3.2", "verified", [AE + ("test_sessions",), SE + ("test_policy_update",)],
    "Oracle S4 against our AMF, SMF, UPF, UDM and PCF; UERANSIM's gNB does not answer a modify request, so the NGAP request in the capture is the "
    "evidence there and the scripted gNB completes the procedure.")
row("P6-SYS-05", "System", "S5: connection release (inactivity), the UE returns with a service request, user plane resumes; network-triggered paging for downlink data",
    "TS 23.502", "4.2.3.2", "verified", [AE + ("test_idle_service_paging",)],
    "Oracle S5 (nr-cli ue-release, then ping); paging, its repetition and its failure with the scripted gNB.", also=["4.2.3.3"])

# ---- scale -----------------------------------------------------------------------------------------------------------------------------
row("P6-SCALE-01", "System", "100 / 1,000 / 10,000 simulated UEs, each registering with 5G-AKA and establishing a PDU session, then de-registering; the functions "
    "in one process on real sockets (load_core)", "TS 23.502", "4.2.2.2.2", "tested", [LC],
    "10,000 UEs over 32 gNBs: all registered with a session in 71 s, de-registered in 17 s, latency p50 9 ms / 195 ms (registration / session), no "
    "descriptor leak, AMF, SMF and UPF empty at the end. Run with G5C_LOAD_UES=10000; ctest runs 150.")
row("P6-SCALE-02", "System", "the same load against the daemons as separate processes in a private network namespace (deploy/run/g5c-cluster.sh ns load)",
    "TS 23.502", "4.2.2.2.2", "tested", [CL],
    "10,000 UEs over 32 gNBs: registered with a session each in 20.7 s (484 UE/s), de-registered in 9.8 s; latency p50 38 ms / 25 ms / 29 ms "
    "(registration / session / de-registration), flat as the population grows. ctest runs 300 UEs x 2 waves.")
row("P6-SCALE-03", "AMF", "the unauthenticated-connection limit counts only connections that have not completed authentication", "TS 38.413", "8.6.1", "tested",
    [LC, AE + ("test_registration",)],
    "Found by the first load run: the limit counted every connection, so an AMF refused new UEs with an overload Error Indication once 4,096 UEs were "
    "connected.")

# ---- failure injection -------------------------------------------------------------------------------------------------------------------
row("P6-FAIL-01", "System", "network functions killed (SIGKILL) and restarted at random while the load runs; afterwards a clean wave of new UEs must pass in "
    "every detail", "TS 23.502", "4.2.2.2.2", "tested", [CC],
    "30 s of load with 16 kills (UPF, SMF, AMF, UDM, PCF, AUSF, UDR): 8,762 UE cycles completed, the rest counted as failures, no hang; the recovery wave "
    "of 100 UEs passes.")
row("P6-FAIL-02", "SMF", "SMF restart: sessions come back from the state file, the UPF association is re-established with the same Recovery Time Stamp",
    "TS 29.244", "6.2.6", "tested", [SE + ("test_persistence",), CC],
    "In-process test with the real PFCP sockets; the chaos run restarts the SMF as a process.")
row("P6-FAIL-02b", "SMF", "UPF restart detected through the Recovery Time Stamp: sessions released towards the AMF and the N4 association set up again", "TS 29.244", "6.2.6",
    "tested", [SE + ("test_upf_outage",), CC], "Found by the chaos run: the association was not re-established, so the UPF refused new sessions (cause 72).")
row("P6-FAIL-03", "AMF", "AMF restart: registered UEs come back CM-IDLE with their security context and are served by a service request",
    "TS 23.502", "4.2.3.2", "tested", [AE + ("test_persistence",)], "In-process test; the chaos run restarts the AMF as a process.")
row("P6-FAIL-04", "AMF", "loss of the N2 association: UE contexts of that gNB go CM-IDLE, sessions are kept", "TS 38.413", "8.7.4.2.2", "tested",
    [AE + ("test_association_loss",)], "Scripted gNB closes its SCTP association.")
row("P6-FAIL-05", "UDR", "UDR outage and restart under UDM / PCF load: a clean 503 while it is down, the first request after it is back succeeds, no leaked "
    "state", "TS 29.504", "-", "tested", [SK], "soak_core stops and restarts the UDR repeatedly under a mixed workload (also under ASan and TSan).")
row("P6-FAIL-06", "UDR", "subscriber store persistence is a snapshot plus a journal of changed subscribers: a crash image recovers every flushed change, "
    "removals included, and a journal older than its snapshot is not replayed", "TS 29.505", "-", "tested", [UD],
    "test_journal_recovery copies the files of a running store (what a crash leaves) and reopens them.")

# ---- soak and memory --------------------------------------------------------------------------------------------------------------------
row("P6-SOAK-01", "System", "waves of register / session / de-register for a fixed time against the daemons; RSS of every function must stay flat between the "
    "second and the last wave", "TS 23.502", "4.2.2.2.2", "tested", [CS],
    "ns soak 500 UEs for 90 s (30 waves): no function grows beyond the tolerance; ctest runs 30 s. The strategy's 72 hour run uses the same command "
    "(`ns soak 500 259200`).")
row("P6-SOAK-02", "System", "memory and descriptor leaks: the load run under ASan/UBSan (leak check at exit) and the chaos run", "TS 23.502", "-", "tested",
    [LC, CC], "load_core under AddressSanitizer reports nothing at exit; descriptors return to their starting count (+ the bounded SBI connection pool).")

# ---- what the phase leaves open -----------------------------------------------------------------------------------------------------------
row("P6-GAP-01", "System", "72 hour soak", "TS 23.502", "-", "gap", [],
    "The harness exists and ran for minutes in this environment; the 72 hour run needs a host that can be left alone for three days (`ns soak 500 259200`).")
row("P6-GAP-02", "System", "S1-S8 on srsRAN (ZMQ gNB / UE) and an O-RAN emulator", "TS 38.413", "-", "gap", [],
    "Deferred by the owner until all eleven functions exist; the interop pass with srsUE and the OCUDU gNB is planned for that point together with the demo "
    "environment.")
row("P6-GAP-03", "System", "scripted UEs do not run user-plane traffic at scale (control plane and session setup only)", "TS 29.281", "-", "gap", [],
    "UPF throughput is measured by its own benchmark (about 3.2 Gbit/s uplink, 1.8 Gbit/s downlink per core); a combined signalling + traffic run needs a "
    "traffic generator inside the namespace.")
row("P6-GAP-04", "SMF", "an SMF killed within the write-behind window of its state file leaves PFCP sessions on the UPF that the restarted SMF does not know",
    "TS 29.244", "6.2.6", "gap", [],
    "The window is 25 ms or ten times the cost of a write. A graceful stop flushes. Closing it needs an N4 session audit (a Recovery Time Stamp change is "
    "not usable because the SMF keeps the stamp to keep its sessions).")

doc = {
    "title": "Conformance matrix, Phase 6 (the five-function core as a system: scenarios, scale, failure injection, soak)",
    "note": "Same rules as the other matrices. 'verified' = tests pass and a real independent peer (UERANSIM, Open5GS's AUSF / NRF) confirms it. "
            "The system rows are run by deploy/run/g5c-cluster.sh (real processes) and nf/amf/tests/load_core.c; the gap rows are what the phase leaves out.",
    "specs": {
        "TS 23.502": "23502-gj0.txt",
        "TS 38.413": "38413-gi0.txt",
        "TS 29.244": "29244-gd0.txt",
        "TS 29.281": "29281-g20.txt",
        "TS 29.504": "29504-ge0.txt",
        "TS 29.505": "29505-gc0.txt",
    },
    "rows": rows,
}
(ROOT / "docs" / "conformance" / "phase6-matrix.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf8")
print("wrote %d rows" % len(rows))
