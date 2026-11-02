#!/usr/bin/env python3
"""Writes docs/conformance/phase8-matrix.json (Phase 8: production hardening). The matrix is data; tools/check/check_matrix.py validates every reference in it.
Rows are added here as the work packages of Phase 8 (docs/adr/0025-phase8-plan.md) are built.

    python3 tools/gen/gen_phase8_matrix.py"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
B = ("bad_configs_rejected", "tests/conformance/check_bad_configs.sh", "-")
CL = ("cluster_load", "deploy/run/g5c-cluster.sh", "-")
CC = ("cluster_chaos", "deploy/run/g5c-cluster.sh", "-")
CS = ("cluster_soak", "deploy/run/g5c-cluster.sh", "-")
ORACLE = ("sbi_oracle_interop", "tests/conformance/CMakeLists.txt", "-")
OAT = "nf/nrf/tests/test_oauth2.c"
OA = lambda fn: ("nrf_oauth2", OAT, fn)

rows = []


def row(rid, nf, proc, spec, clause, status, tests, evidence, also=None):
    r = {"id": rid, "phase": 8, "nf": nf, "procedure": proc, "spec": spec, "clause": clause}
    if also:
        r["also"] = also
    r["status"] = status
    r["tests"] = [{"ctest": c, "file": f, "fn": fn} for (c, f, fn) in tests]
    r["evidence"] = evidence
    rows.append(r)


OA_ORACLE = ("Oracle S4, S7 and S8 with every function ours (OUR_OAUTH2=1): every request between the functions that is for a service carries the access token of the NRF and every "
             "function refuses one without.")

row("SEC-OA-01", "all", "producer side: a request for a service of the function needs a bearer token that the NRF signed; the signature is checked against the NRF's key set (/oauth2/jwks), "
    "fetched on first use and again when the key id is unknown or the set is old (never more than every two seconds); no token, a damaged one, one with another algorithm (alg none), "
    "another key or another payload are 401 with WWW-Authenticate; when the NRF cannot be reached and no key is held, 503", "TS 33.501", "13.4.1.1.2", "tested",
    [OA("test_guard_and_tokens"), OA("test_refused_and_unreachable")], OA_ORACLE)
row("SEC-OA-02", "all", "the claims: exp (a token is not accepted on or after it, with the configured leeway), iat and nbf not in the future, a subject; the audience is the function's NF type or its "
    "instance id (a string or a list); the scope holds the service the request is for; wrong audience or scope is 403 with the error of RFC 6750", "TS 33.501", "13.4.1.1.2", "tested",
    [OA("test_guard_and_tokens")], "", also=["13.4.1.1.1"])
row("SEC-OA-03", "all", "what the check applies to: the requests for the services the function registers (the first path segment); health, metrics, callbacks, the admin and northbound "
    "APIs are not services of the NRF's token and are left to their own handling; a route that authenticates its callers itself (G5C_ROUTE_OWN_AUTH: the UDR's provisioning extensions) is "
    "left alone; the guard the function had before still runs for what passes", "TS 33.501", "13.4.1.1.2", "tested", [OA("test_guard_and_tokens")], "")
row("SEC-OA-04", "all", "consumer side: the SBI client of every function gets a token from the NRF (client credentials; the instance id, the NF type, the target type and the service as the scope) "
    "for a request to a service of another function and sends it; one request for a token per service, kept until shortly before it expires (exp is truncated to a second, so a second is "
    "taken off and the token is renewed at 80% of the rest), one request at a time per service; a refusal is remembered for 2 s; an Authorization header that is there is not replaced", "TS 33.501",
    "13.4.1.1.2", "tested", [OA("test_guard_and_tokens"), OA("test_refused_and_unreachable")], "", also=["13.4.1.1.1"])
row("SEC-OA-05", "all", "the services of the NRF itself take a token as well when the consumer is configured to ask for one (optional, TS 33.501 13.3.1.3): discovery and subscriptions yes, "
    "the registration, heart-beat and deregistration of an instance no (the NRF lets them in)", "TS 33.501", "13.3.1.3", "tested", [OA("test_guard_and_tokens")], "")
row("SEC-OA-06", "all", "configuration (common section `oauth2: { enforce, acquire, leeway_s, jwks_refresh_s }`, needs `nrf.uri`): every wrong value is refused at start with the key that is wrong", "TS 33.501",
    "13.4.1", "verified", [OA("test_config"), B], "5 bad configurations per function are rejected by the binaries (11 functions).")
row("SEC-OA-07", "all", "the cluster enforces and acquires by default (G5C_OAUTH2=1): every function requires the token and asks for one; load, chaos and soak runs pass through it", "TS 33.501",
    "13.4.1", "tested", [CL, CC, CS], "")
row("SEC-OA-08", "all", "the oracle with every function ours (OUR_OAUTH2=1) passes the registration, PDU session, policy push, AS session with QoS and the BSF binding scenarios", "TS 33.501", "13.4.1",
    "tested", [ORACLE], OA_ORACLE + " Open5GS's functions send no tokens and check none, so they are not in these runs.")
row("SEC-OA-09", "UDR", "the provisioning token of the UDR's extension routes travels in its own header (x-g5c-provisioning-token; the bearer form is still accepted) so that Authorization is free for "
    "the NRF's token on the same requests", "TS 33.501", "13.4.1", "tested", [CL], "")
TLS_SBI = ("sbi_router_h2_tls", "libs/sbi/tests/test_sbi.c", "test_tls")
TLS_NEG = ("sbi_router_h2_tls", "libs/sbi/tests/test_sbi.c", "test_tls_negative")
TLS_ROT = ("sbi_router_h2_tls", "libs/sbi/tests/test_sbi.c", "test_tls_rotation")
CTLS = ("cluster_tls", "deploy/run/g5c-cluster.sh", "do_tls")
CLTLS = ("cluster_load_tls", "deploy/run/g5c-cluster.sh", "-")
CSEC = ("cluster_secrets", "deploy/run/g5c-cluster.sh", "do_secrets")
OPS = ("ops_files_check", "tools/check/check_ops.py", "-")
NSSF_T = ("cluster_load", "deploy/run/g5c-cluster.sh", "-")

row("SEC-TLS-01", "all", "every SBI listener is TLS 1.2 or later with ALPN h2 and demands a client certificate signed by the cluster CA (mutual TLS); every outgoing request validates the server "
    "certificate against the CA (by IP address SAN or name) and presents the function's own certificate", "TS 33.501", "13.1", "tested", [TLS_SBI, TLS_NEG, CLTLS],
    "libs/sbi test: a client trusting the CA works, one trusting another CA fails, a client without a certificate and one with a certificate of another CA are refused, a server certificate "
    "for another name is refused. The cluster runs 2000 UEs with TLS on every function (every function, the UPF's listener included).", also=["13.3.2.1"])
row("SEC-TLS-02", "all", "a cluster PKI (deploy/run/g5c-pki.sh): a CA, one certificate per function (EC P-256, SANs of its addresses, server and client authentication), one for the operator; "
    "the cluster script makes it and writes https URIs and `sbi.tls` into every configuration (G5C_TLS=1; the demo launcher does by default)", "TS 33.501", "13.1", "tested", [CTLS, CLTLS], "")
row("SEC-TLS-03", "all", "refusals: a cleartext request to a TLS listener, a request without a client certificate, with a certificate of another CA, and a client that trusts another CA are all "
    "refused by a running cluster; the request with the cluster's certificate is served; no function warns about missing TLS", "TS 33.501", "13.3.2.1", "tested", [CTLS], "")
row("SEC-TLS-04", "all", "certificate rotation without a restart: SIGHUP makes every function read its certificate, key and CA again and use them for new connections as server and as client "
    "(server and client contexts are swapped under a lock, connections in progress keep theirs); a damaged or mismatching file is refused and the old certificates stay in use; all twelve "
    "listeners (the UPF's included) log the reload; traffic works through the rotated certificates", "TS 33.501", "13.1", "tested", [TLS_ROT, CTLS],
    "ASan and TSan runs pass the library test and the cluster test (the cluster runs the sanitized binaries).")
row("SEC-TLS-05", "all", "chaos under mutual TLS: functions killed with SIGKILL and restarted under load recover and a clean wave passes", "TS 33.501", "13.1", "tested",
    [("cluster_chaos_tls", "deploy/run/g5c-cluster.sh", "-")], "ctest cluster_chaos_tls (the chaos mode with G5C_TLS=1), also run by scripts/g5c_regress.sh with 200 UEs.")
row("SEC-SEC-01", "all", "secrets hygiene: no master key, home network key, admin or provisioning token, AF token by value in a log, a configuration or a state file; K and OPc not in the clear "
    "in any state file; key files and PKI private keys mode 600; configurations name files, never key values", "TS 33.501", "5.2.4", "tested", [CSEC], "")
row("OPS-01", "all", "Prometheus alert rules (availability, security, service, capacity), recording rules, scrape configuration with the cluster's client certificate, and a Grafana dashboard: "
    "every metric they use is registered by a function (checked against the sources)", "-", "-", "tested", [OPS], "deploy/ops/*; runbooks per alert in docs/ops/runbooks.md.")
row("OPS-02", "UDM / PCF", "audit log of provisioning and policy changes (tag g5c_audit: subscriber provisioned / deleted, policy put / deleted, session terminated)", "-", "-", "verified",
    [CSEC], "The lines are written by the admin handlers; the secrets check shows they carry no key.")
row("NSSF-C-01", "AMF", "the AMF as a consumer of Nnssf_NSSelection (registration): the subscribed and requested S-NSSAIs and the tracking area go to the NSSF (found through the NRF or "
    "`amf.nssf.uri`); the allowed NSSAI of the Registration Accept and the rejected S-NSSAIs come from its answer, cut to what the AMF serves; 403 (nothing available) rejects the "
    "registration with cause #62; no answer falls back to the AMF's own lists", "TS 29.531", "5.2.2.2.2", "tested", [NSSF_T],
    "The cluster load (every UE registers through the NSSF) shows g5c_amf_nssf_selections_total{result=ok}; the unit and end-to-end tests of the AMF still run with its own lists.", also=["TS 23.502 4.2.2.2.3"])
row("NSSF-C-GAP", "AMF", "not done: using the NSI information of the answer to pick the SMF / NRF of the slice, the AMF re-allocation (target AMF set), the NSSAI availability "
    "(Nnssf_NSSAIAvailability) updates from the AMF, and a scenario with two slices end to end through a UE (per-slice SMF and UPF selection)", "TS 29.531", "5.2.2.2", "gap", [], "")
CLUS = "deploy/run/g5c-cluster.sh"
SMFE = "nf/smf/tests/test_smf_e2e.c"
row("CHG-01", "SMF / UPF", "charging data records: the SMF installs a usage reporting rule (Create URR: volume and duration measurement) with the session when `smf.cdr.file` is set, refers to it from the session's "
    "PDRs, reads the Usage Report of the Session Deletion Response (Volume Measurement octets and packets, Duration) and writes one JSON record per released PDU session (SUPI, PDU session id, DNN, S-NSSAI, "
    "UE address, UPF, start, end, duration, octets and packets up and down, close cause, sequence number); a session whose UPF could not report still gets a record with `usageReported: false`",
    "TS 29.244", "5.2.2", "tested", [("smf_e2e", SMFE, "test_happy_path"), ("cluster_ops", CLUS, "do_ops")],
    "The e2e test checks the record of a session that sent 60 octets; `ns ops` checks 10 records after a load; the host demo run prints the record of the 5 pings (468 octets up, 420 down).", also=["7.5.2.4", "7.5.7.2"])
row("CHG-GAP", "SMF", "not done: Nchf (Converged Charging) client and online charging, CDR rotation / transfer (the file is opened for every record so a rename rotates it), interim records by time or volume "
    "threshold, per-flow (rating group) records", "TS 32.255", "-", "gap", [], "")
row("NSSF-C-02", "AMF", "the AMF consults the NSSF for every PDU session establishment (slice-info-request-for-pdu-session with the S-NSSAI and the tracking area): 403 stops the session "
    "(5GMM cause #90), no answer lets it continue; the NSSF's registration decision (slice 1 allowed, slice 2 rejected) and PDU session decisions (slice 1 accepted, slice 2 refused) are checked on the real cluster",
    "TS 29.531", "5.2.2.2.3", "tested", [("cluster_slices", CLUS, "do_slices")], "")
row("OPS-03", "all", "run-time operations: SIGUSR1 raises the log level of a running function to debug and SIGUSR2 restores it (no restart); the release version is in the first log line and in `g5c_build_info`; "
    "a secret may be read from the output of a command (`exec:<absolute path> args`, no shell, 10 s, exit 0)", "-", "-", "tested", [("cluster_ops", CLUS, "do_ops")], "")
row("SEC-KEY-01", "UDM", "rotation of the master key that protects K and OPc: current and previous key, the credentials stored under the previous key still open, `POST /admin/v1/keys/rewrap` protects them under "
    "the current key, then the previous key is removed; a wrong key does not open the credentials", "TS 33.501", "6.1.3", "tested", [("cluster_ops", CLUS, "do_ops")], "")
row("OPS-04", "all", "upgrade and rollback under load: every function stopped gracefully and started again one at a time with the same binaries (upgrade) and then with a copy of the previous binaries "
    "(rollback) while UEs register and de-register; a clean wave with new subscribers passes at the end", "-", "-", "tested", [("cluster_upgrade", CLUS, "do_upgrade")], "")
row("OPS-05", "all", "service level objectives with gates: control-plane throughput of at least 50 UE/s and p99 of registration (1 s), PDU session (0.5 s) and de-registration (0.5 s) on the cluster load logs; "
    "UPF one-core forwarding gate; authentication vector rate gate; flat memory", "-", "-", "tested", [("cluster_load", CLUS, "-")], "docs/ops/slo.md; `tools/check/check_slo.py` runs on the 2000-UE logs in scripts/g5c_regress.sh. The 10 to 100 Gbit/s UPF target is not measured (needs a NIC).")
row("OPS-GAP", "all", "not done: shared-state high availability (AMF / SMF contexts in an external store, N4 failover to a second UPF, SCTP multi-homing), horizontal autoscaling, a Kubernetes operator, Helm "
    "chart, configuration hot reload other than certificates and the log level; the container image and the Kubernetes manifests are written but were never built or applied (no runtime available)", "-", "-", "gap", [], "")
row("SUP-01", "all", "support tooling: a diagnostics bundle (versions, host, processes, metrics of every function, configurations, last log lines, certificate expiry, audit lines) with IMSI / SUPI, MSISDN, IMEI, GUTI, "
    "tokens, keys and addresses redacted, and no key file or state file in it; a capture helper with the filters of N2, N3, N4 and the SBI; a redaction filter", "-", "-", "tested",
    [("cluster_support", CLUS, "do_support"), ("redact_tool", "tests/support/test_redact.py", "main")], "The bundle is searched for the subscribers of the load run, every key and token of the cluster, K and OPc of a provisioned subscriber.")
row("REL-01", "release", "release engineering: one VERSION compiled into every binary, signed archives with checksums (GnuPG detached signatures), a source archive, an SBOM of all functions, the automated licence audit "
    "(SPDX identifiers, no copyleft or foreign copyright in product files, SBOM and THIRD_PARTY agree, test-only tools not in build files) with NOTICE, the API reference generated from the sources and checked for "
    "drift, systemd units and an installer tested into a staging root", "-", "-", "tested", [("licence_audit", "tools/release/licence_audit.py", "main"), ("api_docs_fresh", "tools/docs/gen_api_docs.py", "main")],
    "`tools/release/release.sh` runs the gates, builds the archives, verifies checksums and signatures and installs the archive into a staging root.")
row("REL-GAP", "release", "not done and not possible here: counsel's sign-off of the licence audit and the patent / FRAND review (recorded for counsel), a scan of the SBOM against a vulnerability database (no scanner "
    "installed), signing with the offline release key (the candidate is signed with a test key), a container image build and scan, a pilot with a partner, the external penetration test, the 7 day soak", "-", "-", "gap", [], "")
row("SEC-GAP-02", "all", "not done: the CA key on a production cluster (an HSM or an offline CA), certificate revocation (CRL, OCSP), rotation of the AUSF's master key and a key id in the stored ciphertext (the UDM rotates with a previous key), client credentials assertions (13.3.8), additional scope (resources and operations) in the token, NSSAI / NSI / NF set claims checked by the producer, "
    "roaming PLMN checks (13.4.1.2), the SCP obtaining tokens for delegated discovery (TS 29.500 6.10.11), revocation, a key set with more than one key (the NRF publishes one)",
    "TS 33.501", "13.4.1", "gap", [], "")

doc = {
    "title": "Conformance matrix, Phase 8 (production hardening): security",
    "note": "Same rules as the other matrices. The functions that take part in the tested rows are ours on both sides: Open5GS's functions send and check no access tokens.",
    "specs": {"TS 33.501": "33501-gk0.txt"},
    "rows": rows,
}
(ROOT / "docs" / "conformance" / "phase8-matrix.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf8")
print("wrote %d rows" % len(rows))
