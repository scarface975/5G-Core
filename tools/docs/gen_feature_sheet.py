#!/usr/bin/env python3
"""Writes docs/strategy/Feature_Opportunities.xlsx: what we can add to the g5c core, set against what Open5GS, free5GC and the commercial 5G test and core products offer.
   python tools/docs/gen_feature_sheet.py
Peer information is taken from public product pages and descriptions (see docs/strategy/3GPP_Release_and_Vendor_Comparison.xlsx, 'Vendor Comparison') and general knowledge;
every peer cell is indicative and marked for verification where it is not documented."""
from pathlib import Path

from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule, FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "docs" / "strategy" / "Feature_Opportunities.xlsx"

NAVY, TEAL, GREY, LIGHT = "1F3A5F", "2A7F8E", "F2F4F7", "E8F1F4"
thin = Side(style="thin", color="C9D1D9")
BORDER = Border(left=thin, right=thin, top=thin, bottom=thin)
HDR_FONT = Font(bold=True, color="FFFFFF", name="Calibri", size=11)
HDR_FILL = PatternFill("solid", fgColor=NAVY)
WRAP = Alignment(wrap_text=True, vertical="top")
CENTER = Alignment(horizontal="center", vertical="center", wrap_text=True)

PEERS = ["Open5GS", "free5GC", "Spirent Landslide", "Amarisoft Callbox / UE Simbox", "Artiza DuoSIM-5G", "Valid8 UE Tester / core emulators", "Viavi TM500", "Accuver XCAL",
         "Polaris Networks (core and test products)", "Mobileum (roaming, analytics, signalling security)"]
PEER_KEY = {"O": "Open5GS", "F": "free5GC", "L": "Spirent Landslide", "A": "Amarisoft", "D": "Artiza DuoSIM", "V": "Valid8", "T": "Viavi TM500", "X": "Accuver XCAL",
            "P": "Polaris Networks", "M": "Mobileum"}
# peers added after the backlog was first written: feature id -> extra letters (public descriptions only)
PEER_ADD = {"A-01": "M", "A-06": "M", "A-07": "P", "B-01": "P", "B-02": "P", "B-06": "PM", "C-01": "PM", "C-05": "M", "I-01": "P"}

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# What we have in place (the foundations the feasibility ratings lean on)
FOUNDATIONS = [
    ("F-SBI", "SBI library (libs/sbi)", "HTTP/2 server and client over libuv + nghttp2, router with route flags, TLS / mutual TLS with live certificate swap, OAuth2 token provider (consumer) and guard (producer), SCP-aware client, multipart", "Every new service or API is a router registration plus handlers; TLS, tokens, metrics and indirect communication come with it"),
    ("F-NF", "Twelve network functions", "AMF, SMF, UPF, PCF, UDM, UDR, AUSF, NRF, NSSF, NEF, SCP, BSF as separate daemons with discovery, registration, heart-beat, state files, metrics, health", "A new function copies the nfcore runtime (config, logging, NRF registration, SIGHUP / SIGUSR handling) and is running in days of plumbing"),
    ("F-UDR", "UDR with generated API (176 operations)", "Table-driven from the pinned OpenAPI files, PostgreSQL / journalled file / memory, subscriptions and notifications, schema validator in C", "Any new data type (policy data, application data, exposure data) is data in the UDR, not new storage code"),
    ("F-CODEC", "Protocol codecs", "Generic APER interpreter for NGAP (138 golden PDUs byte-exact), NAS table-driven codec (48 messages, security envelope), PFCP IEs and groups, GTP-U, JSON DOM", "Encode / decode / mutate any signalling message: the base of a tester, a fuzzer and a trace decoder"),
    ("F-LOAD", "Load generator (load_core)", "Scripted gNBs and UEs against real daemons: registration, PDU sessions, de-registration, latency histograms, descriptor / memory checks, remote mode", "A starting point for a scenario engine; it already drives N2 and the SBI with thousands of UEs"),
    ("F-CLUSTER", "Cluster harness (g5c-cluster.sh)", "One command brings up 12 daemons in a private namespace; modes: load, chaos, soak, tls, ops, slices, upgrade, support; per-function logs and RSS", "A scenario runner for system-level tests without privileges or hardware"),
    ("F-ORACLE", "Oracle and differential tools", "Open5GS + UERANSIM harness, S1 to S8 scenarios swapping in our functions one at a time, differential tools (PFCP, NRF, AUSF, NSSF, SCP, BSF) comparing behaviour on the wire", "A built-in interop and compatibility proof that others do not ship; reusable as a customer-facing 'compat report'"),
    ("F-MATRIX", "Conformance matrix", "387 rows: procedure, spec clause (verified against the pinned text), status, tests, evidence; `check_matrix.py` validates every reference", "Exportable compliance evidence per clause; the skeleton of a certification dashboard"),
    ("F-ATLAS", "Atlas dashboard", "Generated site: architecture, call flows, conformance matrix, test results, coverage, findings", "A live, shareable view for customers and auditors; can grow into a trace and KPI viewer"),
    ("F-OBS", "Observability", "Prometheus metrics on every function, alert rules, Grafana dashboard, structured audit log, runtime log level, diagnostics bundle, redaction filter, capture helper", "Operators get telemetry on day one; new KPIs are counters in the registry"),
    ("F-SEC", "Security stack", "mTLS between functions, NRF OAuth2 tokens enforced, secrets as files or commands, master-key rotation, SBOM, signed archives, threat model, fuzz replay under sanitizers", "A security story that testers and regulators can inspect; hooks for HSM, revocation, IPsec"),
    ("F-CDR", "Charging data records", "Usage reporting rule on the UPF, termination report, one JSON record per session (volumes, duration, cause)", "The event source for Nchf, billing mediation and usage-based policy"),
    ("F-CTL", "Admin APIs and CLI", "UDM admin API (subscribers, key rewrap), PCF admin API (policies, sessions), `g5c-ctl`, NEF northbound APIs (traffic influence, monitoring events, AS session with QoS)", "A web console, SDKs and a provisioning gateway are thin layers over these"),
    ("F-DEMO", "ZMQ demo kit", "One-command lab: our core + OCUDU gNB + srsUE over ZeroMQ, ping both directions, host and namespace harnesses, PDF guide", "A ready lab for training, trade-show demos and device-less interop"),
    ("F-REL", "Release tooling", "Versioned binaries, signed archives, SBOM, licence audit, NOTICE, systemd units, installer, guides, generated API reference", "Ready to package extra products (a tester edition, a lab appliance)"),
    ("F-UPF", "UPF engine", "PFCP rule engine (PDR, FAR, QER, URR, BAR), GTP-U, TUN N6, QER rate enforcement, usage reports, session reports, one-core gate of about 1.2 Gbit/s", "A clean seam to swap the data path for XDP / DPDK / SmartNIC without touching N4"),
]

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# The backlog: id, category, feature, what it is, peers that offer it (letters), evidence, where we are, foundation, what we can do better or new, audience, feasibility, effort, needs from outside, wave
# feasibility: High / Medium / Low;  effort: S / M / L / XL (relative size of a work package, no dates);  wave: 1 quick wins, 2 differentiators, 3 strategic, 4 market-led
B = []


def add(*row):
    B.append(row)


# --- A. Core network functions and features
add("A-01", "Core functions", "NWDAF (network data analytics)", "Collects data from NFs and the OAM and serves analytics (load, slice load, UE mobility, abnormal behaviour) over Nnwdaf", "L", "Landslide emulates it; commercial cores include it", "Not built", "F-NF (nfcore runtime), F-OBS (metrics), AMF / SMF event exposure (Namf_EventExposure exists), F-SBI",
    "Native analytics from the counters we already export; analytics served as ordinary SBI APIs and also as Prometheus series; start with slice load and registration anomaly analytics that feed the PCF and the NSSF", "Operators, vendors", "Medium", "L", "Pinned TS 29.520 / 23.288; a small data store", 3)
add("A-02", "Core functions", "CHF with Nchf converged charging", "Online / offline charging of PDU sessions over Nchf_ConvergedCharging; rating groups, quota grants", "F", "free5GC ships a CHF; commercial cores do", "CDR file from the SMF (usage reporting rule on the UPF)", "F-CDR, F-UPF (URR with thresholds already parsed), F-SBI, F-CTL",
    "Build the CHF on top of the CDR event source: quota grant by volume threshold URRs, CDR export (ASN.1-free JSON and 3GPP CDR), prepaid and postpaid in one model", "Operators, MVNOs", "High", "L", "Pinned TS 32.290 / 32.291 / 32.255", 2)
add("A-03", "Core functions", "Usage monitoring and spending limits (PCF / SMF)", "The PCF sets volume / time thresholds for the SMF, which reports and the PCF changes the policy (throttle, upsell)", "L", "Landslide tests it; commercial cores include it", "Usage rule and reports exist at the UPF; PCF side open", "F-UPF (thresholds, session reports), F-CDR, PCF SM policy",
    "Close the loop: threshold URR on the UPF, report to the SMF, update to the PCF, decision pushed back; the same machinery serves fair-use and prepaid", "Operators", "High", "M", "Pinned TS 29.512 UMC clauses", 1)
add("A-04", "Core functions", "UE policy (URSP) delivery", "The PCF delivers UE route selection policy through the AMF in a UE configuration update (UCU)", "L", "Landslide emulates; commercial cores include it", "Not built", "AMF NAS transport + config update (exists for GUTI), PCF Npcf_UEPolicyControl would be new, F-CODEC (NAS container)",
    "Slice / DNN steering per app for private networks and enterprise; admin API to author URSP rules", "Enterprise, operators", "Medium", "L", "TS 29.525, 24.501 annex D, 24.526", 3)
add("A-05", "Core functions", "Nudm_EventExposure and AMF event completion", "Subscriptions at the UDM for UE events (reachability, loss of connectivity, location), notified to NEF / AFs", "L", "Commercial cores include it", "NEF reaches the AMF directly; UDM service not built", "AMF Namf_EventExposure, NEF MonitoringEvent, UDM UECM (finds the serving AMF), F-SBI",
    "Complete the path NEF to UDM to AMF so third-party AFs see the standard architecture", "Operators, AF developers", "High", "M", "Pinned TS 29.503 EE clauses", 1)
add("A-06", "Core functions", "SEPP and roaming (N32)", "Security edge proxy between PLMNs: TLS or PRINS protection, topology hiding", "O", "Open5GS has a SEPP; commercial cores do", "Not built", "F-SBI (TLS, router), F-NF, OAuth2 / NRF inter-PLMN token gaps listed in the matrix",
    "A SEPP that reuses our TLS and token machinery; start with N32-c / N32-f TLS mode and add PRINS later; enables home-routed roaming tests", "Operators", "Medium", "L", "TS 29.573, 33.501 13.2; a second PLMN lab", 3)
add("A-07", "Core functions", "4G interworking (EPC, N26, S1)", "MME / SGW / PGW-C / HSS functions or an N26 bridge so 4G devices and 5G share the core", "O", "Open5GS has a full EPC; Amarisoft and Valid8 include one", "Not built (5G SA only)", "SMF / UPF already speak PFCP (combined SMF+PGW-C and UPF+PGW-U share the N4 code), UDM / UDR for HSS data",
    "Open the 4G installed base: a PGW-C inside the SMF and an S6a-less HSS facade over the UDM; one subscriber database for both generations", "Operators, labs", "Medium", "XL", "TS 23.401 / 29.274 / 29.272 pinned; an eNB for testing", 4)
add("A-08", "Core functions", "N3IWF / TNGF / W-AGF (non-3GPP access)", "Untrusted Wi-Fi and fixed-access devices register through IPsec to the 5G core", "F", "free5GC ships an N3IWF; commercial cores include it", "Not built", "AMF NGAP / NAS (N3IWF uses NGAP), F-SBI, F-CODEC",
    "Enterprise Wi-Fi and FWA onboarding; the AMF side is largely there, the IPsec / IKEv2 side is the work", "Enterprise, fixed-wireless", "Low", "XL", "IKEv2 / IPsec stack (a partner library), TS 23.502 4.12", 4)
add("A-09", "Core functions", "Network slice admission control and slice authentication (NSAC, NSSAA)", "Limits UEs / sessions per slice and authenticates access to a slice with an AAA server (EAP)", "L", "Landslide tests it; commercial cores include it", "NSSF selection built; admission and NSSAA open", "NSSF + AMF (slice flows built), AUSF EAP engine (EAP-AKA' exists), F-SBI",
    "Per-slice quotas with live counters; an AAA-S gateway (RADIUS / Diameter) for enterprise slices", "Enterprise, operators", "Medium", "M", "TS 23.502 4.2.9, 29.526, 29.531 update", 2)
add("A-10", "Core functions", "Edge: UL-CL / branching point, DNAI selection, local breakout", "Traffic steering to local data networks and edge application servers by DNAI and per-UE rules", "F", "free5GC supports UL-CL; commercial cores do", "Traffic influence through the NEF writes policy; SMF steering open", "NEF traffic influence (built), UDR TrafficInfluData, SMF multi-UPF config, F-UPF rule engine (multiple PDRs / FARs)",
    "Complete the chain from an AF request to a branching rule on a second UPF; the PFCP rule vocabulary is already in the UPF", "Enterprise, MEC", "Medium", "L", "TS 23.501 5.6.4, 23.548", 3)
add("A-11", "Core functions", "SMS over NAS (SMSF), emergency services, 5G-EIR", "Text over NAS, emergency registration / sessions, equipment identity checks", "L", "Landslide tests; commercial cores include them", "Not built (emergency rejected cleanly)", "AMF NAS handling, UDM / UDR for data, F-SBI",
    "Small functions with clear specs; 5G-EIR gives device blacklisting that private networks want", "Operators, enterprise", "Medium", "M", "TS 29.540, 29.511", 4)
add("A-12", "Core functions", "Location services (LMF / GMLC)", "UE positioning requests and location exposure", "L", "Landslide emulates; commercial cores include them", "Not built", "AMF N1 / N2 transport (NRPPa / LPP containers), NEF exposure",
    "Position exposure through the NEF for industrial and public-safety use", "Enterprise, public safety", "Low", "L", "TS 23.273, 29.572, 38.455", 4)
add("A-13", "Core functions", "Multi-PLMN, SNPN and private-network identities", "More than one PLMN or an SNPN in one core; NID / CAG access", "A", "Amarisoft and commercial cores", "Single PLMN per function", "Config model (plmn per function), NRF profile fields (plmnList), UDM",
    "Neutral-host and campus networks: one core serving several identities with per-identity slices and keys", "MVNO, neutral host, enterprise", "Medium", "L", "TS 23.501 5.30 (SNPN), 23.003", 3)
add("A-14", "Core functions", "RedCap, CIoT and power-saving features (eDRX, MICO, PSM)", "Core support for low-power devices: extended DRX, mobile-initiated-only mode, reachability handling", "A", "Amarisoft / Viavi list RedCap and IoT on the RAN side", "Not built (listed as gaps in the matrix)", "AMF timers and reachability (events exist), NAS codec supports the IEs",
    "Core support for IoT fleets, tested end to end with an IoT-capable UE emulator", "IoT, utilities", "High", "M", "TS 24.501 5.3.x, 23.501 5.31", 2)
add("A-15", "Core functions", "Multicast and broadcast services (MBS)", "5G MBS session management and delivery", "A", "Amarisoft UE Simbox MBS", "Not built", "SMF / UPF PFCP (multicast IEs exist in the spec), AMF NGAP",
    "Public-safety and media delivery trials", "Broadcasters, public safety", "Low", "XL", "TS 23.247, 29.532", 4)
add("A-16", "Core functions", "NTN-aware core (long delay, satellite access)", "Timers and procedures tuned for satellite links; location verification", "A", "Amarisoft / Viavi mention NTN", "Not built", "AMF / SMF timer configuration (already configurable), F-LOAD for delay injection",
    "A core profile that passes the satellite delay envelope; the load tool can add the delay", "Satellite operators", "Medium", "M", "TS 23.501 5.4.11, 38.300 NTN overview", 4)
add("A-17", "Core functions", "IMS / VoNR integration", "Core support for voice: IMS DNN, QoS flows for voice, PCF Rx / N5 for P-CSCF", "A", "Amarisoft includes IMS; Landslide tests voice", "N5 (policy authorization) built, no IMS", "PCF N5 and AS-session-with-QoS (built), SMF dedicated QoS flows (built), BSF",
    "A tested voice QoS path with a partner IMS (Kamailio / Open IMS), shipped as a lab recipe", "Operators, labs", "Medium", "L", "An IMS core (partner or open source), TS 23.228 / 29.514", 3)
add("A-18", "Core functions", "ATSSS (multi-access steering)", "Steering over 3GPP and non-3GPP access with MPTCP or ATSSS-LL", "L", "Landslide lists it", "Not built", "SMF / UPF rule engine, AMF multi-access NAS",
    "Needs non-3GPP access first; plan with A-08", "Enterprise, FWA", "Low", "XL", "TS 23.501 5.32, MPTCP proxy", 4)
add("A-19", "Core functions", "Lawful intercept (X1 / X2 / X3)", "Warrant-driven interception of signalling and content", "L", "Commercial cores include it", "Design written (docs/security/lawful-intercept-design.md)", "AMF / SMF event hooks, F-UPF duplication rules, separate LI function",
    "A ready design with the seams identified; build once a jurisdiction is chosen", "Operators (regulated markets)", "Medium", "XL", "Jurisdiction decision, ETSI TS 102 232 / 3GPP 33.126-128", 4)

# --- B. Test and emulation
add("B-01", "Test and emulation", "Scenario engine for scripted UEs and gNBs (a scenario language)", "Describe a test as steps (register, session, mobility, idle, failure) and run it against any core", "LADTVX", "Landslide, Amarisoft, DuoSIM, Valid8, TM500, XCAL all script UEs", "load_core runs fixed waves; the oracle has S1 to S8 scripts", "F-LOAD (gNB / UE state machines over N2 and N1), F-CODEC, F-CLUSTER",
    "A small declarative scenario format (YAML) with assertions on messages and timers, shareable and diff-able; scenarios double as regression tests and as customer demos", "Vendors, labs", "High", "M", "None", 1)
add("B-02", "Test and emulation", "User-plane traffic profiles (TCP / UDP flows, QoS validation)", "Generate per-UE traffic with rates, packet sizes, QoS flows and measure loss, latency, jitter, throughput", "LADTVX", "All testers generate user plane", "Pings in the demo; load_core is control plane", "F-UPF (GTP-U, QER rate enforcement), F-LOAD, F-CODEC (GTP-U)",
    "UE emulator side GTP-U generators measured against UPF QERs; verify GBR / AMBR enforcement numerically and publish the result in the matrix", "Vendors, labs, operators", "High", "M", "None", 1)
add("B-03", "Test and emulation", "Million-subscriber scale emulation", "Emulate very large populations of UEs against a core under test", "LTX", "Landslide, TM500, XCAL-MUbox (1,000+ UEs per chassis)", "10,000 UEs with sessions in 20.7 s through real daemons", "F-LOAD (remote mode), F-CLUSTER; multi-process emulator fan-out",
    "Scale the emulator with processes and hosts, keep per-UE memory small; show a published scaling curve against our own core and against Open5GS", "Vendors, operators", "High", "L", "Several hosts for the large runs", 2)
add("B-04", "Test and emulation", "Core-emulator mode for gNB / RAN vendors (scriptable AMF and UPF personality)", "A core whose behaviour can be scripted: reject causes, delays, timer expiry, NGAP errors, selective session failures, so a RAN vendor tests error paths", "D", "Artiza DuoSIM sits on the RAN side; vendors build such cores by hand", "Real core, no failure scripting", "AMF / SMF / UPF with configuration, SIGUSR / admin hooks, F-CODEC, F-UPF",
    "Failure-injection knobs in the real functions (config or admin API: 'reject registration of SUPI X with #N', 'delay N2 responses 2 s', 'drop PFCP responses') so one product serves as a product core and as a RAN test partner", "RAN vendors, labs", "High", "M", "None", 1)
add("B-05", "Test and emulation", "Protocol fault injection and negative testing as a service", "Mutate NAS / NGAP / PFCP / SBI messages on the wire and check the core's reaction", "LV", "Landslide and Valid8 cover negative / conformance cases", "Fuzz replay with seeds under ASan / UBSan on every build", "F-CODEC (decode, mutate, re-encode), fuzz harness, F-CLUSTER (proxy between emulator and core)",
    "A mutation proxy that sits on N2 / N4 / SBI, driven by the conformance matrix ('for every mandatory IE: missing, wrong length, out of range'), producing a pass / fail table per clause", "Vendors, security teams", "High", "M", "None", 2)
add("B-06", "Test and emulation", "Automated conformance suites with spec mapping and reports", "Run test cases named after the standards (TS 38.5xx / 33.5xx / 24.501) and emit reports", "LV", "Landslide, Valid8", "Matrix of 387 rows linked to tests", "F-MATRIX, F-ATLAS, ctest labels, JUnit output",
    "Publish the matrix as a living compliance report (HTML, PDF, Excel, JUnit) that a customer can re-run against any core they own; ours first, then 'bring your own core'", "Vendors, auditors", "High", "M", "None", 1)
add("B-07", "Test and emulation", "Remote automation API (REST / WebSocket) for the emulator and the harness", "Control tests from CI or a notebook: start, stop, query counters, fetch traces", "LAV", "Landslide APIs, Amarisoft remote JSON API", "Shell scripts and admin APIs", "F-SBI (server, TLS, tokens), F-CTL, F-CLUSTER",
    "A tokened HTTP/2 + WebSocket API on the emulator and the cluster harness with an OpenAPI file, plus a Python SDK; same security stack as the core", "Labs, CI users", "High", "M", "None", 1)
add("B-08", "Test and emulation", "Network impairment between emulator and core (delay, loss, reorder)", "Shape the links of N2 / N3 / N4 / SBI to test timers and retransmissions", "LT", "Landslide / TM500 emulate impairments", "Chaos (kill and restart) exists; no link impairment", "F-CLUSTER (private network namespace: tc netem works there), UPF / SMF retransmission logic",
    "Scenario steps like 'add 200 ms delay on N4 for 10 s'; verifies T1 / N1 retransmissions and heart-beat logic automatically", "Vendors, operators", "High", "S", "tc / netem in the namespace", 1)
add("B-09", "Test and emulation", "Mobility scenario library (Xn, N2 handover, inter-AMF, idle reselection)", "Scripted mobility between cells and AMFs with expected message sequences", "LDT", "Landslide, DuoSIM, TM500", "Path switch and N2 handover implemented and tested in-process", "AMF / SMF handover procedures, F-LOAD gNB model",
    "Multi-gNB emulator scenarios on the real daemons; add inter-AMF handover when AMF sets exist", "Vendors, operators", "Medium", "M", "None (inter-AMF needs A-05-like AMF relocation work)", 2)
add("B-10", "Test and emulation", "Radio-level lab kit (virtual radio over ZeroMQ, OCUDU / srsRAN, optional SDR)", "A turnkey device-less lab: gNB + UE + core, optionally real RF with an SDR", "A", "Amarisoft Callbox is an RF product", "ZMQ demo kit, tested", "F-DEMO",
    "Package a 'lab in a box' (container or VM image, scripts, guides) that boots in minutes; add an SDR recipe for real handsets later", "Education, labs, vendors", "High", "M", "SDR hardware for the RF variant", 2)
add("B-11", "Test and emulation", "Replay of recorded traces (pcap to scenario)", "Turn a capture into a replayable scenario and compare responses with the recording", "L", "Landslide imports captures", "Golden pcaps stored for diffs; diff tools for PFCP", "F-CODEC, F-ORACLE (golden traces and differential tools)",
    "pcap in, scenario out: decode N2 / NAS from a capture, rebuild the UE / gNB script, replay against our core and report differences; a strong customer-support tool", "Support, vendors", "Medium", "M", "None", 2)
add("B-12", "Test and emulation", "Timing and timer conformance tests", "Check that every NAS / NGAP / PFCP timer behaves as specified (T3510, T3550, N4 T1 / N1 ...)", "LV", "Conformance testers", "Timers implemented; some tested", "Virtual clock hooks (g5c_now_seconds), AMF / SMF timer tests",
    "A time-warp mode that runs hour-long timer scenarios in seconds, making timer conformance cheap to prove", "Vendors", "Medium", "M", "None", 2)
add("B-13", "Test and emulation", "Security test cases (NAS replay, wrong MAC, SUCI tests, key hierarchy checks)", "Automate TS 33.501 / 33.117 style tests", "LV", "Landslide / Valid8 include security tests", "Test vectors for crypto, replay and integrity tests in the AMF e2e", "F-CODEC (NAS security envelope), F-SEC",
    "A named security suite mapped to NESAS / SCAS test cases with a report; reusable on third-party cores", "Vendors, regulators", "High", "M", "Pinned TS 33.117 / 33.501", 2)
add("B-14", "Test and emulation", "DN-side emulation (servers, DNS, DHCP, AAA, application servers)", "Emulate what is behind N6: web, DNS, AAA, video servers", "L", "Landslide emulates data networks", "Namespace host behind the UPF in the demo", "F-CLUSTER (namespaces), F-UPF (TUN N6)",
    "Packaged data-network peers for scenarios, including an AAA (RADIUS) peer for slice authentication", "Labs", "High", "S", "None", 1)
add("B-15", "Test and emulation", "KPI engine and standard counters (TS 28.552 style)", "Compute registration success, session setup success, latency percentiles, throughput, drop rates per period and slice", "LTX", "Landslide, TM500, XCAL report KPIs", "Latency histograms in load output; Prometheus counters", "F-OBS (counter registry), F-LOAD histograms",
    "One KPI definition file feeding the emulator report, the live core dashboards and the SLO gates, so lab and production numbers are comparable", "Operators, vendors", "High", "M", "None", 1)

# --- C. Analysis and observability
add("C-01", "Analysis and observability", "Trace viewer: pcap and logs to call-flow ladders", "Decode N2 / NAS / PFCP / GTP-U and logs into per-UE ladders with findings", "LTX", "XCAL / Landslide analysers; Wireshark for raw decode", "tools/inspect decodes; Atlas shows reference call flows", "F-CODEC, F-ATLAS, tools/inspect",
    "Upload a capture, get a ladder per UE with spec clause links from the matrix and red flags ('Registration Accept without SMC'); the same viewer for our own logs", "Support, vendors, operators", "High", "M", "None", 1)
add("C-02", "Analysis and observability", "SBI decryption in Wireshark (TLS key log)", "Write TLS session secrets so captures of the mutual-TLS SBI can be decrypted by the engineer who owns the keys", "-", "Standard practice (SSLKEYLOGFILE) in browsers and some stacks", "SBI is encrypted; captures show only TLS records", "F-SBI (OpenSSL contexts; a key-log callback is a few lines), g5c-capture",
    "An opt-in key-log file per function (off by default, mode 600, audit line when on) so mutual TLS does not cost debuggability; the capture helper adds the Wireshark profile", "Support, operators", "High", "S", "None", 1)
add("C-03", "Analysis and observability", "End-to-end request tracing (correlation IDs, OpenTelemetry)", "Follow one registration through AMF, AUSF, UDM, UDR, PCF, SMF, UPF", "L", "Commercial cores offer tracing", "Per-function logs; no shared trace id", "F-SBI (header hooks: 3gpp-Sbi-Correlation-Info, traceparent), nfcore logging",
    "Propagate a trace id through the SBI and N4, export OTLP, show one timeline per UE in the Atlas; the single most useful debugging tool in a multi-function core", "Operators, support", "High", "M", "An OTLP collector (optional)", 1)
add("C-04", "Analysis and observability", "Automatic procedure validation against the conformance matrix", "Check live or recorded traffic against the expected message sequence of each procedure", "L", "Landslide validates call flows in tests", "Matrix + tests; no runtime validation", "F-MATRIX, F-CODEC, C-01",
    "A passive 'conformance monitor' that flags deviations in a production or lab core (also third-party ones)", "Vendors, auditors", "Medium", "L", "None", 3)
add("C-05", "Analysis and observability", "Subscriber journey and failure classification", "Explain why a UE failed to register or lost its session, in plain terms with the clause and the NF at fault", "X", "XCAL-style analysis for the radio side", "Logs name the cause per event", "F-OBS (audit and log lines), AMF reject causes, C-03",
    "Rule-based root-cause engine over logs and traces ('#11 PLMN not allowed: subscriber has no PLMN in UDM data'); feeds the runbooks", "Operators, support", "Medium", "M", "None", 2)
add("C-06", "Analysis and observability", "Live Atlas: dashboards fed by a running core", "The Atlas site shows live topology, sessions, KPIs and alarms instead of a build-time snapshot", "-", "Commercial cores have GUIs", "Atlas is generated per regression", "F-ATLAS, F-OBS (metrics), F-SBI",
    "A live mode reading Prometheus and the NRF's registry; the same pages as the static site, so the demo and the product look alike", "Operators, demos", "High", "M", "None", 2)
add("C-07", "Analysis and observability", "Alarm and event streaming (syslog, SIEM, SNMP traps, X.733)", "Send alarms and audit events to the operator's systems", "L", "Commercial cores integrate with OSS", "Audit lines in logs", "F-OBS, structured JSON logs",
    "A sink module: JSON over TLS syslog and Kafka-style HTTP; map the alert rules to alarms with severities", "Operators", "High", "S", "None", 2)

# --- D. Security
add("D-01", "Security", "HSM / PKCS#11 and KMS integration for K, OPc and home-network keys", "Keys never in process memory in the clear; operations in an HSM", "L", "Commercial cores integrate HSMs", "master key from file or command (`exec:`); rotation with rewrap", "F-SEC (key source hook), UDM key handling, threat note",
    "A PKCS#11 provider for the UDM (Milenage / SUCI de-concealment inside the HSM) with SoftHSM for tests", "Operators (regulated)", "Medium", "L", "An HSM or SoftHSM; PKCS#11 headers (permissive)", 3)
add("D-02", "Security", "Certificate revocation and function identity pinning", "OCSP / CRL checks and binding a certificate to an NF type so one function cannot impersonate another", "L", "Commercial cores differ", "mTLS with a cluster CA; token decides authorization", "F-SBI (TLS contexts, swap), PKI script, NRF OAuth2",
    "CN / SAN to NF-type mapping enforced by the producer; CRL reload on SIGHUP; closes two lines of the threat model", "Operators, auditors", "High", "M", "None", 1)
add("D-03", "Security", "N2 / N3 / N4 transport protection (IPsec, DTLS)", "TS 33.501 clause 9 protection of the RAN and user-plane interfaces", "L", "Landslide tests IPsec", "Left to the operator network", "AMF SCTP socket layer, UPF sockets",
    "Document and test strongSwan-based protection of N2 / N3 / N4 in the lab kit; native DTLS for PFCP is a stretch goal", "Operators", "Medium", "L", "strongSwan (partner), a gNB that supports it", 3)
add("D-04", "Security", "Overload and rate control (TS 29.500 LCI / OCI, 429, per-source limits)", "Tell consumers to back off; protect the AMF from signalling storms", "L", "Commercial cores implement overload control", "Bounded contexts, deadlines, 503 on dependency failure", "F-SBI (router observer hooks, status codes), AMF max_unauthenticated",
    "Token-bucket per source on N2 and the SBI, LCI headers, automatic back-pressure in the SCP; proven with the load tool in storm mode", "Operators", "High", "M", "None", 2)
add("D-05", "Security", "Security assurance pack (NESAS-style evidence)", "Collect the artefacts an assessor wants: threat model, test results, SBOM, fuzz results, hardening guide", "LV", "Vendors sell tested products into NESAS-driven markets", "Threat model, SBOM, signed releases, fuzz and sanitizer runs", "F-SEC, F-REL, F-MATRIX",
    "A generated evidence bundle per release mapped to the GSMA NESAS / 3GPP SCAS test case names; shortens customer audits", "Vendors, operators", "High", "M", "Pinned SCAS documents; an assessor for the formal scheme", 2)
add("D-06", "Security", "Privacy features test kit (SUCI schemes, null-scheme policy, temporary identities)", "Verify concealment, de-concealment and GUTI reallocation behaviour", "L", "Landslide / Valid8 test identities", "SUCI profiles A and B implemented and tested", "F-CODEC, UDM SUCI",
    "A privacy suite with a report ('no SUPI in clear on N1 / N2 captures'), reusable by RAN and device vendors", "Vendors, regulators", "High", "S", "None", 2)

# --- E. Performance and scale
add("E-01", "Performance and scale", "UPF fast path (AF_XDP / eBPF / DPDK)", "Move GTP-U forwarding out of the userspace TUN path", "OF", "free5GC uses a kernel module (gtp5g); commercial UPFs use DPDK / hardware", "Userspace engine, about 1.2 Gbit/s on one core, gated", "F-UPF (PFCP rule engine independent of the data path), ADR-0014",
    "Keep our PFCP engine and add an XDP data path behind the same interface; publish throughput per core; the design already separates the two", "Operators, vendors", "Medium", "XL", "A NIC with XDP and a second host to measure", 3)
add("E-02", "Performance and scale", "Multi-core scaling of the UPF and the AMF", "Use several cores per function with flow / UE affinity", "LTX", "Commercial products advertise scale", "Worker pools in the SBI; one-core UPF", "F-SBI worker pools, F-UPF",
    "RSS-style flow hashing across UPF threads; per-UE sharding in the AMF; scaling curve in the SLO sheet", "Operators", "Medium", "L", "A many-core host", 3)
add("E-03", "Performance and scale", "Shared-state high availability (AMF / SMF contexts in an external store)", "Any replica can serve any UE; failover without losing connected UEs", "L", "Commercial cores offer HA", "State files, restart recovery, rolling upgrade tested", "F-UDR (PostgreSQL store pattern), state persistence in AMF / SMF, NRF NF sets, F-CLUSTER chaos tests",
    "A pluggable context store (PostgreSQL or Redis-class) behind the persistence layer, then active / standby and N+1 replicas with the chaos suite as the proof", "Operators", "Medium", "XL", "A shared store; design review", 3)
add("E-04", "Performance and scale", "SCTP multi-homing and N4 failover to a second UPF", "Redundant paths on N2 and an alternative UPF for sessions", "L", "Commercial cores", "Single path; SMF lists UPFs", "AMF SCTP layer, SMF UPF selection and heart-beat / loss detection (built)",
    "Multi-homed N2 and per-DNN UPF groups with automatic re-selection for new sessions first, session migration later", "Operators", "Medium", "L", "None", 3)
add("E-05", "Performance and scale", "NF sets and groups (TS 23.501 5.21), horizontal autoscaling", "Replicas of a function as a set, found through the NRF; scale on load", "L", "Commercial and cloud-native cores", "Single instance per function in tests", "NRF (profile fields, discovery), SCP (reselection, quarantine), F-OBS (load metrics)",
    "NF set support in the NRF / SCP and a metric-driven scaling controller for a Kubernetes deployment", "Operators", "Medium", "L", "Kubernetes (E-08)", 3)
add("E-06", "Performance and scale", "Performance regression tracking", "Record throughput / latency per release and flag regressions", "-", "Internal practice", "Gates with fixed thresholds", "F-CLUSTER, check_slo.py, Atlas",
    "A history chart in the Atlas of registrations per second and UPF Gbit/s per release; regressions flagged automatically", "Engineering, customers", "High", "S", "None", 1)

# --- F. Operations
add("F-01", "Operations", "Web console (subscribers, policies, sessions, health)", "A browser UI for day-to-day operation", "OFA", "Open5GS and free5GC ship web UIs; Amarisoft has a web GUI", "g5c-ctl and admin APIs", "F-CTL (UDM / PCF admin APIs, bearer tokens, mTLS), F-ATLAS, F-SBI",
    "A small console over the existing APIs: subscriber lists and bulk import, policy editor with validation, live sessions, certificate and key status, link to runbooks; role-based access", "Operators, labs", "High", "M", "None", 1)
add("F-02", "Operations", "Bulk provisioning and import / export (CSV, JSON, Open5GS / free5GC formats)", "Move subscribers in and out; migrate from other cores", "OF", "Both open cores store subscribers in MongoDB", "g5c-ctl subscriber add / list", "F-CTL, F-UDR",
    "Importers for Open5GS (MongoDB dump) and free5GC subscriber documents and a CSV format: the shortest path for someone to try us with their own subscribers", "Operators, labs", "High", "S", "None", 1)
add("F-03", "Operations", "Role-based access for admin APIs and tenant separation", "Operators with different rights; several customers in one core", "L", "Commercial cores have RBAC", "One bearer token per function", "F-SBI (guard hooks), F-CTL",
    "Roles (read, provision, policy, key admin) in the token claims; per-tenant subscriber namespaces; the audit line names the role", "Operators, MVNOs", "Medium", "M", "None", 2)
add("F-04", "Operations", "Helm chart, Kubernetes operator, container images", "Cloud-native deployment and lifecycle", "OF", "Community Helm charts exist for both open cores", "Dockerfile, compose and manifests written, never built or applied", "F-REL, systemd units, `ns upgrade` (rolling logic), F-OBS",
    "Build and verify the image in CI, a Helm chart generated from the same configuration model as the cluster script, an operator that runs the upgrade order and certificate renewal", "Operators", "Medium", "L", "A container runtime and a Kubernetes cluster", 2)
add("F-05", "Operations", "OAM interfaces (TS 28.532 provisioning MnS, 28.552 PM, 28.545 FM, NETCONF / YANG)", "Standard management interfaces for OSS integration", "L", "Commercial cores expose OAM", "Admin APIs and Prometheus", "F-CTL, F-OBS, KPI engine B-15",
    "A REST MnS facade mapping our admin API and counters to 3GPP management models; start with PM file export", "Operators", "Medium", "L", "Pinned TS 28.xxx", 3)
add("F-06", "Operations", "Configuration hot reload and staged changes", "Change slices, TACs, DNNs and policy without a restart; dry-run and rollback", "L", "Commercial cores", "Certificates and log level reload at run time", "nfcore SIGHUP path, config parser with strict key checking, `--check` mode",
    "A reload command (`SIGHUP` plus admin API) applying a validated config diff with automatic rollback if health fails", "Operators", "High", "M", "None", 2)
add("F-07", "Operations", "Zero-touch install and guided setup", "Generate a working configuration from a few answers (PLMN, TAC, addresses)", "A", "Amarisoft ships ready-made configs and a GUI", "Cluster script generates a full cluster; demo launcher reads gNB settings", "g5c-cluster.sh gen_conf, g5c-demo (reads gnb.yml)",
    "`g5c init` wizard writing configs, PKI and secrets for one host or a small cluster; the demo's 'read the gNB config' trick generalised", "New users, labs", "High", "S", "None", 1)

# --- G. Developer ecosystem
add("G-01", "Developer ecosystem", "OpenAPI served by every function and generated SDKs (Python, Go, JS)", "Machine-readable APIs with client libraries", "L", "Landslide offers automation APIs", "API reference generated from sources (296 routes); pinned 3GPP OpenAPI files for UDR / NSSF / NEF / BSF", "tools/docs/gen_api_docs.py, tools/gen_*_api.py (schemas), F-SBI",
    "Serve `/openapi.json` per function from the pinned schemas, generate SDKs and a Postman collection from them; examples in the guides", "Developers, AF builders", "High", "S", "None", 1)
add("G-02", "Developer ecosystem", "Policy and decision scripting (a safe extension language)", "Let operators express policy and steering rules without code changes", "L", "Commercial PCFs offer rule engines", "PCF policy layers in YAML / JSON", "PCF policy resolution layers, admin API",
    "A small expression language (or WASM modules) evaluated in the PCF / NSSF with resource limits; policy as code in a repository", "Operators, enterprise", "Medium", "L", "None", 3)
add("G-03", "Developer ecosystem", "Plugin hooks for charging, authentication and LI mediation", "Stable extension points", "-", "Commercial architectures", "Command-based secret source; CDR file", "nfcore (hooks), F-CDR, `exec:` pattern",
    "Documented, versioned hooks (CDR sink, auth vector source, event sink) so partners extend without forking", "Partners", "Medium", "M", "None", 3)
add("G-04", "Developer ecosystem", "Training lab and course kit", "Guided exercises on a device-less 5G lab", "A", "Vendors sell training around their testers", "ZMQ demo kit, guides, Atlas call flows", "F-DEMO, F-ATLAS",
    "Twelve exercises (register a UE, watch NAS, break a certificate, rotate a key, trace a session) with expected outputs checked by scripts", "Education, new hires", "High", "M", "None", 2)

# --- H. Market-led
add("H-01", "Vertical solutions", "Private-network starter pack (campus 5G)", "Core + provisioning + slices + local breakout in a small footprint", "OFA", "Open cores and Amarisoft target private networks", "Single-host cluster and demo", "F-CLUSTER, F-DEMO, F-REL (installer, units)",
    "A one-host appliance image with console, local breakout and enterprise slice templates; the cheapest way to reach many small deployments", "Enterprise", "Medium", "L", "Image build pipeline", 3)
add("H-02", "Vertical solutions", "Open RAN ecosystem interop and certification list", "Publish which gNBs and UEs were tested and with what results", "TL", "Vendors list supported RAN stacks", "OCUDU + srsUE (ZMQ), UERANSIM, Open5GS cross-tests", "F-ORACLE, F-DEMO, F-MATRIX",
    "An interop matrix per gNB / UE with capture links and fixes found; grows with each pilot", "Vendors, operators", "High", "M", "Access to more RAN / UE products", 2)
add("H-03", "Vertical solutions", "Edge application hooks (EAS discovery, DNAI exposure)", "Expose edge status to application servers", "L", "Commercial cores", "NEF traffic influence", "NEF, UDR application data, SMF multi-UPF config",
    "Edge discovery API on the NEF and a reference MEC integration", "Enterprise, MEC", "Medium", "M", "None", 3)
add("H-04", "Vertical solutions", "IoT fleet management features", "Bulk device provisioning, lifecycle, reachability statistics", "LA", "Landslide / Amarisoft IoT support", "Provisioning API, reachability events", "F-CTL, A-14, event exposure",
    "Fleet-level APIs: group provisioning, per-group policy, 'devices not seen for N hours' report", "Utilities, logistics", "High", "M", "None", 3)
add("H-05", "Vertical solutions", "Fixed-wireless and residential gateway support (FN-RG, 5G-RG)", "Authentication and sessions for gateways", "LF", "Commercial cores", "AUSF has FN-RG authentication paths", "AUSF, SMF, F-CODEC",
    "End-to-end FWA scenario with a gateway emulator", "Operators (FWA)", "Medium", "M", "A gateway emulator / device", 4)
add("H-06", "Vertical solutions", "Public-safety and mission-critical readiness", "Priority, preemption, MCX integration points", "L", "Commercial cores", "ARP / QoS flows supported in SMF / PCF", "SMF QoS, PCF rules, A-17",
    "Preemption and priority test suite and an MCX hand-off recipe", "Public safety", "Low", "L", "An MCX partner", 4)

# --- I. Commercial packaging
add("I-01", "Packaging and commercial", "Tester edition: our emulator and harness as a product", "Sell or give the UE / gNB emulator, scenario engine and reports as a core-test tool", "LADTVX", "Landslide, Valid8, Amarisoft, Viavi sell testers", "Internal harness", "F-LOAD, F-CLUSTER, B-01 to B-15, F-REL",
    "A separately licensed 'g5c-test' product reusing the same codecs as the core: the cost advantage of sharing code and specs between the DUT and the tester is ours alone", "Vendors, labs", "High", "L", "None", 2)
add("I-02", "Packaging and commercial", "Differential compatibility reports", "'Does your core behave like Open5GS / free5GC / commercial X on these scenarios' as a report", "-", "No peer publishes such a thing", "Differential tools for six functions against Open5GS", "F-ORACLE",
    "Offer the report to customers migrating from Open5GS; extend the oracle to free5GC to broaden it", "Migrating users", "High", "M", "free5GC binaries for the oracle", 2)
add("I-03", "Packaging and commercial", "Licensing and feature flags", "Enable features by licence key", "L", "Commercial products", "None", "nfcore config, secrets mechanism",
    "A signed licence file checked at start (feature flags, expiry, node count) kept optional and offline-verifiable", "Vendor", "High", "S", "Business decision on terms", 4)
add("I-04", "Packaging and commercial", "Support and telemetry workflow", "Case intake, bundle upload, version and config checks", "L", "Commercial support processes", "Diagnostics bundle, redaction, capture helper", "g5c-diag, g5c-redact, g5c-capture",
    "A bundle analyser that reads the diag tarball and prints known-issue matches; opt-in anonymous usage statistics", "Vendor, customers", "High", "M", "None", 3)
add("I-05", "Packaging and commercial", "Compliance and release dossiers", "Per-release PDF / Excel of conformance, test results, SBOM, licence audit, threat model", "L", "Commercial vendors supply dossiers on request", "Matrix, Atlas, release manifest", "F-MATRIX, F-REL, md_to_pdf.py",
    "One command producing the dossier a customer's procurement team asks for", "Vendor, customers", "High", "S", "None", 1)

# status of backlog items built since the sheet was first issued: feature id -> text for "Where we are today"
BUILT = {
    "A-06": "BUILT (first version): nf/sepp, a function of its own in the TLS-protected mode of N32-f. A local function's request for another network (3gpp-Sbi-Target-apiRoot in the domain of a partner) is screened and sent to the partner's SEPP with the originating network id; a request from a partner SEPP is checked against that partner (network id, source address, allowed services, forbidden paths, a request rate, identities) and delivered to the local function its target apiRoot stands for, with the Via chain, back-off propagated (429) and the function's Location rewritten to the SEPP's public apiRoot (topology hiding). Tested with a visited and a home SEPP and a stand-in UDM in process (11 cases). NOT built: the N32-c handshake and security capability negotiation (the partner relation is configured), PRINS (application layer protection) and the IPX provider's modification policy, a run against another vendor's SEPP (Open5GS has one and would need N32-c), the SEPP in compose, systemd, the cluster script and the Atlas",
    "A-20": "BUILT (first version, part of the SEPP): per-partner screening of inbound roaming signalling: only the services the partner is allowed, paths it may not touch (for example /location), a token bucket per partner (429 with Retry-After), SUPIs in request paths must belong to the local network (a partner asks about our subscribers, not about others), an unknown network id or a wrong source address is refused, and every decision is counted per partner and result (g5c_sepp_requests_total). NOT built: screening of message bodies (a location request inside an allowed service), anomaly baselines per partner, the home-routed and steering-of-roaming checks, alerting rules for the counters",
    "B-16": "BUILT (first version): the roaming cases of nf/sepp/tests/test_sepp.c run a visited and a home network end to end in process: the allowed request, a service not open to the partner, a forbidden resource, a subscriber of another network, an unknown network, a wrong source, a target not served, topology hiding, the rate limit and recovery, a loop. NOT built: a library of scenarios that runs two real core clusters side by side (home-routed sessions, local breakout, inbound and outbound roamers through the functions), a scenario step for the engine, a run against Open5GS's SEPP",
    "G-02": "BUILT (first version): policy.scripts at the PCF: each entry has a condition (`when`) in a small bounded expression language (and, or, not, ==, !=, <, <=, >, >=, startswith, endswith, contains, in [...], over supi, dnn, sst, sd, plmn and the subscribed 5QI; 400 characters, 64 nodes, 16 levels, no loops or calls) and a profile (session AMBR, default QoS, PCC rules); the first script whose condition holds is a layer of the policy, below the subscriber's own policy and above the operator's DNN profile. Syntax and unknown fields are refused when the configuration is read, with the position. Tested on the language (precedence, types, limits, errors), on the resolution order and on the real daemons (a script takes the rate of every session of the load generator's subscribers from 1 Gbit/s to 1 Mbit/s and the UPF enforces it). NOT built: scripts at the NSSF, scripts that call out or keep state, WASM modules, policy kept in a repository and reloaded (the PCF reads it at start; SIGHUP reload of policy.scripts is not hooked), a dry-run tool for conditions",
    "E-04": "PARTLY BUILT: amf.ngap.addresses binds the AMF's N2 SCTP endpoint to up to eight local addresses (SCTP bindx), so a gNB can reach it on any of them (cluster test: two waves of gNBs, one to each address); the SMF already selects only UPFs that are up and serve the DNN, round robin, so a lost UPF is replaced for new sessions. NOT built: a gNB-side multi-homed association with path failover (the harness connects to one address), session migration to another UPF, per-DNN UPF groups with weights",
    "H-01": "BUILT (first version): g5c-init --preset campus defaults to the private-use PLMN 999/99 and writes campus/ next to the configurations: three device groups (staff, machines, sensors) as groups.json for g5c-fleet, a devices template and a guide with the commands to add devices, the slices and DNN to add to the configurations, and what to watch. Tested (the files, the groups accepted by g5c-fleet). NOT built: an appliance image, local breakout and a second data network, slice templates written into the configurations, a console page for groups",
    "A-01": "BUILT (first version, not an SBI function): tools/cli/g5c-nwdaf samples the /metrics of the functions you name and serves, in the shape of Nnwdaf_AnalyticsInfo and as Prometheus series, NF_LOAD (load, request rate, server-error share), SLICE_LOAD_LEVEL (PDU sessions per S-NSSAI, from the new g5c_smf_pdu_sessions_by_slice gauge) and REGISTRATION_ANOMALY (the registration rate against its own recent window in standard deviations, and the rejected share). Tested on constructed windows and against fake functions. NOT built: an Nnwdaf SBI function (HTTP/2, NRF registration, OAuth2, subscriptions and notifications), learned models, UE mobility analytics, abnormal-behaviour analytics beyond registrations, analytics from the SMF or UPF event streams",
    "G-03": "PARTLY BUILT: a documented, versioned extension contract (libs/nfcore/include/g5c/hook.h, g5c-hook/1): a partner program receives each item as a line of JSON on its standard input with an empty environment except the hook point, a bounded queue, a timeout that kills the program and what it started, and counters. The first hook point is the SMF's charging records (smf.cdr.sink_command); the event sinks already exist (events: syslog, HTTP). Tested in the library (delivery, failure, timeout, queue overflow, refusal of a bad command) and on the real daemons. NOT built: a hook for authentication vectors (the UDM computing them itself today), hook points in other functions, hooks that answer (request / response), a registry of hooks",
    "H-04": "BUILT (first version): tools/cli/g5c-fleet works from the subscriber inventory and the SMF charging records: group provisioning from a template (slices, DNNs, aggregate rates) into the CSV of g5c-subscribers, a per-group report over a window (devices, active, silent, never seen, sessions, volume) and the list of silent devices with the time last seen (exit 1 for cron). Tested with synthetic fleets and with the importer. NOT built: groups known to the UDM or the PCF (the group is a file the operator keeps, so a per-group policy is applied at provisioning only), reachability from the AMF's events, a group-wide bulk change of existing subscribers",
    "I-04": "BUILT (first version): tools/cli/g5c-triage reads a diagnostics bundle and checks it against docs/ops/known-issues.json (15 rules over logs, metrics, configurations and certificate expiry; each with advice and a runbook heading that a test checks exists); findings by severity, and rules the bundle cannot answer are listed as not checked. NOT built: case intake, bundle upload, opt-in usage statistics, matching against a database of issues kept by the vendor",
    "E-05": "PARTLY BUILT: nf_set_id in the configuration of any function puts nfSetIdList in its NRF profile, and the NRF's discovery answers target-nf-set-id (case-insensitive) with the members of the set; the SCP's existing reselection and quarantine work within an answer. NOT built: service sets, NF set information in the SCP's routing headers, a metric-driven scaling controller for Kubernetes",
    "C-04": "BUILT (first version): tools/cli/g5c-conform checks a capture (tshark, or the rows of g5c-ladder) against docs/conformance/procedures.json: per UE the order registration, authentication, security mode, context setup; NGAP requests answered in time; the authentication request answered within T3560; NG Setup answered; PFCP establishment and deletion answered. It keeps every rule on the recorded Open5GS + UERANSIM traces (also with our AMF / SMF / UPF in them) and finds each violation in synthetic ones, naming the clause. NOT built: live capture, rules for N1 messages after ciphering starts (not visible in a capture), mobility, handover and paging rules, a rule per row of the matrix",
    "A-02": "PARTLY BUILT: a new function, nf/chf (Nchf_ConvergedCharging, TS 32.291): a charging session per PDU session that reserves a volume quota against the subscriber's balance, grants it with a validity time, debits what is reported, re-grants on update, says TERMINATE on the last quota, denies when the balance is gone and writes a charging data record on release. The SMF is the trigger (smf.chf): it opens the session at set-up (a denial refuses the PDU session) and closes it with the usage the UPF measured. Tested in process (balances, quota arithmetic, records) and on the real daemons (30 sessions all charged; with no credit every session refused). Quota is controlled while the session is up: the UPF reports when the granted volume has passed (a usage rule with a volume threshold), the SMF reports it to the CHF, gets the next quota and re-arms the rule; with no balance left the SMF releases the PDU session (cluster tests: 28 renewals for 1.5 MB at 50 kB quotas; a balance of 120 kB ends the sessions and nothing beyond it is charged). Traffic that arrives before the UE confirms the release is forwarded but not charged. NOT built: time-based and event-based charging, offline charging records in a standard format (CDR file is JSON lines), rating (tariffs), the CHF in compose / Kubernetes / systemd, persistence of the CHF's state",
    "A-09": "PARTLY BUILT: network slice admission control. amf.slice_limits caps the registered UEs per S-NSSAI (a full slice leaves the allowed NSSAI and goes into the rejected NSSAI) and smf.slice_limits caps PDU sessions per S-NSSAI (cause #69, insufficient resources for the specific slice); both tested with the real flows. NOT built: slice-specific authentication (NSSAA, EAP with an AAA server through an NSSAAF); the Rel-17 Extended rejected NSSAI with its back-off timer T3526 (the NAS tables are Rel-16, so the plain rejected NSSAI carries the slice); a separate NSACF shared by several AMFs (the count is per AMF); two registrations racing for the last place can both get it",
    "A-14": "PARTLY BUILT: amf.power_saving grants MICO mode, extended DRX and the active timer T3324 when the UE asks for them (the negotiated values go back in the Registration Accept; the eDRX cycle is limited to what NGAP can carry). A MICO UE and a UE whose T3324 has run out are not paged: the SMF's transfer fails at once with UE_NOT_REACHABLE and the paging is counted as suppressed. A UE with extended DRX is paged with the Paging eDRX information (cycle and paging time window). Tested end to end through the AMF. NOT built: RedCap (the NGAP tables are Rel-16 and have no RedCap indication), data buffering until the UE is reachable (the transfer is failed, not held), these states are not kept across an AMF restart, no 5GS PSM (T3412 extended) negotiation beyond T3324",
    "B-03": "PARTLY BUILT: tools/cli/g5c-fanout runs many load processes against one core with disjoint IMSI ranges (--processes, or --total with --slice K/N to spread it over hosts) and adds up the result; the scenario step takes processes: N. Tested with a stand-in and on the real daemons (4 processes of 40 UEs). The earlier measurement stays the largest real one: 10,000 UEs with sessions in 20.7 s through real daemons in one process. NOT shown: a million subscribers, or several hosts (nothing here has more than one machine)",
    "B-09": "PARTLY BUILT: the load generator's mobility mode (G5C_LOAD_MOBILITY, scenario step mobility: N, mobility_kind: n2 for N2 handovers) moves every UE between two gNBs by Xn path switches or by full N2 handovers (Handover Required, Request with the next hop checked, Acknowledge, Command, Notify, source release) against the real daemons, checking every answer (the UE and RAN ids, the next hop and its chaining count against the UE's own derivation, the switched sessions); 144 switches by 24 UEs on 4 workers pass, and the SMF's downlink tunnel follows (cluster tests cluster_mobility_xn and cluster_mobility_n2). NOT built against real daemons: inter-AMF mobility (N2 handover with an AMF change), idle-mode reselection and the paging that follows",
    "B-10": "BUILT: deploy/radio-kit holds the configurations of the OCUDU gNB and srsUE and g5c-radio-kit check / run: the whole lab (our core, gNB, UE, registration, session, ping through the radio) in one command without sudo; run on this machine with the kit's own files: both pings 5 of 5, 27 s. The gNB and the UE are not shipped (they are built from their projects; check says how). NOT run: real RF with an SDR (g5c-radio-kit sdr describes the two blocks that change), more than one UE",
    "H-02": "BUILT (first version): docs/interop/register.json and its page list the six combinations that were run (OCUDU gNB with srsUE over ZeroMQ against our core; UERANSIM with our AMF, with our SMF and UPF, with our AUSF's EAP-AKA'; Open5GS with our UDM, UDR, PCF; the differential comparison) with the result, the limits, the command to run each again and the evidence file, checked by a test; it lists what has NOT been tested (any commercial gNB, UE or radio unit, free5GC, real RF). The list grows only when a new product is run",
    "I-01": "BUILT: tools/cli/g5c-tester points the load generator at a core that is not ours (--amf ip:port, --subscribers URL or --no-provision, an admin token from the environment) with storms, mobility, traffic and many processes, and g5c-tester pack writes one reproducible bundle (the load generator, the tools, the scenarios, the training exercises, the test guide, a manifest of hashes). Run against the Open5GS 2.8.0 oracle (deploy/oracle/tester.sh; ctest tester_vs_open5gs): scripted UEs register, authenticate, set up PDU sessions and de-register at an AMF, SMF and UPF that are not ours; it found that our scripted UE sent non-cleartext IEs in its first Registration Request, which Open5GS rejects (fixed: --foreign sends cleartext IEs only). NOT done: the scenario engine against a foreign core (it needs the cluster script), N2/N3 behaviours other than registration and sessions, a licence and a support offer, installers",
    "C-06": "BUILT (first version): tools/cli/g5c-atlas-live serves a page that refreshes every 5 s from the running functions: live / ready, release and load of each function, the NRF's registry, and the service KPIs with their targets, since start and over the last minute (the arithmetic of g5c-kpi, one definition file); read-only; checked in a browser and by a test against fake functions (which found and fixed a mix-up of identical series of two functions). Open: the other pages of the static Atlas (procedure ladders, traceability) in live mode, history beyond five minutes, Prometheus as a source, a login, alert history",
    "I-02": "BUILT: tools/cli/g5c-compat runs the nine differential tests against Open5GS 2.8.0 (or reads their output) and writes a compatibility report, one row per compared case: 129 cases, 56 matches, 29 where ours adds fields, 44 documented differences each with its reason (a status the TS says otherwise, a resource the reference lacks), none unexplained; text, Markdown, HTML, CSV and JSON. Open: free5GC as a second reference (no binaries for the oracle), scenarios beyond what the nine tests compare, a version of the report for a customer's own configuration",
    "B-12": "BUILT: G5C_TIME_WARP / g5c_time_warp_set make the clock of deadlines run faster than the wall clock (the AMF timer thread and the SMF job scheduler sleep the warped wait): the T3560 sequence of five transmissions runs in a fifth of a second at a warp of 25 with the same behaviour; the default NAS timers are pinned against TS 24.501 Table 10.2.2. Open: the SMF N4 retransmission timers and the SBI client deadlines are not warped, timers of the other functions, a per-timer conformance table for the SMF",
    "B-11": "BUILT: tools/cli/g5c-replay extracts the NGAP exchange of a capture (steps with decoded names), replays the gNB messages that need no secrets (NG Setup, an unprotected Registration Request) to the AMF over SCTP and compares each answer with the recorded one; the scenario step replay and cluster_replay show our core refusing an unknown subscriber where the recorded core authenticated, and matching after provisioning. Open: replay beyond the first authentication (needs the recorded keys or a UE model), N4 and SBI captures, mapping to a rebuilt UE script",
    "B-05": "BUILT: tools/cli/g5c-mutate sbi sends 28 kinds of hostile request to every route of a function (from its /openapi.json: invalid and truncated JSON, wrong content type, JSON bombs, oversize and absurd values, hostile path parameters) and fails a route on 5xx, silence, a function that stops being ready or accepting what is not JSON; n2 corrupts the gNB messages (cuts, flips, garbage, repetition). cluster_mutation sweeps nine functions and the AMF (about 700 requests, about 80 % reaching route parsing, none failed); the unit test proves it can fail. Open: driving the mutations from the conformance matrix per clause, N4 and PFCP, a stateful mutation of a running procedure",
    "G-04": "BUILT: docs/training holds thirteen exercises (first registration, refusing on purpose, asking why, losing the SMF, a slow link, a session rate, a signalling storm, hot reload, replaying a capture, hostile input, reading a capture, breaking a certificate, rotating a key), each with goal, steps, expected result and reason, and tools/cli/g5c-lab checks each on a private cluster (all thirteen pass). Open: a course around them, exercises for the user plane radio side, a hosted lab",
    "F-04": "PARTLY BUILT: deploy/k8s/base holds manifests generated from the compose model (a Deployment, Service, ConfigMap and state claim per function, restricted pod security, default-deny network policies, rendering of the compose addresses at pod start), cross-checked by a test that also runs the init scripts. NOT built: a Helm chart, an operator, and nothing has been applied to a cluster or built as an image (no container runtime here)",
    "B-13": "BUILT (first version): docs/conformance/security-suite.json names 17 security cases (5G-AKA and the key hierarchy, EAP-AKA prime, NAS integrity / ciphering / replay / wrong MAC, SUCI and the null-scheme policy, mutual TLS, pinning and revocation, OAuth2, overload, roles and tenants, audit, secrets, configuration, parser robustness, licences), each with its specification and the tests that prove it; g5c-dossier security prints the verdict of each case and the ctest expression that runs exactly the suite. Open: running the suite against a core that is not ours, the SCAS test case names (the documents are not pinned)",
    "D-05": "BUILT (first version): g5c-dossier security writes the security assurance report (the suite with results, the 30 security rows of the matrices with the gaps listed, CSV and JSON) and the release dossier carries it next to the threat model, SBOM, licence audit, test results and guides, all hashed in the manifest. Open: the GSMA NESAS / SCAS test case names and an assessor (the SCAS documents are not pinned), a hardening guide as its own document, the penetration test result",
    "C-08": "BUILT: tools/cli/g5c-cdr reports from the SMF charging records: usage by DNN, slice, UPF, hour, day or subscriber, session length and throughput, why sessions ended, the inbound-roamer share against a home PLMN, the heaviest subscribers, and data-quality checks (missing records in the sequence, duplicates, unreadable lines, sessions without a measurement); CSV export and a period for cron. Open: counters from /metrics in the same report (use g5c-kpi), tariffs and rating, a scheduled mail of the report, call-quality measures from the radio side",
    "C-05": "BUILT: tools/cli/g5c-why reads the functions logs (directory, files or stdin; text or JSON) and explains each failure per subscriber: the 5GMM cause in words, the function and clause at fault, what to check and the runbook entry, with the error of the function that caused it found by the trace id; repeated failures counted, a storm summarised (16,650 congestion refusals in one entry on the real overload test logs). Open: rules for the functions other than AMF, SMF, AUSF, UDM, PCF, a web page in the Atlas, learning new rules from the conformance matrix",
    "F-03": "BUILT: admin_tokens_file at the UDM and PCF: tokens (stored as SHA-256) with roles read, provision, policy, key-admin; tenants confined to SUPI prefixes (what is outside is not there for them, bulk requests are judged per record, a tenant lists and ends only its own sessions); 401 / 403 with the missing role named; the audit lines say who did it; tools/cli/g5c-tokens makes and revokes tokens and the file is read again when it changes. Open: per-tenant limits and quotas, roles on the other functions' admin interfaces, OIDC tokens",
    "F-06": "BUILT: SIGHUP, POST /admin/v1/reload and g5c-ctl reload re-read the configuration, validate it, diff it and apply live what the function can (overload, events, log level in every function; suci at the UDM, amf.overload at the AMF), list the rest as restart-required, and put everything back if a section fails or the function stops being ready or answers server errors after the change. Open: the slice, TAC, DNN and policy sections of the AMF, SMF and PCF (they need their configuration to be read from a snapshot), staged changes",
    "D-04": "BUILT: per-source token buckets on the SBI of every function (overload: 429, Retry-After, 3gpp-Sbi-Oci, 3gpp-Sbi-Lci), clients that honour them, an SCP that reselects and answers 429, and AMF registration admission (amf.overload: cause #22 with T3346); proved with a storm in the live cluster (22,535 registrations in 4 s, 100 admitted, the rest refused, AMF ready throughout). Open: NGAP Overload Start towards the gNBs, overload by CPU or queue depth instead of rate, a limit per consumer type behind the SCP",
    "D-06": "BUILT: tools/cli/g5c-privacy scans a capture of N1 / N2 (null-scheme SUCI, IMSI in clear, repeated SUCI outputs, GUTI not reallocated, subscriber digits as ASCII or BCD); suci.null_scheme: reject at the UDM; an end-to-end test proves a concealing UE leaves no digits on N2 and a null-scheme UE does. Open: temporary identity checks across handover, EPS identities",
    "C-07": "BUILT: events: sends warnings, errors and every audit line as JSON to a syslog collector (RFC 5424 over UDP, TCP or TLS) and/or an HTTP collector, with X.733 alarm fields, a bounded queue and delivery metrics; deploy/ops/alarms.json maps every Prometheus alert to an alarm and tools/cli/g5c-alarms forwards Alertmanager webhooks. Open: SNMP traps, Kafka wire protocol",
    "A-05": "BUILT: Nudm_EventExposure at the UDM (SUPI, GPSI or anyUE; loss of connectivity, CM state, location, reachability) relayed from the AMF; nef.events_via_udm routes the NEF through it. Done since: subscriptions survive a UDM restart (ee.state_file). Open: group identities, UEs not yet registered",
    "C-02": "BUILT: G5C_TLS_KEYLOG writes the TLS secrets (NSS key log, mode 0600) from every function for Wireshark; a capture is opaque without it and decrypts with it (tshark, in the cluster test)",
    "F-02": "BUILT: tools/cli/g5c-subscribers imports Open5GS, free5GC and CSV subscribers (validated, applied through g5c-ctl) and exports an inventory without keys. Done since: a bulk endpoint (subscribers-bulk) and a batched import. Open: import of policies",
    "B-01": "BUILT: tools/cli/g5c-scenario runs a YAML scenario (load, kill, restart, impair, assert on metrics and KPIs, HTTP) against a private cluster; three scenarios ship and run as tests. Open: scripted per-UE mobility and idle steps, gNB-side message assertions",
    "B-04": "BUILT (first version): amf.inject (registration reject with a chosen cause, delayed accept) and smf.inject (PDU session reject with a status, N4 responses dropped), counted in metrics. Open: NGAP error injection, timer expiry, a runtime API instead of configuration",
    "B-06": "BUILT: tools/release/g5c-dossier report writes the 387-row matrix as HTML, CSV and JUnit with the result of each row's tests. Open: running the same suite against a core that is not ours",
    "B-07": "BUILT (first version): tools/cli/g5c-api, a bearer-token HTTP/1.1 API to start, watch and stop scenario runs, with OpenAPI. Done since: output followed with ?since=, TLS required off loopback, a client generated from its OpenAPI. Open: a WebSocket stream",
    "B-08": "BUILT: the scenario step impair (delay and loss toward one function, tc netem, verified: the SMF's session set-up p95 rose to 0.23 s with 150 ms toward the UPF). Done since: reorder, duplication and jitter. Open: impairment of radio-side links",
    "B-14": "BUILT: tools/cli/g5c-dn serves DNS, HTTP (bytes, delay, status), UDP echo and RADIUS for scenarios. Done since: RADIUS accounting. Open: DHCP, video-like application servers",
    "C-01": "BUILT: tools/cli/g5c-ladder turns a capture into per-UE and per-N4-session ladders with red flags and links to matrix rows (found the malformed PFCP in the 2026-10-28 capture). Open: ciphered NAS names need the keys, our own logs as ladders, GTP-U",
    "C-03": "BUILT: W3C traceparent over the SBI, trace ids on every log line, one trace per UE connection at the AMF, tools/cli/g5c-trace joins logs into timelines (15 multi-function traces in the live test). Open: OTLP export, N4 and thread-hop propagation",
    "D-02": "BUILT: sbi.tls.allowed_peers pins client certificate names per function and sbi.tls.crl enforces revocation (g5c-pki.sh revoke), both tested in the live cluster. Done since: per-function default lists (G5C_PIN_PEERS, g5c-init --pin-peers), proved in a full wave. Open: OCSP, client-side pinning of servers",
    "E-06": "BUILT: tools/release/perf_history.py records each regression run per release, flags regressions against the median of the earlier ones and draws a chart (first entry recorded). Open: the Atlas page, more metrics",
    "F-01": "BUILT (first version): /console at the UDM, a single page with a strict content security policy to list, add, import and delete subscribers. Open: policies and sessions (PCF), roles, certificate status, a test in a real browser",
    "F-07": "BUILT: deploy/run/g5c-init writes configurations for all twelve functions, fresh secrets and a PKI from a few answers (every binary accepts the result with --check). Done since: systemd units (g5c-init --systemd). Open: multi-host layouts",
    "G-01": "BUILT: every function serves /openapi.json from its live router; tools/cli/g5c-sdk makes a Python client and a Postman collection (used against the live UDM). Done since: a JavaScript client (node:http2). Open: a Go client, request and response schemas from the pinned 3GPP files",
    "I-05": "BUILT: tools/release/g5c-dossier dossier collects the report, test results, SBOM, licence audit, threat model, guides and a hash manifest into one folder and zip. Open: PDF and Excel renderings, counsel's sign-off",
    "A-03": "BUILT (first version): policy.usage_monitoring at the PCF -> umDecs, a monitoring URR with a volume threshold on the UPF, usage report to the SMF, accuUsageReports to the PCF, throttle decision applied (UPF, UE, gNB), tested end to end with the real PCF and UPF. Open: per-subscriber and time thresholds, re-arming per period, several monitoring keys, prepaid quota (needs Nchf)",
    "B-02": "BUILT (first version): the load generator sends uplink GTP-U per UE at a set rate and size after the session set-up; the UPF's counters give delivered and dropped, and a scenario fails unless the session AMBR is held (4 Mbit/s offered, 1 Mbit/s allowed: 1.03 delivered). Open: downlink and loss / latency / jitter at the receiver (the generator side is written and kept in scenarios/experimental, not working yet), GBR checks, TCP-like flows, several QoS flows per UE",
    "B-15": "BUILT: deploy/ops/kpis.json + tools/cli/g5c-kpi (lab runs, periods, targets as a gate) + generated Prometheus recording rules. Done since: per-slice KPIs. Open: emulator-side latency percentiles in the same file",
}

# --- features that the two newest peers make visible: roaming and interconnect, signalling security, service-quality analytics
add("A-20", "Core functions", "Roaming signalling security screening at the SEPP", "Checks on N32 traffic: message validation, rate and anomaly limits, spoofed-identity and location-request screening, per-partner policy", "M",
    "Mobileum markets signalling firewalls for SS7, Diameter and 5G roaming", "Not built (depends on the SEPP, A-06)", "F-SBI (router, rate control hooks), F-NF, F-OBS (counters per partner), D-04 style overload control",
    "Ship the screening as policy on our own SEPP with every decision counted and exported; partner scorecards come from the same counters", "Operators", "Medium", "M", "TS 33.501 13.4 / 33.117; GSMA FS.36 / FS.40 guidance; a second PLMN lab", 3)
add("B-16", "Test and emulation", "Roaming and interconnect scenario library (home-routed, local breakout, inbound and outbound)", "Scripted visited / home PLMN scenarios across N32 with the partner's profile, including failure and policy cases", "M",
    "Mobileum and Landslide describe roaming and interconnect testing", "Not built (needs the SEPP and a second PLMN lab)", "F-LOAD, F-CLUSTER (two clusters side by side), F-ORACLE (Open5GS SEPP as reference), B-01",
    "Run the same roaming scenarios against our core and against a reference core and publish the differences", "Operators, vendors", "Medium", "L", "A-06 SEPP; TS 23.502 4.2.2 roaming flows; GSMA IR.88 / IR.92 style test lists", 3)
add("C-08", "Analysis and observability", "Service-quality and roaming analytics from CDRs and counters", "Reports on registration success, session setup time, cause-code trends, volume per DNN / slice / roaming partner", "M",
    "Mobileum sells analytics and business-intelligence on network and roaming data", "CDR file and Prometheus counters exist; no reporting layer", "F-CDR, F-OBS (Prometheus, Grafana), F-ATLAS (generated pages), C-05 failure classification",
    "Scheduled reports and dashboards from data the core already produces, with a CSV / JSON export for the operator's own tools", "Operators, MVNOs", "High", "M", "None", 2)

B.sort(key=lambda r: (r[0][0], int(r[0][2:])))

HEAD_B = ["ID", "Category", "Feature / capability", "What it is", "Offered by (peers, public descriptions)", "Peer evidence", "Where we are today", "What we already have to build on",
          "What we can add or do differently", "Who benefits", "Feasibility", "Effort (relative)", "Needs from outside", "Suggested wave"]

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Feature matrix: indicative, from public descriptions.  F full, P partial / variant / optional, - not offered or not documented, ? to verify.
# columns: O5GS, F5GC, Landslide, Amarisoft, DuoSIM, Valid8, TM500, XCAL, g5c today, g5c with the backlog
MATRIX = [
    ("Complete 5G SA core functions (AMF, SMF, UPF, AUSF, UDM, UDR, PCF, NSSF, NRF)", "F F P F - P - - F F"),
    ("SCP (indirect communication)", "F - P ? - - - - F F"),
    ("BSF", "F ? P ? - - - - F F"),
    ("NEF with northbound APIs", "- F P ? - - - - F F"),
    ("CHF / Nchf charging", "- F P ? - - - - P F"),
    ("NWDAF", "- P F ? - - - - - F"),
    ("SEPP / roaming", "F - P ? - - - - - F"),
    ("4G EPC (MME / SGW / PGW / HSS)", "F - P F - F - - - F"),
    ("N3IWF / non-3GPP access", "- F P ? - - - - - F"),
    ("UE policy (URSP)", "- ? F ? - - - - - F"),
    ("Edge: UL-CL / local breakout", "- F P ? - - - - P F"),
    ("IMS / VoNR support", "- - F F - P - - - F"),
    ("Web console for subscribers", "F F - F - - - - P F"),
    ("OAuth2 tokens enforced between NFs", "? P ? ? - - - - F F"),
    ("Mutual TLS between NFs", "P P ? ? - - - - F F"),
    ("Prometheus metrics on every NF", "F P ? ? - - - - F F"),
    ("Native audit log and charging records", "- P ? ? - - - - F F"),
    ("Hot certificate renewal and key rotation", "- - ? ? - - - - F F"),
    ("Signed releases, SBOM, licence audit shipped", "- - ? ? - - - - F F"),
    ("Cloud-native packaging (Helm / operator)", "P P P ? - - - - - F"),
    ("High availability with shared state", "- - ? ? - - - - - F"),
    ("UPF acceleration (XDP / DPDK / kernel module)", "- F ? ? - - - - - F"),
    ("Scripted UE / gNB emulation (control plane)", "- - F F F F F F P F"),
    ("User-plane traffic generation and KPIs", "- - F F F F F F P F"),
    ("Large-scale emulation (thousands to millions of UEs)", "- - F F F F F F P F"),
    ("Mobility / handover scenarios", "- - F F F F F P P F"),
    ("Slice scenarios", "- - F F F F F - P F"),
    ("Negative testing and fault injection", "- - F F F F P - P F"),
    ("Automated conformance suites with reports", "- - F P P F P - P F"),
    ("Remote automation API (REST / WebSocket / SDK)", "- - F F ? ? ? ? P F"),
    ("Network impairment emulation", "- - F ? ? ? F - P F"),
    ("Real RF / SDR air interface", "- - P F P F F F - P"),
    ("O-RAN fronthaul / RU testing", "- - ? F ? ? F - - -"),
    ("Drive-test and RF measurements", "- - - - - - P F - -"),
    ("Protocol decode and call-flow analysis", "- - F P P F F F P F"),
    ("Passive conformance monitor on live traffic", "- - P - - - - P - F"),
    ("Differential comparison against a reference core", "- - - - - - - - F F"),
    ("Device-less lab kit (virtual radio)", "P P - P - - - - F F"),
    ("NTN / satellite support", "- - ? F - - P - - P"),
    ("RedCap / IoT / eDRX core support", "- - F F - - P - - F"),
    ("MBS (multicast / broadcast)", "- - ? F - - - - - P"),
    ("Lawful intercept", "- - ? ? - - - - - P"),
    ("Security assurance evidence pack (NESAS-style)", "- - ? ? - - - - P F"),
]
# Polaris Networks and Mobileum, in matrix order (public descriptions; Mobileum is a roaming / analytics / signalling-security vendor, not a core vendor)
MATRIX_NEW = ["P -", "? -", "? -", "? -", "? -", "? P", "? P", "F -", "? -", "? -", "? -", "? -", "? -", "? -", "? -", "? -", "? P", "? -", "? -", "P -", "? -", "? -", "F -", "F -",
              "P -", "F -", "P -", "P -", "F P", "? ?", "? -", "- -", "- -", "- -", "P F", "- F", "- -", "P -", "- -", "- -", "- -", "- -", "- -"]
assert len(MATRIX_NEW) == len(MATRIX), (len(MATRIX_NEW), len(MATRIX))
MATRIX = [(cap, " ".join(v.split()[:8] + new.split() + v.split()[8:])) for (cap, v), new in zip(MATRIX, MATRIX_NEW)]
# capabilities the two newest peers bring into view; columns: O F L A D V T X Polaris Mobileum, g5c today, g5c with the backlog
MATRIX += [("Roaming test scenarios (home-routed / local breakout)", "- - P ? - ? ? - ? P - F"),
           ("Roaming signalling security screening (firewall)", "- - - - - - - - - F - P"),
           ("Service-quality and roaming analytics", "- - - - - - P P ? F P F")]
MATRIX_HEAD = ["Capability"] + PEERS + ["g5c today", "g5c with the backlog"]

NOTES_PEERS = [
    ("Open5GS", "Open-source 4G + 5G core (AGPL-3.0). Our behavioural oracle. Stated Release-19 in its README; NF completeness varies.", "docs/strategy: Reference Projects"),
    ("free5GC", "Open-source 5G core (Apache-2.0) with N3IWF, CHF, NEF and UL-CL work; kernel-module UPF (gtp5g).", "docs/strategy: Reference Projects"),
    ("Spirent Landslide (now Keysight)", "Core and RAN/UE emulator; tests AMF / SMF / UPF over N1 to N11 and 20+ service nodes; states 3GPP compliance testing up to Release 17.", "docs/strategy: Vendor Comparison"),
    ("Amarisoft AMARI Callbox / UE Simbox", "Software eNB / gNB with built-in core and IMS for device testing; UE Simbox simulates UEs against a gNB or core; Release 18 core, Release 19 RAN software stated.", "docs/strategy: Vendor Comparison"),
    ("Artiza DuoSIM-5G", "RAN (gNB / eNB) tester that simulates thousands of UEs, SA / NSA, slicing, handovers; no core emulation claimed.", "docs/strategy: Vendor Comparison"),
    ("Valid8 UE Tester + core emulators", "Base-station and core emulator for UE testing; customisable core nodes; NR Release 15 stated.", "docs/strategy: Vendor Comparison"),
    ("Viavi TM500", "UE-side network tester emulating thousands of devices for RAN testing; roadmap to Release 16 / 17 / 18, NTN and RedCap.", "docs/strategy: Vendor Comparison"),
    ("Accuver XCAL", "Multi-UE traffic generator (XCAL-MUbox) and drive-test / analysis tools (XCAL, XCAP); Release 16 stated.", "docs/strategy: Vendor Comparison"),
    ("Polaris Networks", "Mobile core software (EPC and a 5G core) together with 4G / 5G test tools: UE, eNB / gNB and core emulation, protocol and load testing. Marketing descriptions only; versions and release levels to verify.",
     "Public product pages; not yet in the Vendor Comparison workbook: verify"),
    ("Mobileum", "Not a core network vendor: roaming (steering, testing, business intelligence), signalling security and firewalls for SS7 / Diameter / 5G, fraud and risk management, network analytics and monitoring for operators.",
     "Public product pages; not yet in the Vendor Comparison workbook: verify"),
]

WAVES = [
    (1, "Quick wins on what exists", "Small to medium work packages that lean directly on the SBI library, the load generator, the cluster harness, the Atlas and the admin APIs. Each one is visible to a user within a short build.",
     "B-01 B-02 B-04 B-06 B-07 B-08 B-14 B-15 C-01 C-02 C-03 D-02 E-06 F-01 F-02 F-07 G-01 A-03 A-05 I-05"),    (2, "Differentiators", "Features where the shared codebase between product and tester, the differential oracle and the conformance matrix give us something others do not offer together.",
     "A-02 A-09 A-14 B-03 B-05 B-09 B-10 B-11 B-12 B-13 C-05 C-06 C-07 D-04 D-05 D-06 F-03 F-04 F-06 G-04 H-02 I-01 I-02 C-08"),
    (3, "Strategic builds", "Larger work that needs a design, hardware or a partner but changes what we can sell: analytics, roaming, HA, fast path, HSM, policy engine.",
     "A-01 A-04 A-06 A-10 A-13 A-17 C-04 D-01 D-03 E-01 E-02 E-03 E-04 E-05 F-05 G-02 G-03 H-01 H-03 H-04 I-04 A-20 B-16"),
    (4, "Market-led", "Pursue when a customer or a market asks: 4G interworking, non-3GPP access, MBS, NTN, location, LI, FWA, public safety, licensing.",
     "A-07 A-08 A-11 A-12 A-15 A-16 A-18 A-19 H-05 H-06 I-03"),
]

RUBRIC = [
    ("Feasibility: High", "Builds on code and tests we already have; no new external dependency or hardware; a clear specification or an obvious design."),
    ("Feasibility: Medium", "Needs a pinned specification we do not have yet, a design decision, a partner component, or a second environment to test in; the foundation is there."),
    ("Feasibility: Low", "Needs substantial new technology (IPsec / IKE, positioning protocols, multicast), scarce hardware, or a stack we would have to adopt; worth it only when a market asks."),
    ("Effort S", "A work package inside one function or tool: a few components, tests and a document."),
    ("Effort M", "A work package spanning two or three components, with new tests in the cluster harness and the conformance matrix."),
    ("Effort L", "A new function or a new subsystem with its own design record, several test layers and documentation."),
    ("Effort XL", "A program of several work packages with external dependencies; broken down in its own plan before starting."),
    ("Wave", "1 = quick wins, 2 = differentiators, 3 = strategic, 4 = market-led. A suggestion for ordering, not a schedule: no dates are given on purpose."),
    ("Peer columns", "Taken from public product pages and descriptions (see docs/strategy/3GPP_Release_and_Vendor_Comparison.xlsx) and general knowledge. Marketing statements, not test results; '?' means to verify with the vendor."),
]


def style_header(ws, row, ncols):
    for c in range(1, ncols + 1):
        cell = ws.cell(row=row, column=c)
        cell.font, cell.fill, cell.alignment, cell.border = HDR_FONT, HDR_FILL, CENTER, BORDER


def write_table(ws, start_row, headers, rows, widths, wrap_cols=None):
    for i, h in enumerate(headers, 1):
        ws.cell(row=start_row, column=i, value=h)
    style_header(ws, start_row, len(headers))
    for r, row in enumerate(rows, start_row + 1):
        for c, v in enumerate(row, 1):
            cell = ws.cell(row=r, column=c, value=v)
            cell.alignment = WRAP
            cell.border = BORDER
            cell.font = Font(name="Calibri", size=10)
            if (r - start_row) % 2 == 0:
                cell.fill = PatternFill("solid", fgColor=GREY)
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.freeze_panes = ws.cell(row=start_row + 1, column=3)
    ws.auto_filter.ref = "A%d:%s%d" % (start_row, get_column_letter(len(headers)), start_row + len(rows))


def title(ws, text, sub=None):
    ws["A1"] = text
    ws["A1"].font = Font(bold=True, size=16, color=NAVY, name="Calibri")
    if sub:
        ws["A2"] = sub
        ws["A2"].font = Font(italic=True, size=10, color="555555", name="Calibri")
        ws["A2"].alignment = Alignment(wrap_text=True, vertical="top")


def main():
    wb = Workbook()

    # ---- Summary
    ws = wb.active
    ws.title = "Summary"
    title(ws, "g5c 5G core: opportunities to extend the product", "Everything we can build next, set against Open5GS, free5GC and the commercial core and test products. Peer information is indicative (public descriptions); verify before external use.")
    ws.merge_cells("A2:F2")
    ws.row_dimensions[2].height = 34
    cats = {}
    for r in B:
        cats.setdefault(r[1], []).append(r)
    feas = {"High": 0, "Medium": 0, "Low": 0}
    for r in B:
        feas[r[10]] += 1
    rows = [("Features in the backlog", len(B)), ("Categories", len(cats)), ("Peers compared", len(PEERS)), ("Capabilities in the matrix", len(MATRIX)),
            ("Feasibility High / Medium / Low", "%d / %d / %d" % (feas["High"], feas["Medium"], feas["Low"])),
            ("Wave 1 (quick wins on what exists)", sum(1 for r in B if r[13] == 1)), ("Wave 2 (differentiators)", sum(1 for r in B if r[13] == 2)),
            ("Wave 3 (strategic)", sum(1 for r in B if r[13] == 3)), ("Wave 4 (market-led)", sum(1 for r in B if r[13] == 4))]
    ws["A4"], ws["B4"] = "Measure", "Value"
    style_header(ws, 4, 2)
    for i, (k, v) in enumerate(rows, 5):
        ws.cell(row=i, column=1, value=k).border = BORDER
        c = ws.cell(row=i, column=2, value=v)
        c.border, c.alignment = BORDER, Alignment(horizontal="center")
    r0 = 5 + len(rows) + 1
    ws.cell(row=r0, column=1, value="Backlog by category").font = Font(bold=True, color=NAVY, size=12)
    ws.cell(row=r0 + 1, column=1, value="Category")
    ws.cell(row=r0 + 1, column=2, value="Features")
    ws.cell(row=r0 + 1, column=3, value="High feasibility")
    ws.cell(row=r0 + 1, column=4, value="Wave 1")
    style_header(ws, r0 + 1, 4)
    for i, (cat, rs) in enumerate(cats.items(), r0 + 2):
        for c, v in enumerate([cat, len(rs), sum(1 for r in rs if r[10] == "High"), sum(1 for r in rs if r[13] == 1)], 1):
            cell = ws.cell(row=i, column=c, value=v)
            cell.border = BORDER
            if c > 1:
                cell.alignment = Alignment(horizontal="center")
    r1 = r0 + 2 + len(cats) + 1
    ws.cell(row=r1, column=1, value="Where we can stand out (themes)").font = Font(bold=True, color=NAVY, size=12)
    themes = [
        "One codebase for the core and the tester: our codecs, state machines and specs are shared, so a core-test tool and a core product come from the same work (I-01, B-01 to B-15).",
        "Proof built in: a conformance matrix tied to spec clauses, differential comparison with Open5GS, fuzzing and sanitizer runs, all re-runnable by a customer (B-06, I-02, D-05).",
        "Security as a feature: mutual TLS, OAuth2, hot certificate renewal, key rotation, signed releases and an evidence pack (D-01 to D-06).",
        "Debuggability of an encrypted core: TLS key log, end-to-end tracing, ladders from captures, a failure classifier (C-01 to C-05).",
        "A device-less lab and training kit that boots in minutes (B-10, G-04, F-07).",
        "Operations that feel finished: console, importers for Open5GS / free5GC subscribers, CDRs, Prometheus / Grafana / runbooks, upgrade and rollback (F-01 to F-07, A-02).",
    ]
    for i, t in enumerate(themes, r1 + 1):
        c = ws.cell(row=i, column=1, value="• " + t)
        c.alignment = WRAP
        ws.merge_cells(start_row=i, start_column=1, end_row=i, end_column=6)
        ws.row_dimensions[i].height = 32
    r2 = r1 + len(themes) + 2
    ws.cell(row=r2, column=1, value="Sheets").font = Font(bold=True, color=NAVY, size=12)
    for i, (n, d) in enumerate([("Backlog", "every feature with peers, what we have, what we can add, feasibility, effort and wave"), ("Matrix", "capability by product, indicative"),
                                ("Foundations", "the APIs and systems already in place that the feasibility ratings lean on"), ("Waves", "a suggested order, grouped"), ("Peers", "who the peers are and where the information comes from"),
                                ("Rubric", "how to read feasibility, effort and wave")], r2 + 1):
        ws.cell(row=i, column=1, value=n).font = Font(bold=True)
        ws.cell(row=i, column=2, value=d)
        ws.merge_cells(start_row=i, start_column=2, end_row=i, end_column=6)
    ws.column_dimensions["A"].width = 44
    for col in "BCDEF":
        ws.column_dimensions[col].width = 20

    # ---- Backlog
    wb_ws = wb.create_sheet("Backlog")
    title(wb_ws, "Backlog: what we can build", "Filter by category, feasibility or wave. 'Offered by' uses: O Open5GS, F free5GC, L Spirent Landslide, A Amarisoft, D Artiza DuoSIM, V Valid8, T Viavi TM500, X Accuver XCAL, P Polaris Networks, M Mobileum.")
    wb_ws.merge_cells("A2:N2")
    rows = []
    for (id_, cat, name, what, peers, evidence, today, found, ours, who, feas_, eff, needs, wave) in B:
        letters = ("" if peers == "-" else peers) + PEER_ADD.get(id_, "")
        names = ", ".join(PEER_KEY[ch] for ch in letters) if letters and len(letters) <= len(PEER_KEY) and all(ch in PEER_KEY for ch in letters) else ""
        peer_text = names if names else "No peer documented"
        rows.append((id_, cat, name, what, peer_text, evidence, BUILT.get(id_, today), found, ours, who, feas_, eff, needs, wave))
    write_table(wb_ws, 4, HEAD_B, rows, [7, 18, 34, 42, 30, 34, 32, 44, 56, 22, 12, 11, 30, 9])
    last = 4 + len(rows)
    wb_ws.conditional_formatting.add("K5:K%d" % last, CellIsRule(operator="equal", formula=['"High"'], fill=PatternFill("solid", bgColor="C6EFCE", fgColor="C6EFCE")))
    wb_ws.conditional_formatting.add("K5:K%d" % last, CellIsRule(operator="equal", formula=['"Medium"'], fill=PatternFill("solid", bgColor="FFEB9C", fgColor="FFEB9C")))
    wb_ws.conditional_formatting.add("K5:K%d" % last, CellIsRule(operator="equal", formula=['"Low"'], fill=PatternFill("solid", bgColor="F8CBAD", fgColor="F8CBAD")))
    dv = DataValidation(type="list", formula1='"High,Medium,Low"', allow_blank=False)
    wb_ws.add_data_validation(dv)
    dv.add("K5:K%d" % last)
    dv2 = DataValidation(type="list", formula1='"S,M,L,XL"', allow_blank=False)
    wb_ws.add_data_validation(dv2)
    dv2.add("L5:L%d" % last)
    for r in range(5, last + 1):
        wb_ws.row_dimensions[r].height = 96

    # ---- Matrix
    mx = wb.create_sheet("Matrix")
    title(mx, "Capability matrix (indicative)", "F = offered, P = partial / variant / optional, - = not offered or not documented, ? = to verify. 'g5c with the backlog' is what the Backlog sheet would make true if built.")
    mx.merge_cells("A2:M2")
    rows = []
    for cap, vals in MATRIX:
        v = vals.split()
        rows.append([cap] + v)
    write_table(mx, 4, MATRIX_HEAD, rows, [52] + [14] * 12)
    mx.freeze_panes = "B5"
    last = 4 + len(rows)
    for c in range(2, 14):
        for r in range(5, last + 1):
            mx.cell(row=r, column=c).alignment = CENTER
    rng = "B5:M%d" % last
    mx.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"F"'], fill=PatternFill("solid", bgColor="C6EFCE", fgColor="C6EFCE")))
    mx.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"P"'], fill=PatternFill("solid", bgColor="FFEB9C", fgColor="FFEB9C")))
    mx.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=['"?"'], fill=PatternFill("solid", bgColor="DDEBF7", fgColor="DDEBF7")))
    mx.row_dimensions[4].height = 48
    mx.cell(row=last + 2, column=1, value="Counts of F (offered)").font = Font(bold=True)
    for c in range(2, 14):
        L = get_column_letter(c)
        cell = mx.cell(row=last + 2, column=c, value='=COUNTIF(%s5:%s%d,"F")' % (L, L, last))
        cell.alignment, cell.font = CENTER, Font(bold=True)
    mx.cell(row=last + 3, column=1, value="Counts of F or P").font = Font(bold=True)
    for c in range(2, 14):
        L = get_column_letter(c)
        cell = mx.cell(row=last + 3, column=c, value='=COUNTIF(%s5:%s%d,"F")+COUNTIF(%s5:%s%d,"P")' % (L, L, last, L, L, last))
        cell.alignment, cell.font = CENTER, Font(bold=True)

    # ---- Foundations
    fo = wb.create_sheet("Foundations")
    title(fo, "Systems and APIs already in place", "What the feasibility ratings lean on. The Backlog sheet names these in 'What we already have to build on'.")
    fo.merge_cells("A2:D2")
    write_table(fo, 4, ["Ref", "System / API", "What it is today", "What it gives the backlog"], FOUNDATIONS, [10, 36, 70, 70])
    for r in range(5, 5 + len(FOUNDATIONS)):
        fo.row_dimensions[r].height = 62

    # ---- Waves
    wv = wb.create_sheet("Waves")
    title(wv, "Suggested order", "Grouped by what each wave needs. No dates: a wave is a bundle, ordered by dependency and value.")
    wv.merge_cells("A2:D2")
    byid = {r[0]: r for r in B}
    rows = []
    for n, name, desc, ids in WAVES:
        listing = "; ".join("%s %s (%s, %s)" % (i, byid[i][2], byid[i][10], byid[i][11]) for i in ids.split())
        rows.append((n, name, desc, listing))
    write_table(wv, 4, ["Wave", "Name", "What it is", "Features (feasibility, effort)"], rows, [8, 28, 60, 140])
    for r in range(5, 5 + len(rows)):
        wv.row_dimensions[r].height = 190
    wv.freeze_panes = "C5"

    # ---- Peers
    pe = wb.create_sheet("Peers")
    title(pe, "Peers and sources", "Public statements only. The full table with sources and confidence is in docs/strategy/3GPP_Release_and_Vendor_Comparison.xlsx (sheet Vendor Comparison).")
    pe.merge_cells("A2:C2")
    write_table(pe, 4, ["Peer", "What it is (as publicly described)", "Source"], NOTES_PEERS, [34, 110, 40])
    for r in range(5, 5 + len(NOTES_PEERS)):
        pe.row_dimensions[r].height = 40
    pe.freeze_panes = "B5"

    # ---- Rubric
    ru = wb.create_sheet("Rubric")
    title(ru, "How to read the sheet")
    write_table(ru, 3, ["Term", "Meaning"], RUBRIC, [26, 130])
    for r in range(4, 4 + len(RUBRIC)):
        ru.row_dimensions[r].height = 36
    ru.freeze_panes = "A4"

    for sh in wb.worksheets:
        sh.sheet_view.showGridLines = False
        sh.sheet_properties.tabColor = TEAL if sh.title != "Summary" else NAVY
    OUT.parent.mkdir(parents=True, exist_ok=True)
    wb.save(OUT)
    print("wrote", OUT, len(B), "features,", len(MATRIX), "matrix rows")


if __name__ == "__main__":
    main()
