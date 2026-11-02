# Pilot and field trial plan

Proposal for agreement with a lab or partner network. Nothing here has been agreed; dates are left open on purpose (no timelines by decision). It also carries the assurance work of Phase 8 that needs a third
party or time (an external penetration test, the long soak, a commercial tester).

## Goals
1. Show that the core registers and carries real devices and a commercial RAN for a sustained period without operator intervention.
2. Measure the capacity and latency SLOs of `docs/ops/slo.md` on the partner's hardware, and the user plane against the target set by ADR-0014.
3. Close the external security assessment with no critical or high finding open.
4. Collect operator feedback on provisioning, operations and documentation, and feed it into the backlog.

## Scope
| Item | In | Out |
|---|---|---|
| Access | SA, N2 / N3 with a commercial gNB (the partner's), a few commercial UEs / SIMs, the srsRAN-based lab for scripted cases | NSA, EPC, non-3GPP |
| Core | the twelve functions of 0.9.0-rc1 (or its successor), one site | roaming, multi-site, shared-state HA |
| Services | internet DNN, one or two slices | IMS / voice (needs a P-CSCF and an IMS core of the partner) |
| Charging | the CDR file of the SMF handed to the partner's mediation | Nchf online charging |

## Entry criteria (all met before the pilot starts)
* Release candidate with the regression green on the full matrix, release archive verified (`tools/release.sh`).
* Counsel's review of `docs/legal/patent-frand-review.md` recorded and the licence terms agreed.
* The partner's test SIMs provisioned (`docs/admin-guide.md`), the network plan agreed (addresses, TACs, PLMN, firewalling of N4 and N2, transport protection for N2 / N3 / N4).

## Activities
| # | Activity | Evidence | Needs |
|---|---|---|---|
| 1 | Install on the partner host(s) with `deploy/install.sh`, certificates per function | `install.md` steps pass; `g5c-cluster.sh`-style smoke test | host, root access |
| 2 | Interop: the partner's gNB and UEs register, get sessions, pass traffic; handover with two cells | pcaps (`tools/g5c-capture`), CDRs | RAN |
| 3 | Conformance scenarios S1 to S8 of the oracle suite re-run on the partner's RAN, and the same scenarios with a commercial core-test tool (Keysight / Spirent class) or the partner's lab | report | tool or lab |
| 4 | Soak: 7 days of attach / session / detach waves (`g5c-cluster.sh ns soak` against the real RAN's load) with RSS and descriptor sampling | flat curves, no restart, alerts quiet | host that stays up |
| 5 | Load to the target: registrations per second and sessions per second per `slo.md`, user plane throughput on the partner's NIC (AF_XDP work item) | numbers against the SLOs | NIC, a second host |
| 6 | Failure drills: kill and restart each function under load, upgrade and rollback, certificate renewal, master key rotation | `runbooks.md` steps work as written | none |
| 7 | External penetration test of the SBI, N2, N4, N3, admin APIs and the host hardening, briefed with `docs/security/threat-model.md` | report; every critical / high finding fixed and retested | third party |
| 8 | Operator feedback sessions on the guides, the CLI, the dashboards, the runbooks | list of changes | partner staff |

## Exit criteria
SLOs met and documented on the pilot hardware; 7 day soak clean; no critical or high security finding open; upgrade and rollback done on the pilot system; the feedback list triaged into the backlog;
the GA-candidate tag created.

## Feedback loop
Every finding becomes an entry in `docs/update.md` with the fix and the test that keeps it fixed, as in the release candidate (the changelog's "Fixed during the release candidate" lists what the
last round found). Support bundles come from `tools/g5c-diag`.

## Risks
Commercial gNBs and UEs have behaviours the open-source RAN does not (timers, optional IEs, malformed but tolerated messages): plan for fixes in the codecs. The user plane target needs hardware that
may not be in the pilot lab. Charging and lawful-intercept requirements depend on the market: agree the scope before the pilot starts.
