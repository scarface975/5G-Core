# Known gaps

What is not built or not shown, by area, so nobody has to find it out. The row ids are those of `docs/strategy/Feature_Opportunities.xlsx`, whose "Where we are today" column says the same in more words. Nothing here is a plan with a date.

## Core functions
| Gap | Row | Why it is open |
|---|---|---|
| Slice-specific authentication (NSSAA) with an AAA server | A-09 | Needs an NSSAAF and the EAP exchange through the AMF; the Rel-17 extended rejected NSSAI is not in the pinned NAS tables (Rel-16) |
| RedCap | A-14 | The NGAP tables are Rel-16 and have no RedCap indication |
| Data held for a UE in power saving until it is reachable | A-14 | The transfer is failed with UE_NOT_REACHABLE instead |
| Time-based and event-based charging, rating, offline records in a standard format, the CHF in compose / Kubernetes, the CHF state across a restart | A-02 | Volume quota control is built; the rest is design work |
| A separate NSACF shared by several AMFs | A-09 | Slice limits are counted per function instance |
| UE policy (URSP), SEPP / roaming, edge branching (UL-CL), multi-PLMN and SNPN, IMS / VoNR | A-04 A-06 A-10 A-13 A-17 | Each is a design of its own (wave 3, not started) |

## Test and emulation
| Gap | Row | Why it is open |
|---|---|---|
| Inter-AMF mobility and idle-mode reselection against the running daemons | B-09 | Xn path switch and N2 handover run on the real daemons; AMF relocation needs a second AMF and the context transfer |
| A million subscribers, several hosts | B-03 | `g5c-fanout` does the fan-out; nothing here has more than one machine. The largest real run is 10,000 UEs |
| Real RF with an SDR | B-10 | `g5c-radio-kit sdr` describes it; it has not been run |
| Replay beyond the first authentication; N4 and SBI captures | B-11 | Needs the recorded keys or a UE model |
| The SMF's N4 retransmission timers under time warp | B-12 | Only the AMF timers and the SMF job scheduler are warped |
| Running the security suite against a core that is not ours; SCAS test names | B-13 D-05 | The SCAS documents are not pinned |

## Interoperability
`docs/interop` lists what was run. Nothing else has been: no commercial gNB or O-RAN radio unit, no commercial UE or modem, no free5GC, no other core than Open5GS for the tester. The scenario engine needs the cluster script, so it cannot drive a foreign core; the load generator can (`g5c-tester --foreign`).

## Operations and packaging
| Gap | Row | Why it is open |
|---|---|---|
| Kubernetes: nothing applied, no image built, no Helm chart, no operator | F-04 | No container runtime here |
| Hot reload covers a few sections | F-06 | The rest is listed as restart-required |
| Shared-state high availability, a gNB-side multi-homed association with path failover, autoscaling | E-03 E-04 E-05 | NF sets are in the NRF and the AMF binds several N2 addresses; the rest is not started |
| HSM / PKCS#11, IPsec / DTLS on N2 N3 N4 | D-01 D-03 | Need an HSM (or SoftHSM) and strongSwan; not started |
| UPF fast path (AF_XDP / DPDK), multi-core scaling | E-01 E-02 | Need a NIC and a many-core host |
| OAM interfaces (TS 28.5xx) | F-05 | Not started |
| Policy scripts at the NSSF, reload of policy.scripts by SIGHUP, a dry-run tool | G-02 | The PCF reads them at start |
| Hooks for authentication vectors and for other functions | G-03 | The contract exists (`hook.h`), only the SMF charging record uses it |
| An Nnwdaf SBI function, learned models | A-01 | `g5c-nwdaf` serves statistics over HTTP/1.1 |

## Wave 3 rows not started
A-04 URSP, A-06 SEPP, A-10 edge branching, A-13 multi-PLMN, A-17 IMS, A-20 roaming screening, B-16 roaming scenarios, D-01 HSM, D-03 transport protection, E-01 fast path, E-02 multi-core, E-03 shared-state HA, F-05 OAM, H-03 edge hooks. Built to a first version or partly: A-01, C-04, E-04, E-05, G-02, G-03, H-01, H-04, I-04.
