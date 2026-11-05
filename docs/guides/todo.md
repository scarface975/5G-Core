# To do

What can be built with what is here today, and what waits. Effort is engineering time for one person, rough (±50 %). `known-gaps.md` says what each finished row still lacks; this page orders the work.

## Built in this round
| Work | Row | Result |
|---|---|---|
| The ORAN emulator against the whole core | proof | `deploy/oran/prove.sh`; `docs/guides/oran-emulator.md` |
| N4 request timer under time warp | B-12 | the T1 wait runs on the warped clock; tested |
| Reload of `policy.scripts` by SIGHUP; dry run | G-02 | `g5c-policy-eval`; the rest of `policy` still needs a restart |
| Authentication-vector hook | G-03 | `auth_hook` at the UDM; the other functions have no hook |
| SEPP N32-c security capability negotiation | A-06 | exchange-capability both ways, `sepp.handshake`; not the parameter exchange or PRINS |
| More procedure rules | C-04 | six rules (mobility, service request, release request, reset, N4 modification) |
| Device groups for policy | H-04 | `groups` in the subscriber policy and `memberof` in scripts at the PCF; the UDM side is open |
| PM counters after TS 28.552, files and a read-only view | F-05 | `g5c-pm`, 19 measurements; not XML files or the TS 28.532 services |
| Device groups in the UDM | H-04 | `groups` in the UDM configuration, Nudm_SDM GetGroupIdentifiers, `internalGroupIds` in am-data, reloadable |
| N4 heartbeat, association retry and lost-after timers under time warp | B-12 | on the virtual clock |
| Hooks in the AMF and the PCF | G-03 | `amf.event_hook`, `decision_hook`; proven live in the ORAN run |
| Reload of the whole `policy` section | G-02 | default, DNN profiles, rfsp, usage monitoring and scripts |
| Per-S-NSSAI subcounters of the registration measurements | F-05 | `RM.RegInitReq.<snssai>` and the others |
| SEPP parameter exchange, N32-f terminate and error report | A-06 | answered 501: they belong to PRINS (TS 29.573 5.2.3) and the SEPP selects TLS only |

## Possible now, not built yet
| # | Work | Row | Effort |
|---|---|---|---|
| 1 | UE policy (URSP) delivery: PCF UE policy association (TS 29.525), UE policy container in a DL NAS transport, URSP encoding (TS 24.526). It can be coded, but nothing here decodes it on the UE side, so it could not be shown working end to end | A-04 | 4-6 weeks |
| 2 | PRINS for the SEPP (JWE/JWS protected N32-f, modification policy, parameter exchange; today the SEPP selects TLS only) | A-06 | 4-8 weeks |

## Waiting
| Work | Row | Waits for |
|---|---|---|
| HSM / PKCS#11 | D-01 | SoftHSM or an HSM and the PKCS#11 headers installed (WSL has no sudo) |
| IPsec / DTLS on N2, N3, N4 | D-03 | strongSwan installed; native DTLS for PFCP is a design of its own |
| UPF fast path | E-01 | a NIC with AF_XDP / DPDK support |
| Multi-core UPF | E-02 | a redesign of the UPF data path (sessions sharded across workers, locks on the shared state) |
| Shared-state high availability | E-03 | a design for the state store under AMF and SMF |
| UL-CL / branching | A-10 | PCF reading traffic influence, SMF handling DNAI, a second UPF |
| Multi-PLMN / SNPN | A-13 | changes in every function's identity and key handling |
| IMS / VoNR | A-17 | an IMS core as a peer |
| Edge application hooks | H-03 | a pinned API (Rel-17 EAS deployment is not in the Release 16 set) |
| NSSAA, RedCap, inter-AMF mobility, offline charging formats, Helm and an operator, SDR radio, a million subscribers | A-09 A-14 B-09 A-02 F-04 B-10 B-03 | specs beyond Release 16, a second AMF, hardware, or a container runtime |
| Licence, support offer, installers | I-01 | commercial decisions |
