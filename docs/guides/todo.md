# To do

What can be built with what is here today, and what waits. Effort is engineering time for one person, rough (±50 %). `known-gaps.md` says what each finished row still lacks; this page orders the work.

## Possible now (nothing missing: specs pinned, tools present)
| # | Work | Row | Effort |
|---|---|---|---|
| 1 | Connect the ORAN_emulator project (its N2 stack as the gNB and UE side) to this core and prove the whole chain: NG Setup, registration with authentication, PDU session, GTP-U through the UPF, release | proof of the system | 2-3 days |
| 2 | SMF N4 retransmission timers under time warp | B-12 | 3-5 days |
| 3 | Reload of `policy.scripts` by SIGHUP and a dry-run tool for conditions | G-02 | 3-5 days |
| 4 | Hook for authentication vectors (the UDM asks a program) and hook points in more functions | G-03 | 1-2 weeks |
| 5 | SEPP N32-c handshake and security capability negotiation (TS 29.573 is pinned) | A-06 | 2-3 weeks |
| 6 | More procedure rules for the conformance monitor (mobility, paging, release) | C-04 | 1-2 weeks |
| 7 | Device groups known to the UDM (group provisioning and per-group policy at the PCF) | H-04 | 2-3 weeks |
| 8 | PM counters named after TS 28.552 measurements, exported as files, and a read-only REST view after TS 28.532 | F-05 | 3-4 weeks |
| 9 | UE policy (URSP) delivery: PCF UE policy association (TS 29.525), UE policy container in a DL NAS transport, URSP encoding (TS 24.526) | A-04 | 4-6 weeks |

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
