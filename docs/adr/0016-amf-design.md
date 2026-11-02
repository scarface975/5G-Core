# ADR-0016: AMF design - connection objects with ordered mailboxes, one mutex per UE context, blocking SBI calls, N2 over kernel SCTP

Status: Accepted (2026-10-13)

## Context
The AMF terminates three protocols at once: NGAP towards the gNBs (SCTP, one association per gNB, many UE associations on it), NAS towards the UEs (security
contexts, retransmission timers, procedures that span several messages) and the SBI towards AUSF, UDM, PCF, SMF and NRF. Events for one UE come from three
directions that are not synchronised with each other: the gNB (NGAP), the other NFs (N1N2 transfers, notifications) and the AMF's own timers. A procedure
(registration) blocks on SBI answers in the middle of a NAS exchange, and the AMF must keep serving thousands of other UEs while it waits.

## Decision
1. **N2 is a kernel one-to-one SCTP endpoint** (PPID 60, RFC 6458 ancillary data for the stream and PPID) with one reader thread on epoll. The reader decodes
   the NGAP PDU, answers the non-UE-associated procedures (NG Setup, RAN Configuration Update, NG Reset, Error Indication) itself and routes UE-associated
   messages by AMF-UE-NGAP-ID to the **connection object** (the "RAN UE") that owns that identifier. A gNB slot is `(index, generation)`: a send to a slot whose
   association was replaced fails instead of reaching a different gNB.
2. **A connection has a mailbox and runs on a worker pool, one batch at a time.** Messages of one UE association are therefore handled in order and the pool
   serves many UEs concurrently. Timers (T3550, T3560, T3570, T3555, T3522, the release guard, handover timers) are posted to the same mailbox, so a timer never
   races the message it is about.
3. **A UE context is guarded by its own mutex, held for the whole handler.** Whoever touches the context (a connection handler, an SBI server thread for an
   N1N2 transfer or a callback, a UE timer) locks it. A connection that is not yet bound to a UE touches no shared state; it is bound after identification
   (GUTI lookup or the SUPI the AUSF returns) and the binding keeps the mutex until the handler returns. Blocking SBI calls under that mutex delay only that UE.
   Lock order is gNB send mutex, then the table mutex; UE mutexes are never held while taking another UE's.
4. **State is split by lifetime.** The UE context holds what outlives a connection: GUTI, native security context (KAMF, algorithms, COUNTs), subscription
   data, allowed NSSAI, PDU session references (SM context URI, DNN, S-NSSAI, active / releasing), pending N1N2 transfers. The connection holds the procedure:
   timers and retries, the registration request being processed, the authentication run, the retransmission buffer, handover state. A context that never became
   a registration is removed when its connection is released.
5. **Security follows TS 33.501 literally.** KAMF from KSEAF with the ABBA; NAS keys from the selected algorithms (NIA2; NEA2 then NEA0 by configuration; SNOW 3G
   and ZUC are refused at configuration time, ADR-0012); the new context is used for the security mode command (SHT 3) and becomes current when the complete
   verifies; KgNB is derived from the uplink NAS COUNT of the security mode complete, or of the initial message when no security mode control ran; the next-hop
   chain starts from KgNB and its first value is never sent (Annex A.10). The 8-bit sequence number is extended to a COUNT as TS 24.501 4.4.3.1 describes; a
   message below the expected COUNT is a replay and is dropped.
6. **Mobility is relayed, not reimplemented.** Path switch and N2 handover are driven by the AMF but the user plane moves through the SMF
   (`n2SmInfoType` PATH_SWITCH_REQ / HANDOVER_REQUIRED / HANDOVER_REQ_ACK and `hoState`), which updates the UPF; the SMF was extended for this (ADR-0015).
   The target leg of an N2 handover is a second connection object bound to the same UE (`ho_conn`); at Handover Notify it becomes the UE's association and the
   source leg is released.
7. **Idle mode is first class.** A released connection leaves the UE registered with its sessions deactivated at the SMF; N1N2 transfers for it are queued and
   a page is started (T3513, bounded attempts); the service request delivers the queue in the context setup. The mobile reachable timer (T3512 plus a grace)
   ends in implicit de-registration.
8. **Persistence is a snapshot of the registered contexts** (JSON, atomic rename, coalesced), restored in CM-IDLE. The downlink COUNT is advanced on restore so a
   message after a crash is never below what the UE expects. This is the interface a shared context store would plug into (stateless-ready); no shared store is built.
9. **Everything is verified with independent peers.** UERANSIM drives the AMF in the oracle scenarios; the in-process suite scripts a gNB (real SCTP) and a UE
   that derives its own keys, against the real UDM, AUSF shim, PCF, SMF and UPF runtime. The harness found two interop defects the unit tests could not (an
   NrLocation without ncgi, the NRF's `snssais` encoding).

## Consequences
- A blocking SBI call occupies a pool worker; the worker count (`amf.workers`) is the concurrency limit for slow peers. Revisit with measurements in Phase 8 (an
  event-driven client with continuations would remove the limit at the cost of splitting every procedure).
- One AMF per PLMN: no relocation, no AMF set, no UE context transfer (listed as gaps). A GUTI of another AMF is answered with an identity request.
- The registration area is the whole TA list of the AMF; there is no per-UE area, no mobility restrictions and no emergency services.
- Persisted contexts keep the downlink COUNT only approximately (see 8); a UE that is far ahead falls back to a registration with authentication.

## Alternatives considered
- One thread per UE: simple, but thousands of idle contexts would hold thousands of threads.
- A global lock: trivial and correct, serialises every SBI round trip of every UE.
- Event loop with continuations for the SBI client: best scaling; every procedure becomes a state machine across callbacks, the cost the SMF design (ADR-0015)
  already declined; the pool is the scaling knob until measurements say otherwise.
- Hosting the user plane relocation inside the AMF: not the AMF's function; the SMF owns the N4 session.
