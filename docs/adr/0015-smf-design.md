# ADR-0015: SMF design - blocking handlers over a reference-counted session table, a deferred N1N2 transfer, an N4 client with its own receive thread

Status: Accepted (2026-10-09, first half); extended 2026-10-12 with section "Second half" below

## Context
The SMF sits between four peers that all speak differently: the AMF (multipart SBI with NAS and NGAP bytes inside), the UDM and PCF (JSON SBI),
the UPF (PFCP over UDP) and, through the AMF, the UE and the gNB (5GSM and NGAP transfer containers). The failure that matters most is a
half-created session: an address taken, a policy association open, a UPF session installed, and no way back.

## Decision
1. **Handlers are blocking functions on the SBI server's worker pool** (as in every other NF here). Create SM Context calls UDM, PCF and the UPF
   in sequence and answers once the user plane exists. Every step that can fail has exactly one way out: `create_abort()` for a session that never
   reached the table, `sess_teardown()` for one that did. Both give back the N4 session, the PCF association, the UDM registration and the address.
2. **The session table holds reference-counted sessions with a mutex each.** A lookup returns the session locked and referenced; removal marks it
   dead, unlinks it and drops the table's reference; the memory is freed by whoever drops the last one. A second establishment of the same PDU session
   id replaces the first (TS 23.502 4.3.2.2.1). Nothing holds the table lock across a network call.
3. **The accept travels after the 201.** The SMF answers Create SM Context first and a deferred job (one worker thread) then sends the PDU Session
   Establishment Accept and the N2 setup request in an N1N2MessageTransfer to the AMF, after a short configurable pause so the AMF has processed the
   201. If the AMF refuses the transfer the session is torn down and the AMF is told with an SM context status notification. The AMF is reached at the
   host of the `smContextStatusUri` it sent (or `smf.amf.uri`); NRF discovery by `servingNfId` comes with Phase 7.
4. **N4 is a client with its own socket, receive thread and heartbeat thread.** Requests are matched to responses by sequence number and peer, and
   retransmitted (T1/N1). The same socket carries what the UPF initiates: heartbeats, an association it starts, and Session Reports, which are
   answered with the right SEID. The Recovery Time Stamp of the association response and of every heartbeat response detects a restarted UPF; a UPF
   that stops answering is marked down and is not selected.
5. **Rules follow the session's flows.** Flow 0 is the default QoS flow (QFI 1). Every distinct QoS data of the PCC decision becomes a flow with
   the next QFI. The PFCP ids are derived from the flow position, so later procedures can address rules without a table. The downlink FAR starts as
   DROP and becomes FORW with the gNB's tunnel; deactivation sets BUFF|NOCP (the BAR exists from the start). The Flow Description of a PCC rule is copied
   unchanged into the uplink and the downlink PDR and the UPF swaps it for ACCESS (TS 29.244 5.2.1A.2A, read from the pinned text). Session AMBR is a QER shared by every PDR of the session.
6. **Policy decisions are narrowed on the way in.** One session rule is applied, IPv4 flow descriptions are accepted (they are what a NAS packet filter can
   express), and a decision that cannot be honoured is refused as a whole rather than half applied.
7. **Every bit layout is taken from the pinned specification text** (TS 24.501 v16.15.0, TS 24.008 v16.7.0, TS 38.413, TS 29.244) and checked a second
   way: byte-exact expectations in the unit tests, the UPF engine as the consumer of the generated N4 messages, UERANSIM as the consumer of the N1/N2
   bytes, and a differential analysis of the request sequence and information elements against Open5GS's own SMF.

## Consequences
- The oracle scenarios S1-S3 pass against this SMF with Open5GS's AMF and UERANSIM, on our UDM, PCF and UPF.
- A crash loses all contexts: they live in memory (persistence is part of the second half).
- IPv6 and IPv4v6 are allocated and signalled, but no router advertisement exists and the UPF has no IPv6 user plane; the matrix says so.
- The deferred transfer is the one place where order is a convention (response before transfer); a pause of `n1n2_delay_ms` (default 10) enforces it
  against a fast AMF. The correct fix is the AMF side's handling of an early transfer, which Open5GS's AMF has.

## Alternatives considered
- Event loop (libuv) for the handlers: better for tens of thousands of concurrent creates, but every peer call would need a continuation; the blocking
  model matches the other NFs, is easy to test, and the worker pool is the scaling knob. Revisit with measurements in Phase 8.
- Sending the accept in the 201 body: not allowed for the initial request (the AMF has to know the context reference first).

## Second half (2026-10-12)
8. **Rules have identities of their own.** Flows carry a QER id and a QFI, PCC rules a QRI and PDR ids, assigned when the decision is read and kept stable across
   updates (`smf_policy_assign_ids`): an unchanged rule keeps its ids, a changed rule is removed and recreated under fresh ones, a flow's QFI is not reused in the same
   step. A policy update is a diff between two such models, so the N4 modification, the NAS command and the N2 transfer are built from the same comparison.
9. **The UPF is modified first.** For a PCF update the UPF change is made before the UE and the gNB are told; if it fails nothing else happens and the PCF gets a
   500. A failure to deliver the command afterwards is logged: the user plane already enforces the new policy, which is the safe side.
10. **A lost user plane is released towards the user.** A UPF restart (Recovery Time Stamp) or `lost_after` seconds of silence send the release command to the UE
    (PTI 0) and the resource release to the gNB through the AMF, then clean PCF, UDM and the pool without a PFCP deletion. A network-requested release that leaves the
    UPF reachable waits for the UE's complete, bounded by a timer on the same delayed-job queue as everything else deferred.
11. **Persistence is a snapshot, not a log.** The state file is rewritten atomically (coalesced) after each change and read back before the first association.
    Restoring must also keep the SMF's own Recovery Time Stamp: a UPF drops the sessions of a peer whose stamp changed (found by the test). The stamps of the UPFs are
    stored too, so a UPF that restarted while the SMF was down is noticed at the first association.
12. **IPv6 router advertisement through the UPF**, as TS 29.244 allows: a PDR matching the router solicitation forwards it to the SMF (FAR to the control plane with
    GTP-U to our address and a per-session TEID), a PDR for packets from the control plane returns the advertisement through the downlink FAR. The match uses
    `to any`: `to assigned` cannot match a link-local source (found by the test).
13. **Discovery of the AMF** is Nnrf_NFDiscovery by the `servingNfId`, cached for a minute, with the status URI's host as the fall-back; UPFs stay configured.

Not done, stated in the matrix: UE-requested modification, charging, ATSSS, Ethernet / unstructured session types, SSC modes 2/3, handover, OAuth2.
