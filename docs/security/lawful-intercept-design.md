# Lawful intercept: interface design (not implemented)

Status: design for scoping with stakeholders (the strategy marks lawful intercept as dependent on the target market). Nothing in this release intercepts traffic; the design shows where it would attach so
that the decision can be made with the cost in front of it.

## Requirements that depend on the jurisdiction (to be settled before any code)
Which regime applies (ETSI TS 102 232 / 3GPP TS 33.126, 33.127, 33.128 in the EU and many others; CALEA / ATIS in the US; national rules elsewhere), which events and content are
intercepted, who may order it, retention, how a warrant is authenticated, and what must be impossible for an operator's staff to see. These are not engineering choices.

## Architecture of TS 33.127 / 33.128, mapped to our functions
| 3GPP element | Role | Where it sits in this core |
|---|---|---|
| LIPF (LI point of control, TS 33.127 6.2) | receives the warrant from the LEMF side, authenticates it, configures the POIs | a new function `lipf`, reachable only from the LI administration network; configuration over its own mutual-TLS interface (LI_X1) |
| POI (point of interception) in the AMF | IRI: registration, de-registration, location, mobility events | the AMF's event hooks that already exist for Namf_EventExposure (`gmm_event`, `events.c`): a POI subscribes to the same internal events for the targeted SUPIs |
| POI in the SMF | IRI: PDU session establishment / modification / release | the SMF's session lifecycle (`sm.c`), the same points where the CDR is written |
| POI in the UDM | IRI: subscriber data change, authentication events (as far as TS 33.127 requires) | the UDM admin and UECM handlers |
| UPF as the CC-POI (TS 33.127 6.5) | content of communication: a copy of the targeted UE's user plane | PFCP duplication: a FAR with `DUPL` and a Forwarding Parameters towards the MDF3 (the PFCP IEs exist: Apply Action DUPL, Duplicating Parameters) |
| MDF2 / MDF3 (mediation and delivery) | formats IRI and CC for the LEMF (ETSI TS 102 232 handover interfaces HI2 / HI3) | a separate process outside the core; the core delivers X2 (IRI) and X3 (CC) in the TS 33.128 formats |

## Interfaces
X1 (configuration: LIPF to POIs): an HTTPS/JSON interface with mutual TLS and its own certificate authority, never on the SBI. X2 (IRI): TCP with TLS to the MDF2, records in the TS 33.128 encoding.
X3 (CC): GTP-U / UDP to the MDF3 (the UPF sends a copy; the target's traffic is not changed).

## Rules the implementation would follow
* The target list lives only in the POIs' memory and the LIPF's store, never in a log, a metric, a configuration of another function or a state file readable by the operators' accounts; the audit log records
  that a warrant was applied, not who the target is.
* Intercepting a UE must not change its service: no added latency on the user plane beyond the copy, no signalling difference the UE or the network could see.
* A POI that cannot deliver (MDF unreachable) buffers within a fixed bound and counts the loss; it never blocks the subscriber's service.
* LI functions are separate processes (separate unit, separate user, no shared files), so a compromise of a core function does not reveal the targets.

## Work to build it (when the market requires it)
LIPF and X1 (new function, certificates), POI hooks in the AMF / SMF / UDM (small: the events exist), CC duplication in the SMF's PFCP rules and the UPF (the UPF already supports FAR duplication in its
rule parser; the forwarding of a copy to a second destination has to be written and measured), the MDF as a separate product or a partner's, and conformance testing with the regulator's or a vendor's
LI test tool. Estimated as a Phase of its own once the jurisdiction is known.
