# ADR-0011: PCF design

Status: Accepted (2026-10-05)

## Decisions
1. **Layered, field-by-field policy resolution.** For each attribute of a session (session AMBR, default QoS, dedicated
   PCC rules) the first value found wins, in this order: per-subscriber DNN profile, per-subscriber default profile,
   configured DNN profile, configured default profile, the values subscribed in the SMF's request (`subsSessAmbr`,
   `subsDefQos`), built-in defaults. An operator can therefore throttle one subscriber's AMBR without touching their QoS.
   The engine (`nf/pcf/src/policy.c`) is pure and unit-tested; validation rejects inconsistent profiles (GBR 5QI without
   rates, rates on non-GBR 5QI, GBR default flow, malformed bit rates, duplicate rule ids).
2. **Policy data lives in the UDR** (`policy-data/ues/{supi}/sm-data`, TS 29.519), not in the PCF, so the PCF stays
   stateless with respect to subscribers. Active associations (`smPolicyId` -> context, last decision) are held in PCF
   memory for now; an external store arrives with HA in Phase 8.
3. **Policy changes are pushed.** An admin change re-evaluates the subscriber's active sessions and sends
   `Npcf_SMPolicyControl_UpdateNotify` only where the decision actually changed; unreachable or rejecting SMFs are
   logged and counted, never fatal. PCF-initiated termination uses the terminate notification.
3a. **Admin API** (`/admin/v1`, bearer token, disabled when no token is configured) is the management interface; it is
   not a 3GPP API.
4. **Schema discipline learned from interop.** OpenAPI arrays with `minItems: 1` must be omitted when empty
   (`triggers`, `policyCtrlReqTriggers`) and mandatory attributes must be present (`suppFeat` in `PolicyAssociation`);
   Open5GS rejects the alternatives. `Location` headers are absolute URIs (ADR-0010).

## Consequences
Policy behaviour is explicit, testable and changeable at run time. Dedicated-flow (PCC rule) decisions are exercised
against a real SMF/UPF; usage monitoring, UE policy (UCU), AF-influenced traffic (N5) and charging triggers remain Phase 7/8.
