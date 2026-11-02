# ADR-0022: NEF design (Phase 7, fifth function)

Status: Accepted (2026-10-23)

## Decision
- **Pinned sources.** TS 29.522 v16.18.0 (the northbound APIs), TS 29.122 v16.19.0 (the T8 APIs they build on: MonitoringEvent, AsSessionWithQoS, the common data types and the
  procedures of the SCEF that TS 29.522 applies to the NEF), TS 29.514 v16.23.0 (Npcf_PolicyAuthorization, the N5 reference point) and TS 29.591 v16.7.0 (Nnef services, pinned but
  not implemented, see the gaps). `tools/gen_nef_api.py` writes `nf/nef/src/api_schemas.gen.c` and `api_ids.gen.h` (234 schemas) from the OpenAPI files; bodies are validated by
  the shared `libs/oaschema`. `python3 tools/gen_nef_api.py --check` fails when the committed tables are stale.
- **The AF is configuration.** `nef.afs` lists the application functions: identifier (the `{afId}` of the URIs), bearer token (file or environment variable, 16 characters at
  least; `no_auth: true` is the explicit development switch), the APIs it may use, the QoS references it may name, the hosts its notification destinations may name, a limit
  on its subscriptions. A notification destination outside the AF's hosts is refused (403): the NEF never POSTs to an address an AF merely names (no server-side request forgery).
  OAuth2 tokens of the NRF instead of the static bearer are the planned pass over all functions (NRF-GAP-04).
- **TrafficInfluence** (TS 29.522 5.4, 4.4.7.3): a request that is not identified by the UE's address is stored as TrafficInfluData (TS 29.519 6.2.6.2.2) in the UDR with
  `PUT /application-data/influenceData/{id}`; GPSI to SUPI by Nudm_SDM id translation (the UDM resolves it from the identity data in the UDR), a request for any UE is stored with
  `interGroupId` `AnyUE`. **The published TS 29.519 file types that member as GroupId, whose pattern rejects `AnyUE` although the text of the specification demands it.** The
  generators and the payload validator apply the amendment listed in `tools/oa_pool.py` (`ANY_UE`); nothing under `docs/specs` is edited. A request identified by the UE's
  address (the PCF path, 4.4.7.2) and a request for a group of UEs are answered 501.
- **MonitoringEvent** (TS 29.122 5.3, 4.4.2; TS 29.522 4.4.2): LOSS_OF_CONNECTIVITY, UE_REACHABILITY and LOCATION_REPORTING for one UE named by an external identifier or an MSISDN.
  The NEF resolves the SUPI (id translation), finds the serving AMF (Nudm_UECM, then the NRF's profile of the AMF instance) and subscribes there with Namf_EventExposure; the AMF's
  reports reach `/nnef-callback/v1/amf-events/{id}` (checked against a correlation identifier the NEF chose) and go to the AF as MonitoringNotification. The one-time request is
  answered with the report itself (200) when the AMF has one; a reached `maximumNumberOfReports` or `monitorExpireTime` removes the subscription at the NEF and at the AMF;
  parameters out of the operator's range are clamped (`max_reports`, `max_lifetime_s`) or refused (403 PARAMETER_OUT_OF_RANGE); event types and features are checked as the
  specification says (EVENT_FEATURE_MISMATCH, EVENT_UNSUPPORTED). The AMF gained what this needs: the LOSS_OF_CONNECTIVITY event (reason UE_DEREGISTERED, or
  MAX_DETECTION_TIME_EXPIRED for the implicit de-registration) and the reachability report when a UE becomes connected.
- **AsSessionWithQoS** (TS 29.122 5.14, 4.4.13; TS 29.522 4.4.9): the NEF is an AF to the PCF. It sends an AppSessionContext with one media component (the AF's flows and its
  `qosReference`, the AuthorizationWithRequiredQoS feature, TS 29.514 4.2.2.32), subscribes to SUCCESSFUL_ / FAILED_RESOURCES_ALLOCATION, keeps the PCF's application session
  identifier, and turns the PCF's notifications into UserPlaneNotificationData (the end of the PDU session is SESSION_TERMINATION and removes the subscription). PUT and PATCH become
  a merge patch of the media component at the PCF (flows that are gone are nulled). The PCF is found through the NRF (`npcf-policyauthorization`).
- **The PCF got N5** (`nf/pcf/src/policyauth.c`): create, read, modify (merge patch), delete, events subscription, notifications and termination. Session binding is by the UE's IPv4
  address (with the DNN, SUPI and S-NSSAI when given: 4.2.2.2); the media components that name a QoS reference of `policy_authorization.qos_references` become PCC rules with that 5QI
  (a GBR 5QI has its bit rates in the reference) and the flows the AF gave; the decision of the SM policy is computed again with those rules and pushed to the SMF as an update
  notification, as every other policy change. Outcome: the SMF's acceptance of the push is SUCCESSFUL_RESOURCES_ALLOCATION, a refusal FAILED_RESOURCES_ALLOCATION (the SMF does not
  yet report rule status). A closed gate (`fStatus` DISABLED) installs no rule.
- **State.** The subscriptions of the NEF (and what it made at other functions) are kept in a state file with a write-behind thread and an atomic replace, like the NSSF's.
  Notifications go out from a worker thread with a bounded queue and retries; the PCF's notifications to the AFs go from threads of their own so that the request that caused them
  is not held up, and `pcf_destroy` waits for them.

## Interop facts that shaped it
Open5GS has no NEF, so the reference peers are the functions behind it: oracle scenario S6 (UERANSIM, our NRF, AUSF, AMF, UDM, UDR, PCF and NEF: traffic influence data in the UDR,
loss of connectivity reported to the AF when the UE de-registers) and S7 (an AF asks for a QoS for a UE with a PDU session; our PCF installs the PCC rule at Open5GS's SMF, and at
ours, and the user plane keeps working). The Nnef_EventExposure service of TS 29.591 reports events of AFs and analytics; nothing in this core produces them, so it is not built.

## Gaps (matrix rows NEF-GAP-*)
No request identified by the UE's address for traffic influence (the PCF's `afRoutReq` and the SMF's traffic steering are not there), no group of UEs (the UDM's group identifier
translation), no subscription at the UDM for a UE that is not registered yet (Nudm_EventExposure is not built), the other monitoring types, PFD management (TS 29.551, not pinned; the SMF
does not read PFDs), Nnef_EventExposure, Nnef_PFDmanagement, Nnef_TrafficInfluence, BSF-based PCF selection (one PCF, or NRF discovery), QoS derived from media types and bandwidths in the
PCF (TS 29.513, not pinned), usage thresholds, sponsored connectivity, QoS monitoring and alternative QoS references of AsSessionWithQoS, Ethernet and IPv6 UEs, websocket notification delivery,
producer-side OAuth2.

## Consequences
The NEF is a small policy-light proxy whose every request is validated, bounded and attributable to an AF; what it does not support is refused with 501 rather than ignored.
