# ADR-0018: NRF design (Phase 7, first function)

Status: Accepted (2026-10-15)

## Decision
- **One process, three services** on the NRF's SBI port: Nnrf_NFManagement (`/nnrf-nfm/v1`), Nnrf_NFDiscovery (`/nnrf-disc/v1`) and
  Nnrf_AccessToken (`/oauth2/token`, plus `/oauth2/jwks` as a deployment convenience for the public key). Specification: TS 29.510 Release 16 as pinned.
- **State is a registry in memory** (profiles and status subscriptions) written behind to one JSON state file (whole registry, at most about a tenth of
  a thread: the delay grows with the cost of the write) and restored at start-up with a fresh heart-beat interval for every instance. A relational store
  is not needed for the number of NF instances of a core and would be one more thing to operate. The registry is bounded (`max_profiles`,
  `max_subscriptions`).
- **Profiles are stored as received** (JSON document) plus the few attributes the registry fills in when absent (priority 0, capacity 100, load 0, the
  PLMN of the NRF, the heart-beat timer). Unknown attributes, custom NF types and vendor-specific attributes are kept (TS 29.510 5.2.2.2.2). The services
  are kept in the representation they were registered in and converted on the way out: the `nfServices` array unless the consumer indicates the
  Service-Map feature (`supported-features`, TS 29.510 6.1.9), then the `nfServiceList` map. Open5GS's functions register with the map and read the array,
  so this is not optional.
- **Liveness**: a function that misses `suspend_after` heart-beats becomes SUSPENDED (not returned by discovery, subscribers told); after `purge_after`
  seconds it is removed with NF_DEREGISTERED. A heart-beat from a SUSPENDED function that says REGISTERED revives it and is answered with the profile.
- **Notifications** are queued and sent by two worker threads with three attempts; a notification for a function that has gone is dropped after its
  attempts (the registry does not remove the subscription: the subscriber's validity time does).
- **Discovery client in `libs/nfcore`** (`g5c_disc`): every function that does not have a peer's address in its configuration asks the NRF, caches
  the answer for `validityPeriod` and forgets it after a connection failure. UDM (UDR), PCF (UDR), AUSF (UDM), SMF (UDM, PCF, AMF) and AMF (AUSF, UDM,
  PCF, SMF) use it; the SMF's UPFs stay in its configuration (N4 is a peer-to-peer association the operator defines).
- **OAuth2**: the token endpoint issues ES256 JWTs (RFC 7515 / 7518, `libs/sbi/jwt`) after checking that the requester is registered with the stated type
  and that a registered producer offers every requested service to that type. `registry.oauth2.enforce` makes the NRF's own discovery, retrieval and
  subscription endpoints require a token; registration, heart-beat and deregistration are authenticated by the transport, since an NF has no token
  before it is registered. Enforcement on the producer side of the other functions is a separate step (`NRF-GAP-04`).

## Why not
- A relational database for the registry: see above. The state file is replaced atomically and costs one write per interval.
- Returning profiles exactly as registered (map or array): breaks consumers of the other representation; the specification makes the NRF responsible.
- Strict leniency on query parameters: `snssais` and `target-plmn-list` are JSON arrays by the OpenAPI, and the reference NRF refuses a single object;
  `service-names` is a comma separated list (`style: form, explode: false`), repeated parameters are accepted as well.

## Verification
`nf/nrf/tests/test_nrf.c` (registration, update, discovery filters and ordering, subscriptions and notifications, heart-beat supervision, tokens,
enforcement, persistence, configuration errors, the discovery client), `fuzz_replay_nrf`, the differential against Open5GS's NRF (`deploy/oracle/nrf_diff.sh`),
Open5GS's functions and UERANSIM against our NRF (oracle `OUR_NRF=1`), and the cluster and chaos runs in which every function finds its peers through it.
Matrix: `docs/conformance/phase7-matrix.json`.
