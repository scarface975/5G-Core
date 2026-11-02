# ADR-0025: Phase 8 (production hardening): scope, order, and the first work package, OAuth2 access tokens

Status: Accepted (2026-10-26)

## Where Phase 7 ended
Every network function the strategy names is built and verified (AMF, SMF, UPF, PCF, UDM, NRF, AUSF, UDR, NSSF, NEF, SCP) and a twelfth, the BSF; the shims are deleted. Phase 7 is recorded as
done with these items **carried into Phase 8 as backlog, not finished**: the AMF as a consumer of the NSSF (so the multi-slice scenario that Phase 7's exit names can run), the PCF's UE policy
and usage monitoring, and the completion of the UDM and AMF event exposure services. They are work packages WP9 to WP11 below.

## Phase 8 work packages
The strategy's Phase 8 ("turn a working core into an operable, secure, scalable product") is too large to be one piece; it is split into packages, each with its own tests, matrix rows and
exit evidence. The order puts first what the others depend on and what needs no hardware or third party. No dates are given on purpose.

| # | Package | What it covers | State |
|---|---|---|---|
| WP1 | OAuth2 access tokens enforced between the functions | TS 33.501 13.4.1: producer check, consumer token client, cluster default, oracle switch | **built, this ADR** |
| WP2 | Mutual TLS between all functions | the transport protection that token based authorization requires (13.3.2.1): a PKI for the cluster, TLS on every listener and client, certificate reload without a restart | **built** (2026-10-28, below) |
| WP3 | Secrets and keys | K / OPc and the home network keys behind a key-management interface (file store with envelope encryption now, PKCS#11 / KMS later), no secrets in configuration or logs, rotation | **built** (hygiene verified, UDM master key rotation with `rewrap` tested, `exec:` command source for a KMS / vault client); an HSM / PKCS#11 integration and the AUSF's key rotation open |
| WP4 | Operations | configuration hot reload, Prometheus rules and Grafana dashboards, structured audit log of provisioning and policy changes, runbooks, Helm chart and operator | **built** (rules, dashboard, audit log, runbooks, certificate reload, log level at run time); configuration reload beyond those, Helm / operator open |
| WP5 | High availability and scale | stateless replicas over the shared stores (PostgreSQL for the UDR exists), AMF and SMF contexts in a shared store, SCTP multi-homing and N4 failover, rolling upgrade and rollback, autoscaling | **partly**: rolling upgrade and rollback under load tested (`ns upgrade`); shared-state stores, N4 failover, multi-homing, autoscaling open |
| WP6 | Performance and SLOs | registrations per second, sessions per second, latency objectives; UPF throughput targets of ADR-0014 (needs a NIC with XDP) | **partly**: control-plane SLOs defined and gated (`docs/ops/slo.md`); the 10-100 Gbit/s user plane needs hardware |
| WP7 | Operator features | charging hooks and CDR export (Nchf), lawful intercept interface design (jurisdiction dependent), provisioning API and CLI / UI, multi-PLMN | **partly**: CDR export built and tested, lawful intercept designed (`docs/security/lawful-intercept-design.md`), provisioning API and `g5c-ctl` exist; Nchf, multi-PLMN, a UI open |
| WP8 | Assurance | 7-day soak, load to target, an external penetration test with remediation, signed artifacts, dependency and container scanning, a commercial core-test tool run | **partly**: threat model, signed archives, SBOM and licence audit, pilot plan; the pen test, the 7-day soak, a vulnerability scan, container scan and the commercial tool need a third party, time or tools not here |
| WP9 | AMF consumes the NSSF; the multi-slice scenario | carried from Phase 7 | **built** (registration and PDU session through the NSSF, tested on the cluster); NSI-driven SMF selection, target AMF, availability, a two-slice scenario through a UE open |
| WP10 | PCF: UE policy, usage monitoring | carried from Phase 7 | usage monitoring BUILT 2026-11-02 (volume threshold: PCF decision -> SMF -> URR on the UPF -> usage report -> SMF -> PCF update -> throttle decision applied; `policy.usage_monitoring`); UE policy (URSP) still open |
| WP11 | UDM / AMF event exposure completion | carried from Phase 7 (optional there) | open |

## WP1 decision: OAuth2 access tokens of the NRF, enforced
- **Specification.** TS 33.501 13.4.1 (read from the pinned text): the NRF is the authorization server, the consumer the client, the producer the resource server; client credentials grant; tokens are
  JWTs. The producer checks the signature with the NRF's public key, that the audience is its own identity or NF type, that the scope covers the requested service, and that the token has not expired
  (13.4.1.1.2 step 2). TS 29.510 5.4 and 6.3.5.2.4 give the request and the claims; the NRF side was built in Phase 7 (ES256 tokens, `/oauth2/token`, `/oauth2/jwks`).
- **Producer** (`libs/nfcore/src/oauth.c`, `g5c_oauth_rs`): a guard in front of the router's own guard. It applies to the requests whose first path segment is one of the services the function
  registers at the NRF, so health, metrics, callbacks (their URIs are the consumer's), the admin APIs and the NEF's northbound APIs (their callers are AFs with their own tokens) are not touched.
  A route flagged `G5C_ROUTE_OWN_AUTH` is not touched either: the UDR's provisioning extensions, which check the provisioning token themselves. The key set of the NRF is fetched on first use, again
  when a token names a key id that is not in it (at most every two seconds, so a stream of forged key ids does not become a stream of requests to the NRF) and every `jwks_refresh_s`; the key set is
  reference counted, so a refresh never frees a key that a check is using. 401 for a missing, damaged, forged, expired or not yet valid token, 403 for another audience or a scope that does not cover
  the service, both with a `WWW-Authenticate` header as RFC 6750 has it; 503 when no key is held and the NRF cannot be reached. `exp` is checked as RFC 7519 4.1.4 says: a token is not accepted *on*
  or after it (a first version accepted it during the second of `exp`; the sanitizer runs' timing found it).
- **Consumer** (`g5c_oauth_client`): a token provider hook of the SBI client (`g5c_client_set_token_provider`) called for every request that has no Authorization header. A request to a service of
  another function (table of the service names of the 5GC and the NF type that offers each; names that are not services get none) gets a token for that service from the NRF, kept until it nears its end
  (the NRF truncates `exp` to a second, so a second is taken off and the token is renewed at 80% of the rest), one request for it at a time per service, a refusal remembered for 2 s. The NRF's own
  discovery and subscription services take a token too (optional per 13.3.1.3); the registration, heart-beat and deregistration of an instance do not, the NRF lets them in.
- **Configuration.** The common section `oauth2: { enforce, acquire, leeway_s, jwks_refresh_s }` of every function (needs `nrf.uri`); both switches default to false, so functions without tokens,
  Open5GS's among them, work as before. The cluster turns both on for every function by default (`G5C_OAUTH2=0` to turn off); the oracle has `OUR_OAUTH2=1` for runs where every function that
  talks SBI is ours.
- **One thing had to change in the UDM and the UDR.** The UDM sent its static provisioning token as `Authorization: Bearer` on *every* request to the UDR, which leaves no room for the NRF's token.
  The provisioning token now has its own header (`x-g5c-provisioning-token`); the UDR still accepts the bearer form, so existing tools and the oracle scripts are unchanged.
- **Transport protection.** TS 33.501 13.3.2.1 says that with token based authorization the network shall use protection at the transport layer. Tokens without TLS authorize but do not
  authenticate the channel (anyone who can read a token can replay it until it expires). A function that enforces tokens on a listener without TLS logs a warning; mutual TLS everywhere is WP2.

## Interop facts
Open5GS 2.8.0 sends and checks no access tokens (its NRF issues them when asked), so a mixed core runs with OAuth2 off, as it did, and the all-ours oracle runs turn it on. Our NRF's token
endpoint already refused requesters that are not registered as the type they claim, and scopes no registered producer offers to that requester type; the consumer therefore never gets a token
that the producer will not take.

## Gaps (matrix rows SEC-GAP-*)
No TLS yet (WP2); no client credentials assertions (13.3.8), no additional scope (resources, operations) in the token, no NSSAI / NSI / NF set claims checked, no roaming PLMN checks, no token
obtained by the SCP for delegated discovery (TS 29.500 6.10.11), no revocation, one signing key at the NRF.

## Consequences
A request for a service of any of our functions without the NRF's token is refused, with every function ours, in the cluster and in the oracle; the cost is one token request per consumer per service
per lifetime and one signature check per request.

## WP2 decision: one PKI, TLS 1.2+ with h2 on every listener, client certificates required, rotation by SIGHUP
- **What was already there:** `g5c_tls_server_ctx` / `g5c_tls_client_ctx` (ALPN h2, client CA = mutual TLS, IP and name verification on the client), `sbi.tls { cert, key, ca }` in every configuration, `https` in
  the NRF profile. The functions never ran with it because nothing made the certificates and every URI in the generated configurations was `http`.
- **PKI** (`deploy/run/g5c-pki.sh`): EC P-256, SHA-256; a CA (5 years), a leaf per function (90 days) with `subjectAltName` of the function's addresses and `serverAuth, clientAuth` (the functions are reached
  by IP address, and the same file is the listener's and the outgoing requests' identity), one for the operator. Files replaced atomically. The CA key is a file for a test cluster; on a production cluster it
  belongs offline (the runbook says how to issue elsewhere).
- **Rotation:** the server holds the context new connections use under a lock; `g5c_server_swap_tls` replaces it and returns the old one; the client swaps likewise and drops its idle pooled connections.
  A new SSL object takes a reference on its context, so a swap never frees a context a handshake is using. `g5c_nf_inst_reload_tls` builds both new contexts first and swaps only if both built: a damaged file
  changes nothing. SIGHUP triggers it (functions on `g5c_nf_run`, the NRF's and the UPF's own loops). Connections in progress keep their negotiated certificate until they close.
- **Not covered:** revocation (CRL / OCSP), certificate pinning by function identity (any certificate of the CA may call any function; the access token decides what it may do), a CA rotation procedure
  beyond the runbook's two-CA overlap, TLS 1.3 only (1.2 is still allowed).
- **Effect on the demo:** the launcher defaults to `G5C_TLS=1`; the "requires access tokens but its SBI has no TLS" warning is gone from every terminal.

## Charging records (WP7), decision
The SMF installs one usage reporting rule per session when `smf.cdr.file` is set (URR 1: volume and duration measurement, no trigger), refers to it from the PDRs of the session, and reads the usage report that
the UPF puts in the Session Deletion Response; one JSON line per released PDU session goes to the file, which is opened for every record. This needs no new UPF code (its URR machinery was complete) and keeps
the integration point open for a charging function: an Nchf client would read the same events. Without the setting nothing changes on the UPF.
