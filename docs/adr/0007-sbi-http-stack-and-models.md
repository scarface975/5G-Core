# ADR-0007: SBI HTTP stack and API models

Status: Accepted (2026-09-30)

## Decision
- Transport (revised by ADR-0013): libuv (event loop, handler thread pool) + nghttp2 (HTTP/2) + OpenSSL 3 (TLS 1.2/1.3,
  mTLS, ALPN h2), all permissive. Development uses cleartext HTTP/2 with prior knowledge (h2c), which is what 3GPP
  TS 29.500 allows inside a trusted domain; TLS and mTLS are implemented and tested, and become mandatory in Phase 8
  (TS 33.501 13). Handlers are plain blocking functions run on a thread pool; the client is a pooled blocking HTTP/2
  client with per-request deadlines.
- `libs/sbi` owns transport only: router, server, pooled client, ProblemDetails (TS 29.571 5.2.4.1), JSON helpers,
  body-size limits. No NF-specific models.
- API models (Nudm_*, Npcf_*, ...) are written per service from the 3GPP OpenAPI YAML in the NF that owns it, and
  validated against that YAML. Bulk generation from the YAML is deferred until the YAML files are downloaded
  (permission required) and a permissively licensed generator is chosen.
- Unknown JSON fields are tolerated on input (forward compatibility, TS 29.500 6.x); required fields are enforced by explicit checks in each handler (a small JSON DOM with a depth limit and strict UTF-8 is in `libs/base`).

## Consequences
Small, auditable transport layer; models stay close to the owning NF until generation is worth the complexity.
