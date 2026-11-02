# UDM key-handling threat note (Phase 1 exit criterion)

Scope: the long-term subscriber credentials (K, OPc or OP), the SUCI home-network private keys, and the secrets that guard the
admin API, as handled by `nf/udm`, `shims/udr-lite` and `shims/ausf-lite`. Written against the code as of 2026-10-07.

## Assets

| Asset | Where it lives | Impact if disclosed |
|-------|----------------|---------------------|
| K, OPc (per subscriber) | UDR record (`encPermanentKey`, `encOpcKey`); plaintext only inside a UDM request for the length of one Milenage run | Full compromise of that subscriber: impersonation, decryption of past and future radio traffic |
| UDM master key (32 bytes) | file named by `master_key_file` or `G5C_UDM_MASTER_KEY` | Decrypts every stored K/OPc |
| SUCI home-network private keys | files named in `hn_keys[].private_key_file` | De-conceals every SUPI sent by UEs using that key |
| Admin token | `admin_token_file` or `G5C_UDM_ADMIN_TOKEN` | Create, read, delete subscribers |
| SQN | UDR authentication subscription | Replay window, sync failures |

## What the code does today

1. **Encryption at rest.** With a master key, K and OPc are stored as `AES-256-GCM(master, random 96-bit IV, aad = SUPI)`. Binding the
   SUPI as associated data means a ciphertext copied to another subscriber's record fails authentication (tested). The scheme name is
   stored beside the value so keys can be re-wrapped later. Without a master key the UDM stores hex plaintext and logs a warning
   at start-up (`udm_keys_none`, development only).
2. **Secrets never in YAML.** Master key, admin token and private keys are read from environment variables or files; the config
   loader rejects unknown keys so a misspelt option fails loudly instead of being ignored.
3. **Minimal exposure in memory.** The UDM wipes key material with `OPENSSL_cleanse` in its own key paths (`nf/udm/src/core.c`, `config.c`):
   the unwrapped K/OPc buffers, the master-key string read from the environment or file, and the config-time key structures.
   Whether every intermediate buffer inside `libs/crypto` is wiped has not been audited (see T5).
4. **Not echoed.** The admin `GET` and `list` calls return provisioning metadata and the SQN, not K/OPc; `ctl_cli` asserts the key hex is
   absent from both. Log lines in `nf/udm` name the SUPI and the cause only (reviewed by grep, not machine-enforced).
5. **Admin API.** Disabled (404) unless a token of at least 16 characters is configured; bearer comparison is constant-time
   (`CRYPTO_memcmp`); the SBI listener can run TLS with mutual authentication.
6. **Random numbers** (RAND, IVs) come from OpenSSL's CSPRNG; a failure aborts the request instead of falling back.
7. **SUCI.** ECIES profiles A and B with the MAC checked before decryption; malformed or truncated schemes return `400/403`, not partial data.
8. **Authentication state.** SQN advances by 32 per vector and is persisted atomically by udr-lite; a resync (AUTS) is verified with
   MAC-S before the SQN is changed.

## Threats and status

| # | Threat | Mitigation | Status |
|---|--------|------------|--------|
| T1 | Stolen UDR database / backup | AES-256-GCM per value, master key held outside the database | Mitigated, provided the master key is stored apart from the data |
| T2 | Master key leaks (file permissions, backup of the config directory) | Files, not YAML; documented 0400 mode; container secrets read-only | **Partial**: no HSM/KMS integration and no automatic rotation |
| T3 | Admin token guessing or interception | Length floor, constant-time compare, TLS available | **Partial**: no rate limiting, no per-operator identity or audit trail, token is static |
| T4 | A malicious NF calls UDM directly (e.g. asks for vectors for any SUPI) | OAuth2 hook exists | **Open**: token validation is a hook only; production needs NRF-issued tokens (Phase 7) and mutual TLS between NFs |
| T5 | Memory disclosure in the UDM process (core dump, swap) | UDM key buffers cleansed after use | **Partial**: master key lives in process memory for the process lifetime; no `mlock`, core dumps not disabled by the process itself; `libs/crypto` intermediates not audited for wiping |
| T6 | Replay of authentication vectors / SQN manipulation | SQN +32, atomic persistence, AUTS MAC check | Mitigated for the shim; HA/concurrency semantics belong to the real UDR (Phase 7) |
| T7 | Parser attacks on SBI JSON / SUCI | Own JSON DOM with depth/size limits, strict UTF-8, sanitizer and fuzz coverage | Mitigated; coverage-guided fuzzing runs in CI only (clang) |
| T8 | Key leakage through logs, metrics or error bodies | Review; `ctl_cli` greps admin responses for key hex | **Partial**: no automated log scan; add one when logging grows |
| T9 | Supply chain (OpenSSL, nghttp2, libuv) | Allow-list in `docs/legal/THIRD_PARTY.md`, SBOM from `tools/gen_sbom.py` | Mitigated for licensing; vulnerability scanning of the SBOM is still to be wired into CI |

## Residual risk to carry forward

- Phase 7 (UDR, NRF, AUSF): real OAuth2 enforcement, KMS/HSM-backed master key with rotation (re-wrap using the stored scheme name), audit log
  for admin actions, rate limiting.
- Phase 8: `mlock` and `PR_SET_DUMPABLE=0` for key-holding processes, systemd/container hardening profile, SBOM vulnerability gate.
- Operators must not reuse `deploy/compose/gen-secrets.sh` output or the oracle's keys outside a lab.

## Addendum 2026-10-22: the real UDR (`nf/udr`, ADR-0020)

The UDR replaced `udr-lite`; the store is PostgreSQL or a journalled file. The keys stay what they were: K and OPc are wrapped by the UDM before they reach the UDR (the UDR never
sees them in the clear and has no key of its own), so T1 holds for the PostgreSQL database and its backups as it did for the file. New or changed:

| # | Threat | Mitigation | Status |
|---|--------|------------|--------|
| T10 | Anyone who can reach the UDR creates, replaces or removes subscribers (the provisioning extension) | bearer token (16 characters at least, constant-time comparison, from a file or the environment), 403 `PROVISIONING_DISABLED` when none is configured, the operations of TS 29.505 need none | **Partial**: one static token shared with the UDM, no rate limiting, no audit trail; OAuth2 for the 3GPP operations is the NF-wide gap (NRF-GAP-04) |
| T11 | The PostgreSQL connection string (a secret) leaks | only from `G5C_UDR_PG_CONNINFO` or a file, never from the configuration file; wiped after the connection is made | Mitigated; TLS to the database is `sslmode=` in the string and the operator's choice (not enforced) |
| T12 | A body that breaks the data model reaches the store and, through the UDM, a UE | every body and every PATCH result is validated against the schemas of the pinned OpenAPI files (400 with the member named) | Mitigated for the 3GPP data; 26 references into specifications that are not pinned accept any value (UDR-GAP-01) |
| T13 | Lost update / replay of a conditional write | a strong ETag (revision) and If-Match / If-None-Match are part of the storage operation (row lock in PostgreSQL), so the check and the write are one atomic step | Mitigated, tested with eight threads on every backend |
| T14 | A consumer's callback URI makes the UDR send requests to arbitrary hosts (SSRF) | notifications go only to the callback URI the subscriber gave, over the UDR's own client; the queue is bounded, delivery attempts are limited | **Partial**: no allow-list of callback hosts; subscribing needs no token |
| T15 | Resource exhaustion by subscriptions or slow consumers | per-data-set subscription limit (429), expiry chosen by the UDR, bounded notification queue, delivery on worker threads | Mitigated |
