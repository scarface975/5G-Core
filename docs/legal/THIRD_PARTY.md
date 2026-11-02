# Third-party components (ADR-0002, ADR-0013)

Only permissively licensed code is linked into the product. `scripts/c_lint.sh` fails if a CMake dependency is not listed
here with an allowed licence.

| Component | Used for | Licence (SPDX) | How it is used |
|-----------|----------|----------------|----------------|
| OpenSSL 3.x | AES, SHA-256, HMAC, CMAC, X25519, P-256, TLS/mTLS | Apache-2.0 | system library, dynamic link |
| nghttp2 | HTTP/2 framing (SBI) | MIT | system library |
| libuv | event loop, thread pool (SBI server) | MIT | system library |
| libpq (PostgreSQL 16 - 18 client library) | the UDR's PostgreSQL storage backend (optional: the UDR builds without it) | PostgreSQL | system library, dynamic link |
| pthreads / libm | threads, math | system (glibc/musl, LGPL-2.1 with the linking exception) | system library |

Allowed licence ids: `Apache-2.0`, `PostgreSQL`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `OpenSSL` (the pre-3.0 licence), `Zlib`.
Not allowed in the product: any GPL/AGPL/LGPL code that is linked statically, SSPL, BUSL, and anything without a licence.

Test-only tools (never linked, never redistributed): Open5GS (AGPL-3.0), UERANSIM (GPL-3.0), MongoDB, Wireshark/dumpcap, the PostgreSQL server (PostgreSQL licence; a throw-away
instance for the UDR's tests, `deploy/run/pg-temp.sh`).
Generators run at development time and their output is committed: Python 3 scripts under `tools/`
(`jsonschema`, `pyyaml` for OpenAPI validation only).

3GPP/ETSI specification documents are downloaded, SHA-256 pinned (`docs/specs/pinned.json`) and git-ignored; only
derived tables (ASN.1 modules, NAS message tables) are committed. The SNOW 3G documents are restricted ETSI/SAGE
material and are not in the repository (ADR-0012).
