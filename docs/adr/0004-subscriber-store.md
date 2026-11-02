# ADR-0004: Subscriber store — PostgreSQL behind a UDR-style API

Status: Accepted (2026-09-30)

PostgreSQL (PostgreSQL licence) in production, SQLite in development. MongoDB is avoided because of the SSPL.
NFs never access the database directly: UDM/PCF go through the Nudr-style API (`shims/udr-lite` now, real UDR in Phase 7).

Implemented 2026-10-22 by the real UDR (ADR-0020, `nf/udr`): PostgreSQL through libpq behind the `udr_db` storage interface; the development store is a journalled
memory store (the code of the shim), not SQLite, which would add a dependency for nothing; the shim is deleted.
