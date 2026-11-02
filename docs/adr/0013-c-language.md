# ADR-0013: Implementation language - C (supersedes ADR-0001)

Status: Accepted (2026-10-07), decision by the project owner. Supersedes ADR-0001 (Rust).

## Context
The owner directed a move of the whole code base to C, citing support and licensing concerns. Recorded for the
file: 3GPP specification licensing, the ETSI/SAGE SNOW 3G licence (ADR-0012) and the clean-room rules (ADR-0002) are
language-independent, so this decision does not change them. The reasons that stand are toolchain ubiquity, the
hiring pool, and long-term vendor-neutral support (GCC/Clang, no single-vendor compiler).

## Decision
- C17 (`-std=c17`), GCC and Clang, built with CMake + Ninja/Make, at the repository root (same layout as before: `libs/`, `nf/`, `shims/`).
- The project tree contains C only. The former Rust tree was moved out of the repository (2026-10-07) to the sibling
  folder `5G_core_rust_archive` and is used only as a read-only reference while porting: each C component must pass the
  same golden and conformance tests (TS vectors, real pcaps, Open5GS interop) before it counts as done.
- Dependencies: permissive licences only (MIT/BSD/Apache-2.0/ISC). Used: OpenSSL 3.x (crypto, TLS; Apache-2.0), nghttp2
  (HTTP/2; MIT), libuv (event loop; MIT). JSON, the YAML subset, the APER codec and the NAS/NGAP table generators are our own
  code (no third-party parser to audit or track). cargo-deny is replaced by `scripts/c_lint.sh` + `docs/legal/THIRD_PARTY.md`.
- AGPL/GPL tools remain test-only (Open5GS, UERANSIM), unchanged.

## Compensating controls for losing memory safety (mandatory, enforced in CI)
Network-facing parsers (NAS, NGAP, PFCP, GTP-U, SBI JSON) are the attack surface; in C they are the main risk.
1. Warnings as errors: `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Werror`.
2. Hardening: `-fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie -Wl,-z,relro,-z,now`.
3. Every test run twice: normal and under ASan + UBSan (`scripts/c_check.sh`). Parsers have libFuzzer targets (`fuzz/`,
   clang, `-DG5C_FUZZ=ON`, run in CI) and a gcc replay driver that feeds the golden NGAP/NAS corpora plus mutations through
   the same entry points inside ctest.
4. One bounds-checked buffer type (`g5c_buf`: pointer + length, all reads/writes via checked accessors). No raw
   `memcpy`/`strcpy`/`sprintf` in parsers; a CI grep gate bans them outside `buf.c`.
5. Static analysis: `gcc -fanalyzer` over the whole tree with warnings as errors, plus a banned-function gate
   (`scripts/c_lint.sh`). clang-tidy and cppcheck can be added when installed.
6. No dynamic allocation in the UPF fast path; arena allocators with per-message lifetimes in the control plane.
7. Secrets: `OPENSSL_cleanse` on key material, no keys in logs.

## Consequences
+ Widest toolchain/support base, direct access to AF_XDP/DPDK for the UPF.
- Highest defect risk of the options; the controls above are the price and are not optional.
- The port was completed on 2026-10-07 (crypto, base, config, sbi, nfcore, NAS, NGAP, PFCP/GTP-U headers, udr-lite, UDM,
  ausf-lite, PCF) and verified against the same golden traces, schemas and Open5GS interop scenarios as the Rust tree; Phase 3
  onwards is written in C only. The measured evidence is in `docs/update.md` (2026-10-07).
