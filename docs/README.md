# Documentation Index

## Project summary
A from-scratch 5G Core intended to ship as a commercial product. Implemented from 3GPP specs (clean-room).
Open5GS / UERANSIM / srsRAN are **test peers and behavioural oracles only** — never a source of code.
See the licensing policy in the strategy PDF, section 2.

## Where things are
| Path | Purpose |
|------|---------|
| `guides/` | install, upgrade, admin guide, testing, release process, pilot plan, known gaps, to do (what is left, in order), the ORAN emulator proof |
| `history/update.md` | Append-only, newest-first build log. Update it every session or milestone |
| `adr/` | Architecture decision records, `NNNN-title.md` (language, licensing, spec baseline, per-NF design) |
| `specs/` | Pinned 3GPP documents and the clause -> module -> test traceability |
| `conformance/` | Per-phase matrices: spec clause, function, proving test (checked by `tools/check/check_matrix.py`) |
| `api/` | Generated SBI reference of every NF |
| `ops/` | Runbooks and service level objectives |
| `interop/` | The register of what was run against which peer, with results and how to repeat each (`g5c-interop`) |
| `pm/` | The TS 28.552 measurements the core counts, with clause and fidelity (`g5c-pm`) |
| `training/` | Exercises for operators (`g5c-lab`) |
| `security/` | Threat model, key-handling note, lawful-intercept design |
| `legal/` | Third-party licences, SNOW 3G licensing, release audit |
| `sbom/`, `perf/` | Software bill of materials, performance history |
| `strategy/` | Phase plan (PDF), vendor comparison and feature opportunity sheets |
| `demo/` | Host and radio-simulator demos |

The repository layout (code, tools, deploy) is described in the [top-level README](../README.md).

## Conventions
- Every protocol-logic change cites the governing 3GPP clause (TS number + section).
- Dependencies: MIT / Apache-2.0 / BSD / ISC / MPL-2.0 only. No GPL/AGPL/SSPL.
- Decisions go in `adr/`; progress goes in `history/update.md`.
- Definition of done: see strategy PDF, section 6.

## Phases (status in history/update.md)
0 Foundations - 1 UDM - 2 PCF - 3 UPF - 4 SMF - 5 AMF - 6 Integration - 7 Remaining NFs - 8 Hardening - 9 Release

**Status:** release candidate 0.9.0-rc1; all functions built; 156 tests green (153 under ASan + UBSan) and the GitHub Actions workflow passing; the ORAN emulator proof passes (`guides/oran-emulator.md`). What is open is in `guides/known-gaps.md` and `guides/todo.md`.

## Build / run
C17, CMake, GCC or Clang, with OpenSSL 3, nghttp2 and libuv development packages (ADR-0013). On Windows use WSL2 Ubuntu;
Linux is required for SCTP/TUN/XDP work.
```
bash scripts/c_check.sh        # build + all tests, twice: plain, and under ASan + UBSan (-Werror, hardening flags)
bash scripts/c_lint.sh         # banned functions, dependency licences, gcc -fanalyzer
bash scripts/c_install.sh      # optimised build, installs the NF binaries to ~/.cache/g5c-bin/bin
.\scripts\validate_payloads.ps1   # every JSON payload our NFs emit, validated against the official 3GPP OpenAPI
```
Fuzzing: `CC=clang cmake -S . -B build-fuzz -DG5C_FUZZ=ON` builds coverage-guided targets (`fuzz/`); without clang the
same entry points run as replay drivers inside ctest. Oracle, golden traces and interop with Open5GS/UERANSIM:
`deploy/oracle/README.md`.
