# Documentation Index

## Project summary
A from-scratch 5G Core intended to ship as a commercial product. Implemented from 3GPP specs (clean-room).
Open5GS / UERANSIM / srsRAN are **test peers and behavioural oracles only** — never a source of code.
See the licensing policy in the strategy PDF, section 2.

## Where things are
| Path | Purpose |
|------|---------|
| `strategy/5G_Core_Phase_Strategy.pdf` | Phase-wise plan (phases 0-9), licensing policy, validation strategy, risks |
| `update.md` | **Append-only, newest-first build/progress log.** Update it every session or milestone |
| `adr/` | Architecture decision records, `NNNN-title.md` (language, licensing, spec baseline, ...) |
| `specs/` | Spec index: 3GPP clause -> module -> test traceability |

## Repository layout
```
libs/    shared C libraries: base (bytes, JSON, YAML, logging, metrics), config, sbi, nfcore, nas, ngap, pfcp, gtpu,
         crypto, testkit
nf/      amf, smf, upf, pcf, udm, nrf, ausf, udr, nssf, nef, scp, bsf   (NFs never import each other; share code only via libs/)
nf/udr/  the UDR (generated API tables, storage interface with memory / file / PostgreSQL backends)
nf/nssf/ the NSSF (Nnssf_NSSelection, Nnssf_NSSAIAvailability; slice policy in configuration)
nf/nef/  the NEF (northbound APIs for application functions: traffic influence, monitoring events, AS session with QoS)
nf/scp/  the SCP (indirect communication between the functions: delegated discovery, reselection, TS 29.500 6.10)
nf/bsf/  the BSF (binding support: which PCF holds the PDU session of a UE address, TS 29.521)
tests/   conformance (golden traces, payload dump), fixtures (golden pcaps and PDUs, fuzz seeds)
fuzz/    libFuzzer targets and the gcc replay driver
deploy/  docker, compose (UERANSIM + Open5GS oracle), k8s
configs/ sample per-NF configuration
tools/ scripts/   spec extractors + code generators (ASN.1, NAS tables, NGAP schema, test vectors), pcap helpers, build/test/lint scripts
```

## Conventions
- Every protocol-logic change cites the governing 3GPP clause (TS number + section).
- Dependencies: MIT / Apache-2.0 / BSD / ISC / MPL-2.0 only. No GPL/AGPL/SSPL.
- Decisions go in `adr/`; progress goes in `update.md`.
- Definition of done: see strategy PDF, section 6.

## Phases (status in update.md)
0 Foundations - 1 UDM - 2 PCF - 3 UPF - 4 SMF - 5 AMF - 6 Integration - 7 Remaining NFs - 8 Hardening - 9 Release

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
