# 5G Core

Clean-room 5G Core (standalone, 3GPP Rel-16 baseline, Rel-17 track) written in C17 from the 3GPP specifications. All twelve network functions are built: AMF, SMF, UPF, PCF, UDM, UDR, AUSF, NRF, NSSF, NEF, SCP, BSF. Open5GS, UERANSIM and srsRAN are used as test peers and behavioural oracles only, never as a source of code.

Status: release candidate 0.9.0-rc1, see [CHANGELOG.md](CHANGELOG.md).

## Repository layout

| Path | What is in it |
|------|---------------|
| `nf/<name>/` | One folder per network function (`amf smf upf pcf udm udr ausf nrf nssf nef scp bsf`), each with `include/`, `src/`, `tests/`. NFs never include each other; shared code lives in `libs/`. |
| `libs/` | Shared libraries: `base` (bytes, JSON, YAML, logging, metrics), `config`, `sbi` (HTTP/2, TLS, OAuth2 client and server), `nfcore` (NF skeleton: registration, discovery, admin and metrics endpoints), `nas`, `ngap`, `pfcp`, `gtpu`, `crypto` (Milenage, 5G-AKA, EAP-AKA', NAS security, SNOW 3G), `oaschema` (JSON validation from the 3GPP OpenAPI), `testkit`. |
| `ctl/` | `g5c-ctl`, the operator command line for the NFs' admin interfaces. |
| `tools/` | Developer and operator tooling, grouped by purpose (below). |
| `scripts/` | Build, test, lint, coverage and regression entry points (`c_check.sh`, `c_lint.sh`, `c_install.sh`, `g5c_regress.sh`, ...). |
| `tests/` | Cross-NF tests: `conformance` (golden traces, payload dump), `support` (tests of the tools), `fixtures` (golden captures, fuzz seeds), `soak`, `tsan.supp`. |
| `fuzz/` | libFuzzer targets and the gcc replay driver that runs the same entry points inside ctest. |
| `scenarios/` | YAML scenarios for the cluster test runner (`tools/cli/g5c-scenario`); `experimental/` holds the unfinished ones. |
| `configs/` | One sample configuration per NF. |
| `deploy/` | Everything to run it: `docker`, `compose` (UERANSIM + Open5GS oracle), `k8s`, `systemd`, `run` (namespace cluster, PKI, init), `oracle` (differential tests against Open5GS), `ops` (alert rules, Grafana, KPI definitions), `console` (web console source), `demo`, per-NF READMEs, `install.sh`. |
| `docs/` | `guides` (install, upgrade, admin, testing, release, pilot), `adr` (architecture decisions), `api` (generated SBI reference), `conformance` (spec-clause to test matrices), `specs` (pinned 3GPP documents), `ops` (runbooks, SLOs), `security`, `legal`, `sbom`, `perf`, `strategy`, `demo`, `history`. |

### tools/

| Folder | Purpose |
|--------|---------|
| `cli/` | Operator and tester commands: `g5c-api`, `g5c-sdk`, `g5c-subscribers`, `g5c-scenario`, `g5c-kpi`, `g5c-trace`, `g5c-ladder`, `g5c-capture`, `g5c-diag`, `g5c-redact`, `g5c-dn`. |
| `release/` | Release candidate build (`release.sh`), SBOM, licence audit, performance history, compliance dossier. |
| `check/` | Consistency checks run by ctest and the regression: conformance matrix, ops files, SLOs. |
| `diff/` | Differential testers that compare our NFs with Open5GS responses. |
| `docs/` | Generators for the API reference, dashboard, feature sheet and PDFs. |
| `gen/` | Generators for checked-in data: test vectors, fuzz seeds, conformance matrices, console and Grafana files. |
| `spec/` | 3GPP spec fetching and extraction, and the code generators fed by it (NGAP, NAS, OpenAPI-derived tables). |
| `inspect/` | `g5c-inspect`, a C tool that decodes NGAP and NAS from hex. |

## Build and test

C17, CMake, GCC or Clang, OpenSSL 3, nghttp2, libuv. On Windows use WSL2 Ubuntu.

```
bash scripts/c_check.sh        # build and all tests, plain and under ASan + UBSan
bash scripts/c_lint.sh         # banned functions, dependency licences, gcc -fanalyzer
bash scripts/c_install.sh      # optimised build, installs the binaries to ~/.cache/g5c-bin/bin
bash scripts/g5c_regress.sh    # full regression (add --oracle for the Open5GS differentials)
```

Start with [docs/README.md](docs/README.md). Install and operate: [docs/guides](docs/guides). Running one NF: [deploy/amf](deploy/amf/README.md), [deploy/smf](deploy/smf/README.md), [deploy/upf](deploy/upf/README.md). Oracle and interop: [deploy/oracle](deploy/oracle/README.md).
