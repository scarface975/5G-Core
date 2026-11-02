# Licence audit, automated part, release 0.9.0-rc1

Made by `tools/release/licence_audit.py`. The manual part (patents, FRAND, export control, the owner's licence terms) is recorded in `patent-frand-review.md` and needs counsel.

- **PASS**: SPDX identifier in every product source file (284 files)
- **PASS**: no copyleft text or foreign copyright line in product files
- **PASS**: SBOM components and THIRD_PARTY.md agree, all licences allowed (4 components)
- **PASS**: no test-only tool in a build file
- **PASS**: specification documents ignored by version control, restricted documents absent

## Third-party components (from the SBOM)

| Component | Version | Licence |
|---|---|---|
| OpenSSL | 3.5.5 | Apache-2.0 |
| nghttp2 | 1.68.0 | MIT |
| libuv | 1.51.0 | MIT |
| libpq | 5.18 | PostgreSQL |
