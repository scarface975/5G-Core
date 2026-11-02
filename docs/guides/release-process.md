# Release process

## Versioning
`VERSION` at the top of the tree is the one source: `MAJOR.MINOR.PATCH`, with `-rcN` for a release candidate (`0.9.0-rc1`). It is compiled into every binary (the first log line of each start, the metric
`g5c_build_info{version, function}`), into the SBOM and the archives. MAJOR changes when a configuration key or a state file format stops being readable by the previous release (the upgrade guide then says
how to convert); MINOR for new functions or features; PATCH for fixes only. `CHANGELOG.md` is updated in the same change as `VERSION`.

## Steps
1. **Freeze**: no feature work; only fixes found by the steps below.
2. **Regression on the full matrix**: `bash scripts/g5c_regress.sh --oracle` (plain, ASan + UBSan, TSan builds of every test; the conformance matrix check; coverage; lint and static analysis; the cluster
   load, chaos, upgrade and rollback runs with and without mutual TLS; the secrets, operations, slices and support checks; the SLO gates; the Open5GS / UERANSIM oracle scenarios; the ZMQ demo with
   the OCUDU gNB and srsUE when installed). It writes `build/regress-summary.txt`; the last line must be `regression: PASS`.
3. **Dependency and vulnerability scan**: `python3 tools/release/gen_sbom.py > docs/sbom/g5c.cdx.json`, then scan the SBOM against a vulnerability database (Grype / Trivy / OSV-scanner, which are not installed on the
   development host: run one where it is, and record the result in `docs/legal/audit-<version>.md`). Container scan: when the image is built.
4. **Licence audit**: `python3 tools/release/licence_audit.py --write` (automated; writes `docs/legal/audit-<version>.md` and `NOTICE`), then counsel's review (`docs/legal/patent-frand-review.md`).
5. **Documentation**: `python3 tools/docs/gen_api_docs.py` (a ctest fails when the committed reference differs from the sources), guides updated, `CHANGELOG.md`.
6. **Build the release**: `bash tools/release/release.sh`. It repeats the gates, builds the binaries, stages the archive, writes the source archive, `SHA256SUMS`, detached signatures, a smoke install of the archive
   into a staging root, and `RELEASE.json` (artifacts and hashes, state of every gate).
7. **Sign with the release key**: `G5C_RELEASE_KEY=<fingerprint> bash tools/release/release.sh` on the machine that holds the offline key. Without it the script makes a TEST key and says so in the manifest: such an
   archive is for the lab only. Publish the public key (`release/g5c-release-pub.asc`) on a channel customers already trust.
8. **Tag**: record the release in `docs/history/update.md` and tag the source (`git tag -s v0.9.0-rc1` once the tree is under version control). A GA candidate needs: the regression green, no critical or high security
   finding open, the licence audit signed by counsel, a pilot plan agreed (`docs/guides/pilot-plan.md`).

## What the archive holds
`bin/` (twelve functions and `g5c-ctl`), `install.sh`, `deploy/` (systemd units, the cluster scripts, the operations files, container and Kubernetes files, the demo launcher), `configs/` (examples),
`docs/` (guides, API reference, operations, security, legal), `tools/` (diagnostics, capture, redaction), `NOTICE`, `LICENSE`, `CHANGELOG.md`, `VERSION`, the SBOM. It does not hold the test harness
(Open5GS oracle), downloaded specifications or anything from `build/`.

## Verifying a download
```bash
sha256sum -c SHA256SUMS && gpg --verify SHA256SUMS.asc SHA256SUMS && gpg --verify g5c-<version>.tar.gz.asc g5c-<version>.tar.gz
```

## Support
A support case starts with `tools/cli/g5c-diag` (versions, host, logs, metrics, configurations, certificate expiry; identities, keys and tokens removed) and, when signalling is the question, `tools/cli/g5c-capture`.
Fixes go out as PATCH releases through the same steps.
