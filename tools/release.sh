#!/usr/bin/env bash
# Builds a release candidate: archives, checksums, signatures, SBOM, licence audit, manifest (docs/release-process.md).
#
#   tools/release.sh [--no-build] [--skip-regress-note]
#
# Output in build/release/<version>/:
#   g5c-<version>.tar.gz        binaries, install script, units, deployment files, documentation, tools, NOTICE, SBOM
#   g5c-<version>-src.tar.gz    the source tree (without build output, downloaded specifications, captures)
#   SHA256SUMS, *.asc           checksums and detached signatures (GnuPG)
#   RELEASE.json                the manifest: artifacts and hashes, gates and their state, the regression summary of the tree
# Signing: with G5C_RELEASE_KEY=<fingerprint or user id> the key of the keyring in use; without it a throw-away TEST key is made in build/release/gnupg and the manifest says so. A release
# that goes to customers is signed with the offline release key; the public key is release/g5c-release-pub.asc.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"
VER="$(cat VERSION)"
OUT="$ROOT/build/release/$VER"; STAGE="$OUT/g5c-$VER"
BUILD=1; [ "${1:-}" = "--no-build" ] && BUILD=0
rm -rf "$OUT"; mkdir -p "$STAGE"

echo "== gates before the archive"
python3 tools/licence_audit.py --write | tail -1
python3 tools/gen_api_docs.py --check
python3 tools/check_ops.py | tail -1
[ "$BUILD" = 1 ] && bash scripts/c_install.sh | tail -1
BIN="${G5C_PREFIX:-$HOME/.cache/g5c-bin}/bin"
for nf in nrf scp bsf udr nssf nef udm ausf pcf smf amf upf g5c-ctl; do [ -x "$BIN/$nf" ] || { echo "missing binary $nf"; exit 1; }; done

echo "== staging"
mkdir -p "$STAGE/bin" "$STAGE/docs" "$STAGE/tools" "$STAGE/release"
cp "$BIN"/* "$STAGE/bin/"
cp -a deploy "$STAGE/deploy"; rm -rf "$STAGE/deploy/oracle" "$STAGE/deploy/windows"      # test-only (Open5GS oracle) and the Windows launchers stay out of the release
cp -a configs "$STAGE/configs"
for d in install.md upgrade.md admin-guide.md; do cp "docs/$d" "$STAGE/docs/"; done
cp -a docs/ops docs/api docs/security docs/sbom "$STAGE/docs/"; mkdir -p "$STAGE/docs/legal"
cp docs/legal/THIRD_PARTY.md docs/legal/SNOW3G-licensing.md docs/legal/audit-"$VER".md docs/legal/patent-frand-review.md "$STAGE/docs/legal/" 2>/dev/null || true
cp tools/g5c-diag tools/g5c-capture tools/g5c-redact tools/g5c-subscribers tools/g5c-kpi tools/g5c-dossier tools/g5c-sdk tools/g5c-ladder tools/g5c-trace tools/g5c-scenario tools/g5c-api tools/g5c-dn tools/perf_history.py "$STAGE/tools/"
cp -r scenarios "$STAGE/scenarios"
mkdir -p "$STAGE/deploy/console" && cp deploy/console/index.html "$STAGE/deploy/console/"
cp VERSION NOTICE LICENSE CHANGELOG.md "$STAGE/"
cp release/g5c-release-pub.asc "$STAGE/release/" 2>/dev/null || true
cp docs/sbom/g5c.cdx.json "$STAGE/g5c-$VER.cdx.json"
cp deploy/install.sh "$STAGE/install.sh"
# install.sh in the archive finds the binaries in ./bin and the deployment files beside it
sed -i 's#^ROOT="$(cd "$HERE/.." \&\& pwd)"#ROOT="$HERE"#' "$STAGE/install.sh"
sed -i 's#"$HERE/systemd/#"$ROOT/deploy/systemd/#g; s#"$HERE/run/g5c-pki.sh"#"$ROOT/deploy/run/g5c-pki.sh"#' "$STAGE/install.sh"

echo "== archives"
( cd "$OUT" && tar --owner=0 --group=0 -czf "g5c-$VER.tar.gz" "g5c-$VER" )
( cd "$ROOT" && tar --owner=0 --group=0 --exclude=./build --exclude=./docs/specs/src --exclude=./docs/specs/restricted --exclude='*.pcap' --exclude='*.pcapng' --exclude='*.whl' --exclude=__pycache__ \
    --transform "s#^\.#g5c-$VER-src#" -czf "$OUT/g5c-$VER-src.tar.gz" . )
( cd "$OUT" && sha256sum "g5c-$VER.tar.gz" "g5c-$VER-src.tar.gz" > SHA256SUMS )

echo "== signatures"
GNUPGHOME_SAVE="${GNUPGHOME:-}"; TESTKEY=false
if [ -z "${G5C_RELEASE_KEY:-}" ]; then
  export GNUPGHOME="$ROOT/build/release/gnupg"; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
  if ! gpg --list-secret-keys "g5c release candidate (TEST KEY)" >/dev/null 2>&1; then
    gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-generate-key "g5c release candidate (TEST KEY) <release-test@g5c.invalid>" ed25519 sign 2y 2>/dev/null
  fi
  KEY="g5c release candidate (TEST KEY)"; TESTKEY=true
else
  KEY="$G5C_RELEASE_KEY"
fi
for f in "g5c-$VER.tar.gz" "g5c-$VER-src.tar.gz" SHA256SUMS; do gpg --batch --quiet --pinentry-mode loopback --passphrase '' --local-user "$KEY" --armor --detach-sign --output "$OUT/$f.asc" "$OUT/$f"; done
gpg --armor --export "$KEY" > "$OUT/g5c-release-pub.asc"
echo "== verification"
( cd "$OUT" && sha256sum -c SHA256SUMS && for f in "g5c-$VER.tar.gz" "g5c-$VER-src.tar.gz" SHA256SUMS; do gpg --batch --verify "$f.asc" "$f" 2>&1 | grep -E "Good signature|BAD" ; done )
[ -n "$GNUPGHOME_SAVE" ] && export GNUPGHOME="$GNUPGHOME_SAVE" || unset GNUPGHOME
echo "== smoke test of the archive: unpack, staging install, units"
T="$(mktemp -d)"; tar -C "$T" -xzf "$OUT/g5c-$VER.tar.gz"
( cd "$T/g5c-$VER" && DESTDIR="$T/root" bash install.sh | tail -1 && [ -x "$T/root/usr/local/bin/amf" ] && [ -f "$T/root/etc/systemd/system/g5c@.service" ] && echo "archive installs into a staging root: ok" )
rm -rf "$T"

echo "== manifest"
SUM="$ROOT/build/regress-summary.txt"
python3 - "$OUT" "$VER" "$TESTKEY" "$SUM" <<'PYEOF'
import hashlib, json, os, sys, datetime
out, ver, testkey, summ = sys.argv[1:5]
def sha(p):
    h = hashlib.sha256(); h.update(open(p, "rb").read()); return h.hexdigest()
art = {f: {"sha256": sha(os.path.join(out, f)), "bytes": os.path.getsize(os.path.join(out, f))} for f in sorted(os.listdir(out)) if os.path.isfile(os.path.join(out, f)) and not f.endswith(".asc")}
reg = open(summ, encoding="utf-8").read().splitlines() if os.path.exists(summ) else []
m = {"release": ver, "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "candidate": "-rc" in ver,
     "artifacts": art, "signed_with_test_key": testkey == "true",
     "gates": {
        "regression": "PASS" if any(l.strip() == "regression: PASS" for l in reg) else ("FAIL or not run" if reg else "not run"),
        "licence_audit_automated": "PASS (docs/legal/audit-%s.md)" % ver,
        "licence_audit_counsel_signoff": "PENDING: needs counsel (docs/legal/patent-frand-review.md)",
        "patent_frand_review": "PENDING: recorded for counsel, not concluded",
        "penetration_test": "PENDING: external, see docs/pilot-plan.md",
        "pilot_plan": "written, agreement of the pilot partner pending (docs/pilot-plan.md)",
        "containers_and_kubernetes": "UNVERIFIED: no container runtime or cluster available to build or apply them",
        "ga_candidate_tag": "not yet: the pending gates above must close first"},
     "regression_summary": reg}
json.dump(m, open(os.path.join(out, "RELEASE.json"), "w"), indent=1)
print("manifest written:", {k: v for k, v in m["gates"].items() if k in ("regression",)}, "signed with a test key" if testkey == "true" else "")
PYEOF
ls -la "$OUT" | sed 's/^/   /'
echo "release candidate $VER in $OUT"
