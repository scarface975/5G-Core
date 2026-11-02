#!/usr/bin/env python3
"""CycloneDX 1.5 SBOM for the 5G core: our components plus the system libraries they link, with the versions found on this
build host (pkg-config). Run in the build environment: python3 tools/release/gen_sbom.py > docs/sbom/g5c.cdx.json"""
import datetime
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path

root = Path(__file__).resolve().parent.parent.parent


def pkg_version(name):
    try:
        return subprocess.check_output(["pkg-config", "--modversion", name], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def project_version():
    f = root / "VERSION"  # the release version (0.9.0-rc1)
    if f.exists():
        return f.read_text(encoding="utf8").strip()
    m = re.search(r"project\([^)]*VERSION\s+([0-9.]+)", (root / "CMakeLists.txt").read_text(encoding="utf8"))
    return m.group(1) if m else "0.0.0"


def pq_version():
    # libpq is optional (the UDR builds without it); the version of the shared object that the build linked
    v = pkg_version("libpq")
    if v != "unknown":
        return v
    for d in [Path.home() / "pg-local/root/usr/lib/x86_64-linux-gnu", Path("/usr/lib/x86_64-linux-gnu")]:
        for f in sorted(d.glob("libpq.so.5.*")):
            return f.name.split("libpq.so.")[1]
    return "unknown"


def lib(name, pkg, lic, purl, desc):
    v = pq_version() if pkg == "libpq" else pkg_version(pkg)
    return {"type": "library", "bom-ref": f"{purl}@{v}", "name": name, "version": v, "description": desc,
            "licenses": [{"license": {"id": lic}}], "purl": f"pkg:generic/{purl}@{v}", "scope": "required"}


components = [
    lib("OpenSSL", "openssl", "Apache-2.0", "openssl", "AES, SHA-2, HMAC, CMAC, X25519, P-256, TLS/mTLS"),
    lib("nghttp2", "libnghttp2", "MIT", "nghttp2", "HTTP/2 framing for the SBI"),
    lib("libuv", "libuv", "MIT", "libuv", "event loop for the SBI server"),
    lib("libpq", "libpq", "PostgreSQL", "libpq", "PostgreSQL client library of the UDR (optional at build time)"),
]
for nf in ["amf", "smf", "upf", "udm", "pcf", "udr", "ausf", "nrf", "nssf", "nef", "scp", "bsf", "g5c-ctl"]:
    components.append({"type": "application", "bom-ref": f"g5c/{nf}", "name": nf, "version": project_version(),
                       "licenses": [{"license": {"name": "Proprietary"}}], "scope": "required"})
bom = {
    "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
    "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
    "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "tools": [{"name": "tools/release/gen_sbom.py"}],
                 "component": {"type": "application", "name": "g5c", "version": project_version()}},
    "components": components,
    "dependencies": [{"ref": f"g5c/{c['name']}", "dependsOn": [x["bom-ref"] for x in components if x["type"] == "library"]}
                     for c in components if c["type"] == "application"],
}
json.dump(bom, sys.stdout, indent=2)
print()
