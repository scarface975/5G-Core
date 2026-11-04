#!/usr/bin/env python3
"""deploy/run/g5c-init: twelve configurations with the chosen PLMN, tracking areas and addresses, fresh secrets, a PKI, and a guide; a second run keeps what exists."""
import importlib.machinery
import json
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "deploy" / "run" / "g5c-init"


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        d = Path(d) / "cfg"
        args = [sys.executable, str(TOOL), "--dir", str(d), "--mcc", "262", "--mnc", "01", "--tac", "7,8", "--n2-address", "127.2.0.5", "--n3-address", "127.2.0.7", "--ue-pool", "10.60.0.0/16", "--yes"]
        p = subprocess.run(args, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        check("generated", p.returncode == 0 and "12 configurations" in p.stdout, p.stdout + p.stderr)
        confs = sorted(c.name for c in (d / "conf").glob("*.yaml"))
        check("the twelve functions", confs == sorted(n + ".yaml" for n in "nrf scp bsf udr nssf nef udm ausf pcf upf smf amf".split()), confs)
        amf = (d / "conf" / "amf.yaml").read_text()
        check("PLMN and tracking areas in the AMF", "mcc: '262'" in amf and "mnc: '01'" in amf and "{ tac: 7 }" in amf and "{ tac: 8 }" in amf, amf[:400])
        check("UE pool in the SMF", "10.60.0.0/16" in (d / "conf" / "smf.yaml").read_text())
        token = (d / "keys" / "admin_token").read_text()
        check("fresh admin token, not the public test one", token != "admin-token-0123456789" and len(token) == 48 and re.fullmatch(r"[0-9a-f]+", token), token)
        check("home network key is new, not the TS 33.501 test key", (d / "keys" / "hn-1.key").read_text() != "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d")
        check("secrets are 0600", all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in (d / "keys").iterdir()), [oct(f.stat().st_mode) for f in (d / "keys").iterdir()])
        check("TLS by default: CA and a certificate per function", (d / "pki" / "ca.crt").exists() and (d / "pki" / "udm.crt").exists() and (d / "pki" / "admin.crt").exists())
        check("the guide names the PLMN and the files", "PLMN 262/01" in (d / "START-HERE.md").read_text() and str(d) in (d / "START-HERE.md").read_text())
        bindir = Path.home() / ".cache" / "g5c-bin" / "bin"
        if (bindir / "udm").exists():  # the binaries accept what was written
            bad = [n for n in confs if subprocess.run([str(bindir / n[:-5]), "--check", str(d / "conf" / n)], capture_output=True, text=True).returncode != 0]
            check("every function accepts its generated configuration (--check)", not bad, bad)
        # --systemd: the units point at this directory
        p = subprocess.run(args + ["--systemd", "--bin-dir", "/opt/g5c/bin", "--pin-peers"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        unit = (d / "systemd" / "g5c@.service").read_text() if (d / "systemd" / "g5c@.service").exists() else ""
        check("--systemd writes the units for this directory", p.returncode == 0 and "ExecStart=/opt/g5c/bin/%i " + str(d) + "/conf/%i.yaml" in unit and "ReadWritePaths=" + str(d) + "/state" in unit
              and "/var/lib/g5c" not in unit and (d / "systemd" / "g5c.target").exists() and (d / "systemd" / "g5c@upf.service.d" / "override.conf").exists(), unit[:400])
        check("and the guide says how to install them", "systemctl enable --now g5c.target" in (d / "START-HERE.md").read_text())
        before = (d / "keys" / "master.key").read_text()
        p = subprocess.run(args, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        check("a second run keeps the secrets", p.returncode == 0 and (d / "keys" / "master.key").read_text() == before)
        p = subprocess.run([sys.executable, str(TOOL), "--dir", str(d), "--mcc", "26", "--yes"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        check("an invalid MCC is refused", p.returncode != 0 and "--mcc" in p.stderr, p.stderr)
    # --preset campus: the private-use PLMN by default, device groups that g5c-fleet accepts, and the guide
    with tempfile.TemporaryDirectory() as d2:
        d2 = Path(d2) / "campus-cfg"
        p = subprocess.run([sys.executable, str(TOOL), "--dir", str(d2), "--preset", "campus", "--no-tls", "--yes"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        check("campus preset: generated with the private-use PLMN 999/99", p.returncode == 0 and "mcc: '999'" in (d2 / "conf" / "amf.yaml").read_text() and "mnc: '99'" in (d2 / "conf" / "amf.yaml").read_text(), p.stdout + p.stderr)
        groups = json.loads((d2 / "campus" / "groups.json").read_text())
        fleet = importlib.machinery.SourceFileLoader("g5c_fleet", str(ROOT / "tools" / "cli" / "g5c-fleet")).load_module()
        check("campus preset: three groups with the PLMN in their prefixes, accepted by g5c-fleet", sorted(groups["groups"]) == ["machines", "sensors", "staff"] and groups["groups"]["staff"]["prefix"] == "imsi-9999901" and
              sorted(fleet.load_groups(d2 / "campus" / "groups.json")) == ["machines", "sensors", "staff"], groups)
        check("campus preset: a device of a group falls in that group", fleet.group_of(groups["groups"], "imsi-999990200000007") == "machines" and fleet.group_of(groups["groups"], "imsi-999991000000001") == "(none)")
        check("campus preset: the guide and the pointer in START-HERE", "Campus network starter pack" in (d2 / "campus" / "README.md").read_text() and "campus/README.md" in (d2 / "START-HERE.md").read_text())
    print("init: PASS" if ok else "init: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
