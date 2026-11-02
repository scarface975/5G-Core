#!/usr/bin/env python3
"""tools/cli/g5c-redact: identities, tokens and keys out, the shape of the log kept, the same value always the same replacement."""
import subprocess
import sys
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent.parent / "tools" / "cli" / "g5c-redact"


def run(text, *args):
    return subprocess.run([sys.executable, str(TOOL), *args], input=text, capture_output=True, text=True, check=True).stdout


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    t = "imsi-001010000000123 registered GUTI 0d192654 from 192.168.1.20 (loopback 127.0.0.1) key 465b5ce8b199b49faa5f0a2ee238a6bc\n"
    o = run(t)
    check("IMSI replaced, PLMN kept", "imsi-00101~" in o and "0000000123" not in o, o)
    check("GUTI replaced", "0d192654" not in o and "GUTI <redacted>" in o, o)
    check("IPv4 replaced, loopback kept", "192.168.1.20" not in o and "127.0.0.1" in o, o)
    check("128-bit key replaced", "465b5ce8b199b49faa5f0a2ee238a6bc" not in o and "<key redacted>" in o, o)
    two = run("imsi-001010000000123 a\nimsi-001010000000124 b\nimsi-001010000000123 c\n").splitlines()
    a, b, c = (l.split()[0] for l in two)
    check("same value, same replacement; different values differ", a == c and a != b, two)
    jwt = "authorization: Bearer eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.abcdefghijklmnop\n"
    check("bearer token replaced", "eyJ" not in run(jwt), run(jwt))
    check("x-g5c-provisioning-token replaced", "secretvalue" not in run("x-g5c-provisioning-token: secretvalue123\n"))
    k64 = "master " + "ab" * 32 + " end\n"
    check("256-bit key replaced", "ab" * 32 not in run(k64))
    pem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY-----\n"
    check("private key block replaced", "MHcCAQEE" not in run(pem))
    check("--keep-ips leaves addresses", "192.168.1.20" in run("peer 192.168.1.20\n", "--keep-ips"))
    plain = "2026-10-29T06:00:00Z  INFO g5c_amf: N2 (SCTP) listening on 127.2.0.5:38412\n"
    check("an ordinary log line is unchanged", run(plain) == plain, run(plain))
    print("redact: PASS" if ok else "redact: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
