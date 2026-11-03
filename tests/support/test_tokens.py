#!/usr/bin/env python3
"""tools/cli/g5c-tokens: tokens are stored as hashes, a token is shown once, tenants and roles are validated, a revoked token is gone, the file is 0600 and a mistake leaves it as it was."""
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent.parent / "tools" / "cli" / "g5c-tokens"


def run(*a, stdin=None):
    return subprocess.run([sys.executable, str(TOOL), *a], capture_output=True, text=True, input=stdin)


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "tokens.json")
        p = run(f, "tenant", "acme", "--prefix", "imsi-0010199", "--prefix", "imsi-0010198")
        check("a tenant is defined", p.returncode == 0 and json.load(open(f))["tenants"]["acme"]["supi_prefixes"] == ["imsi-0010198", "imsi-0010199"], p.stderr)
        p = run(f, "new", "acme-prov", "--roles", "provision,read", "--tenant", "acme")
        token = p.stdout.strip()
        doc = json.load(open(f))
        e = doc["tokens"][0]
        check("the token is printed once and only its hash is stored", p.returncode == 0 and token.startswith("g5c_") and len(token) > 40 and e["sha256"] == hashlib.sha256(token.encode()).hexdigest()
              and token not in open(f).read(), p.stderr)
        check("roles are stored in a fixed order, with the tenant", e["roles"] == ["read", "provision"] and e["tenant"] == "acme", e)
        check("the file is private", stat.S_IMODE(os.stat(f).st_mode) == 0o600)
        p2 = run(f, "new", "noc", "--roles", "read")
        check("another token differs", p2.returncode == 0 and p2.stdout.strip() != token)
        before = open(f).read()
        for args, want in ((("new", "noc", "--roles", "read"), "exists"), (("new", "x", "--roles", "root"), "roles are"), (("new", "y", "--roles", "read", "--tenant", "nobody"), "define the tenant"),
                           (("new", "z", "--roles", "key-admin", "--tenant", "acme"), "key-admin"), (("new", "bad name", "--roles", "read"), "letters"), (("tenant", "t", "--prefix", "imsi-12"), "prefix")):
            p = run(f, *args)
            check("refused: %s" % " ".join(args), p.returncode == 2 and want in p.stderr, p.stderr)
        check("a refusal leaves the file as it was", open(f).read() == before)
        p = run(f, "list")
        check("list shows names, roles and tenants and never a token", "acme-prov" in p.stdout and "tenant acme" in p.stdout and token not in p.stdout and "all subscribers" in p.stdout, p.stdout)
        p = run(f, "revoke", "acme-prov")
        check("revoke removes the token", p.returncode == 0 and [x["name"] for x in json.load(open(f))["tokens"]] == ["noc"])
        check("revoking an unknown name is an error", run(f, "revoke", "ghost").returncode == 1)
        p = run("hash", stdin="my-own-token\n")
        check("hash gives the SHA-256 of a token made elsewhere", p.stdout.strip() == hashlib.sha256(b"my-own-token").hexdigest())
    print("tokens: PASS" if ok else "tokens: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
