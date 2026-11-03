#!/usr/bin/env python3
"""tools/cli/g5c-privacy: every rule on synthetic rows (a concealed SUCI is clean; a null scheme, an IMSI on N1 / N2, a repeated scheme output and a GUTI that was not reallocated are findings; an IMSI on N4 or
the SBI is not), the identity patterns of the byte search, the exit code, and the golden captures when tshark is at hand."""
import importlib.machinery
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-privacy"
loader = importlib.machinery.SourceFileLoader("g5c_privacy", str(TOOL))
spec = importlib.util.spec_from_loader("g5c_privacy", loader)
pv = importlib.util.module_from_spec(spec)
loader.exec_module(pv)
GOLD = ROOT / "tests" / "fixtures" / "golden"


def row(n, src="10.0.0.1", dst="10.0.0.5", proto="NGAP/NAS-5GS", ran="7", msg="", idtype="", scheme="", msin="", output="", tmsi="", imsi="", sht="0"):
    return "\t".join([str(n), "0.0", src, dst, proto, ran, msg, idtype, scheme, msin, output, tmsi, imsi, sht])


def find(rows):
    return pv.analyse(pv.parse_rows("\n".join(rows)))


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    concealed = row(1, msg="0x41", idtype="1", scheme="1", output="aabbccdd" * 8)
    f, st = find([concealed, row(2, src="10.0.0.5", dst="10.0.0.1", msg="0x56")])
    check("a concealed SUCI and no repeat: no finding", f == [] and st["nas_messages"] == 2, f)
    f, _ = find([row(1, msg="0x41", idtype="1", scheme="0", msin="0000000001")])
    check("null scheme: high", [s for s, _, _ in f] == ["high"] and "null protection scheme" in f[0][1] and f[0][2] == [1], f)
    f, _ = find([row(1, msg="0x41", idtype="1", scheme="1", output="aa" * 40), row(5, msg="0x41", idtype="1", scheme="1", output="aa" * 40, ran="8")])
    check("the same scheme output twice: medium, both frames named", [s for s, _, _ in f] == ["medium"] and f[0][2] == [1, 5], f)
    f, _ = find([row(1, proto="NGAP/NAS-5GS", imsi="001010000000001")])
    check("an IMSI on N1 / N2: high", [s for s, _, _ in f] == ["high"] and "IMSI in clear" in f[0][1], f)
    f, _ = find([row(1, proto="PFCP", imsi="001010000000001"), row(2, proto="HTTP2/JSON/NAS-5GS", imsi="001010000000001")])
    check("an IMSI on N4 or in an SBI message is not judged", f == [], f)
    # GUTI reallocation: the request carries the TMSI the UE has, the accept assigns one
    req = row(1, src="10.0.0.1", dst="10.0.0.5", msg="0x41", idtype="2", tmsi="0xc0000010")
    same = row(2, src="10.0.0.5", dst="10.0.0.1", msg="0x42", tmsi="0xc0000010")
    new = row(2, src="10.0.0.5", dst="10.0.0.1", msg="0x42", tmsi="0xc0000011")
    f, _ = find([req, same])
    check("the accept repeats the TMSI of the request: high", [s for s, _, _ in f] == ["high"] and "reallocation" in f[0][1] and f[0][2] == [2], f)
    f, _ = find([req, new])
    check("the accept assigns a new TMSI: clean", f == [], f)
    f, _ = find([req, row(2, src="10.0.0.5", dst="10.0.0.1", ran="9", msg="0x42", tmsi="0xc0000010")])
    check("a TMSI seen on another UE context is not mistaken for a repeat", f == [], f)
    st = find([row(1, msg="0x41", sht="0"), row(2, msg="0x5d", sht="2"), row(3, msg="", sht="4")])[1]
    check("protected messages are counted, not read", st["protected"] == 2, st)

    check("byte patterns: ASCII and packed BCD (low nibble first, f filler)", pv.bcd_patterns("0000000001") == {"ascii": "30303030303030303031", "bcd": "0000000010"}
          and pv.bcd_patterns("12345")["bcd"] == "2143f5" and pv.bcd_patterns("123456")["bcd"] == "214365", pv.bcd_patterns("12345"))

    # the command line: exit code and the report
    rows = Path(ROOT / "tests" / "support" / "_privacy_rows.tsv")
    rows.write_text(row(1, msg="0x41", idtype="1", scheme="0", msin="0000000001") + "\n")
    p = subprocess.run([sys.executable, str(TOOL), "--from-tsv", str(rows)], capture_output=True, text=True)
    check("exit 1 and the finding in the report when something high is found", p.returncode == 1 and "[high]" in p.stdout, p.stdout + p.stderr)
    rows.write_text(concealed + "\n")
    p = subprocess.run([sys.executable, str(TOOL), "--from-tsv", str(rows), "--json"], capture_output=True, text=True)
    check("exit 0 and an empty JSON list when clean", p.returncode == 0 and '"findings": []' in p.stdout, p.stdout + p.stderr)
    p = subprocess.run([sys.executable, str(TOOL), "--from-tsv", str(rows), "--msin", "12345"], capture_output=True, text=True)
    check("--msin needs a capture", p.returncode == 2, p.stderr)
    rows.unlink()

    # real captures (UERANSIM registers with the null scheme)
    cap = GOLD / "s3_open5gs_v2.8.0_ueransim.pcapng"
    if shutil.which("tshark") and cap.exists():
        p = subprocess.run([sys.executable, str(TOOL), str(cap)], capture_output=True, text=True)
        check("golden S3 capture: the null-scheme SUCI of UERANSIM is found, the IMSI of N4 is not", p.returncode == 1 and "null protection scheme" in p.stdout and "IMSI in clear" not in p.stdout, p.stdout + p.stderr)
        p = subprocess.run([sys.executable, str(TOOL), str(cap), "--msin", "0000000001"], capture_output=True, text=True)
        check("--msin finds the digits on the wire as ASCII and BCD", "as bcd in" in p.stdout and "as ascii in" in p.stdout, p.stdout)
        p = subprocess.run([sys.executable, str(TOOL), str(cap), "--msin", "987654321098"], capture_output=True, text=True)
        check("--msin of a subscriber that is not in the capture adds no finding", "987654321098" not in p.stdout, p.stdout)
    print("privacy: PASS" if ok else "privacy: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
