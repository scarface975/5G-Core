#!/usr/bin/env python3
"""tools/cli/g5c-replay: a golden capture becomes steps with decoded names; only what a gNB can resend alone is replayed; against a fake core over real SCTP the answers are compared with the recorded
ones (same, different, nothing), and the replay stops where the recorded session's keys would be needed."""
import importlib.machinery
import importlib.util
import os
import shutil
import socket
import struct
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-replay"
CAP = ROOT / "tests" / "fixtures" / "golden" / "s1_registration_open5gs_v2.8.0_ueransim.pcapng"
loader = importlib.machinery.SourceFileLoader("g5c_replay", str(TOOL))
spec = importlib.util.spec_from_loader("g5c_replay", loader)
rp = importlib.util.module_from_spec(spec)
loader.exec_module(rp)


def fake_core(answers):
    """a listening SCTP socket; for the n-th PDU it receives it sends answers[n] (a list of PDUs); returns (port, thread, stop)"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, rp.IPPROTO_SCTP)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(5)
    port = srv.getsockname()[1]

    def serve():
        try:
            c, _ = srv.accept()
        except OSError:
            return
        c.settimeout(3)
        n = 0
        try:
            while n < len(answers):
                data = c.recv(65536)
                if not data:
                    break
                for pdu in answers[n]:
                    rp.send(c, pdu, 0)
                n += 1
        except (socket.timeout, OSError):
            pass
        finally:
            c.close()
            srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return port, t


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    inspect = None
    try:
        inspect = rp.find_inspect()
    except SystemExit:
        pass
    if not (shutil.which("tshark") and inspect and CAP.exists()):
        print("SKIP: tshark, g5c-inspect or the golden capture is missing")
        return 77
    steps = rp.extract(str(CAP), 38412, inspect)
    names = [(s["dir"], rp.label(s["summary"])) for s in steps]
    check("the capture becomes steps with direction and decoded names", names[0] == ("up", "NGSetup") and names[1] == ("down", "NGSetup response") and
          names[2] == ("up", "InitialUEMessage (Registration request)") and names[3] == ("down", "DownlinkNASTransport (Authentication request)"), names[:5])
    check("a later reject is labelled with its cause", any("Authentication failure #21" in n[1] for n in names), names)
    groups = rp.groups_of(steps)
    check("steps are grouped as an uplink message and the answers that followed", rp.label(groups[1][0]["summary"]).startswith("InitialUEMessage") and len(groups[1][1]) == 1)
    check("only what a gNB can send alone is replayable", [rp.replayable(g[0]) for g in groups[:5]] == [True, True, False, False, False], [rp.replayable(g[0]) for g in groups[:5]])
    ng_ans, auth_req = bytes.fromhex(steps[1]["hex"]), bytes.fromhex(steps[3]["hex"])

    # a core that answers as recorded
    port, t = fake_core([[ng_ans], [auth_req]])
    rep = rp.run(steps, "127.0.0.1:%d" % port, inspect, 1.0)
    t.join(5)
    check("answers like the recorded core: same, then the replay stops where keys would be needed",
          [r["result"] for r in rep] == ["same", "same", "stopped"] and "keys of the recorded session" in rep[2]["detail"], rep)
    # a core that answers the registration with something else (the NG Setup response stands in for any wrong answer)
    port, t = fake_core([[ng_ans], [ng_ans]])
    rep = rp.run(steps, "127.0.0.1:%d" % port, inspect, 1.0)
    t.join(5)
    check("a different answer is reported and ends the comparison", [r["result"] for r in rep] == ["same", "different"] and "part ways" in rep[1]["detail"] and
          rep[1]["recorded"].startswith("DownlinkNASTransport (Authentication request)") and rep[1]["ours"] == "NGSetup response", rep)
    # a core that says nothing to the registration
    port, t = fake_core([[ng_ans], []])
    rep = rp.run(steps, "127.0.0.1:%d" % port, inspect, 0.6)
    t.join(5)
    check("silence is a difference too", rep[-1]["result"] == "different" and rep[-1]["ours"] == "(nothing)", rep)
    # nobody there
    try:
        rp.run(steps, "127.0.0.1:1", inspect, 0.5)
        check("an unreachable core is an error", False)
    except SystemExit as e:
        check("an unreachable core is an error", "cannot reach" in str(e), str(e))
    check("the text report names the step, both answers and the verdict", "recorded:" in rp.text_report(rep) and "DIFFERENT" in rp.text_report(rep))
    print("replay: PASS" if ok else "replay: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
