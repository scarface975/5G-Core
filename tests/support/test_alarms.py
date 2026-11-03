#!/usr/bin/env python3
"""tools/cli/g5c-alarms: an Alertmanager webhook becomes X.733 alarms in the event schema of the functions (firing, resolved, an alert the catalog does not know), the catalog covers every
alert rule, and the receiver forwards to a syslog and an HTTP collector."""
import json
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

try:
    import yaml
except ImportError:
    print("SKIP: PyYAML is not installed")
    sys.exit(77)

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-alarms"

WEBHOOK = {"status": "firing", "alerts": [
    {"status": "firing", "labels": {"alertname": "G5cUpfLost", "severity": "critical", "job": "g5c-smf", "instance": "127.2.0.12:7782"},
     "annotations": {"summary": "the SMF lost its UPF", "runbook": "docs/ops/runbooks.md#upf-lost"}, "startsAt": "2026-11-03T10:00:00Z", "fingerprint": "ab12"},
    {"status": "resolved", "labels": {"alertname": "G5cFunctionDown", "severity": "critical", "job": "g5c-amf", "instance": "127.2.0.11:7781"},
     "annotations": {"summary": "amf is up again"}, "startsAt": "2026-11-03T09:00:00Z", "endsAt": "2026-11-03T10:05:00Z", "fingerprint": "cd34"},
    {"status": "firing", "labels": {"alertname": "SomethingElse", "severity": "warning", "job": "node", "instance": "10.0.0.1:9100"},
     "annotations": {"summary": "disk is filling"}, "startsAt": "2026-11-03T10:01:00Z", "fingerprint": "ef56"}]}


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    # the catalog is in step with the rules and uses the X.733 vocabulary
    p = subprocess.run([sys.executable, str(ROOT / "tools" / "gen" / "gen_alarms.py"), "--check"], capture_output=True, text=True)
    check("catalog is fresh", p.returncode == 0, p.stdout + p.stderr)
    cat = json.loads((ROOT / "deploy" / "ops" / "alarms.json").read_text())["alarms"]
    rules = yaml.safe_load((ROOT / "deploy" / "ops" / "prometheus-rules.yml").read_text())
    alerts = {r["alert"] for g in rules["groups"] for r in g["rules"] if "alert" in r}
    check("every alert rule has an alarm and no alarm lacks a rule", alerts == set(cat), alerts ^ set(cat))
    check("severities are X.733 values and critical rules stay critical", all(c["perceivedSeverity"] in ("critical", "major", "minor", "warning") for c in cat.values())
          and all(c["perceivedSeverity"] == "critical" for c in cat.values() if c["prometheusSeverity"] == "critical"))
    check("every alarm names a repair action in the runbooks", all(c["repairAction"].startswith("docs/ops/runbooks.md#") for c in cat.values()))

    # convert
    p = subprocess.run([sys.executable, str(TOOL), "convert"], input=json.dumps(WEBHOOK), capture_output=True, text=True)
    ev = [json.loads(line) for line in p.stdout.splitlines()]
    check("one event per alert", p.returncode == 0 and len(ev) == 3, p.stderr)
    a = ev[0]
    check("firing: function, severity from the catalog, repair action from the rule", a["function"] == "smf" and a["alarm"]["perceivedSeverity"] == "critical"
          and a["alarm"]["eventType"] == "communicationsAlarm" and a["alarm"]["probableCause"] == "n4AssociationLost" and a["alarm"]["repairAction"].endswith("#upf-lost")
          and a["time"] == "2026-11-03T10:00:00Z" and a["host"] == "127.2.0.12", a)
    check("resolved: cleared, stamped with the end time", ev[1]["alarm"]["perceivedSeverity"] == "cleared" and ev[1]["time"] == "2026-11-03T10:05:00Z", ev[1])
    check("unknown alert: from the Prometheus label, cause unknown", ev[2]["alarm"]["perceivedSeverity"] == "minor" and ev[2]["alarm"]["probableCause"] == "unknown", ev[2])
    check("the alarm id is stable per alert and instance", a["alarm"]["alarmId"] == "G5cUpfLost/ab12")
    check("bad input is an error, not a crash", subprocess.run([sys.executable, str(TOOL), "convert"], input="not json", capture_output=True, text=True).returncode == 2)

    # serve: Alertmanager -> g5c-alarms -> syslog (UDP) and HTTP
    got = []

    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):
            got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    http = HTTPServer(("127.0.0.1", 0), Sink)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(5)
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    srv = subprocess.Popen([sys.executable, str(TOOL), "serve", "--port", str(port), "--syslog", "127.0.0.1:%d/udp" % udp.getsockname()[1],
                            "--http", "http://127.0.0.1:%d/e" % http.server_address[1], "--facility", "20"], stderr=subprocess.PIPE)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%d/" % port, data=json.dumps(WEBHOOK).encode(), method="POST"), timeout=2).read()
                break
            except OSError:
                time.sleep(0.1)
        msgs = []
        try:
            for _ in range(3):
                msgs.append(udp.recv(8192).decode())
        except socket.timeout:
            pass
        check("three syslog messages, local4 + critical = <162>, local4 + cleared = <166>", len(msgs) == 3 and msgs[0].startswith("<162>1 2026-11-03T10:00:00Z 127.2.0.12 g5c-alarms")
              and msgs[1].startswith("<166>1 ") and " ALARM - {" in msgs[0], msgs)
        check("the JSON in the message is the event", json.loads(msgs[0].split(" ALARM - ", 1)[1])["alarm"]["alertName"] == "G5cUpfLost" if msgs else False)
        check("the HTTP collector got the three events as one array", len(got) == 1 and len(got[0]) == 3, got)
        srv.terminate()
        srv.wait()
    finally:
        if srv.poll() is None:
            srv.kill()
        http.shutdown()
    print("alarms: PASS" if ok else "alarms: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
