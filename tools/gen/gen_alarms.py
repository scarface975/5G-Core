#!/usr/bin/env python3
"""deploy/ops/alarms.json: every alert rule as an ITU-T X.733 alarm (event type, probable cause, perceived severity, specific problem, repair action).
The severities and causes are decided here; the problem text and the runbook link are read from the rule, so the catalog cannot drift from the rules.
   python3 tools/gen/gen_alarms.py [--check]"""
import json
import os
import sys

try:
    import yaml
except ImportError:
    print("SKIP: PyYAML is not installed")
    sys.exit(77)

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES = os.path.join(ROOT, "deploy", "ops", "prometheus-rules.yml")
OUT = os.path.join(ROOT, "deploy", "ops", "alarms.json")

EVENT_TYPES = ["communicationsAlarm", "qualityOfServiceAlarm", "processingErrorAlarm", "equipmentAlarm", "environmentalAlarm", "securityAlarm"]
SEVERITIES = ["critical", "major", "minor", "warning", "indeterminate", "cleared"]

# alert -> (event type, probable cause, perceived severity)
TABLE = {
    "G5cFunctionDown": ("communicationsAlarm", "functionNotResponding", "critical"),
    "G5cNrfRegisteredFunctionsLow": ("processingErrorAlarm", "underlyingResourceUnavailable", "major"),
    "G5cNrfSuspendedFunctions": ("communicationsAlarm", "heartbeatLost", "minor"),
    "G5cTokenChecksRejected": ("securityAlarm", "accessTokenRejected", "minor"),
    "G5cNasIntegrityFailures": ("securityAlarm", "integrityViolation", "major"),
    "G5cAuthenticationFailures": ("securityAlarm", "authenticationFailure", "minor"),
    "G5cRegistrationsRejected": ("qualityOfServiceAlarm", "serviceDegraded", "critical"),
    "G5cSbiServerErrors": ("processingErrorAlarm", "applicationSubsystemFailure", "critical"),
    "G5cSbiLatencyHigh": ("qualityOfServiceAlarm", "responseTimeExcessive", "minor"),
    "G5cUpfLost": ("communicationsAlarm", "n4AssociationLost", "critical"),
    "G5cN4Timeouts": ("communicationsAlarm", "n4RequestTimeout", "major"),
    "G5cNoGnbConnected": ("communicationsAlarm", "n2AssociationLost", "major"),
    "G5cPduSessionsDropToZero": ("qualityOfServiceAlarm", "sessionsLost", "major"),
    "G5cUeAddressPoolHigh": ("qualityOfServiceAlarm", "thresholdCrossed", "warning"),
    "G5cUpfDroppedPackets": ("qualityOfServiceAlarm", "packetDropRateHigh", "warning"),
    "G5cRegistrationCongestion": ("qualityOfServiceAlarm", "congestion", "major"),
    "G5cSbiRateLimited": ("qualityOfServiceAlarm", "congestion", "minor"),
}


def build():
    rules = yaml.safe_load(open(RULES))
    out = {}
    for g in rules["groups"]:
        for r in g["rules"]:
            if "alert" not in r:
                continue
            n = r["alert"]
            if n not in TABLE:
                sys.exit("no alarm entry for the alert " + n + " (add it to tools/gen/gen_alarms.py)")
            et, cause, sev = TABLE[n]
            if et not in EVENT_TYPES or sev not in SEVERITIES:
                sys.exit("%s: %s / %s is not an X.733 event type / severity" % (n, et, sev))
            out[n] = {
                "eventType": et,
                "probableCause": cause,
                "perceivedSeverity": sev,
                "prometheusSeverity": r.get("labels", {}).get("severity", ""),
                "specificProblem": r.get("annotations", {}).get("summary", ""),
                "repairAction": r.get("annotations", {}).get("runbook", ""),
            }
    extra = set(TABLE) - set(out)
    if extra:
        sys.exit("alarm entries without an alert rule: " + ", ".join(sorted(extra)))
    return {"standard": "ITU-T X.733", "alarms": out}


def main():
    text = json.dumps(build(), indent=2, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        have = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        if have != text:
            print("deploy/ops/alarms.json is stale: run python3 tools/gen/gen_alarms.py")
            return 1
        print("alarms: fresh")
        return 0
    open(OUT, "w", encoding="utf-8", newline="\n").write(text)
    print("wrote", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
