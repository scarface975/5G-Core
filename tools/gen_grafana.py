#!/usr/bin/env python3
"""Writes deploy/ops/grafana-g5c.json, the Grafana dashboard of the g5c core (Prometheus data source). python3 tools/gen_grafana.py"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
panels = []
pid = [0]


def panel(title, exprs, x, y, w=8, h=7, unit="short", kind="timeseries"):
    pid[0] += 1
    targets = [{"expr": e, "legendFormat": lf, "refId": chr(65 + i)} for i, (e, lf) in enumerate(exprs)]
    panels.append({"id": pid[0], "type": kind, "title": title, "datasource": {"type": "prometheus", "uid": "${DS}"},
                   "gridPos": {"x": x, "y": y, "w": w, "h": h}, "targets": targets,
                   "fieldConfig": {"defaults": {"unit": unit}, "overrides": []}})


panel("Functions up", [('up{job=~"g5c-.*"}', "{{job}}")], 0, 0, 8, 6, kind="stat")
panel("Registered UEs / connected UEs / gNBs", [("sum(g5c_amf_registered_ues)", "registered"), ("sum(g5c_amf_connected_ues)", "connected"), ("sum(g5c_amf_gnbs)", "gNBs")], 8, 0, 8, 6)
panel("PDU sessions (SMF) / sessions (UPF)", [("sum(g5c_smf_pdu_sessions_active)", "SMF"), ("sum(g5c_upf_sessions)", "UPF")], 16, 0, 8, 6)
panel("Registration success ratio", [("g5c:registration_success_ratio:rate5m", "ratio")], 0, 6, 8, 7, unit="percentunit")
panel("Registrations by result (/s)", [("sum by (result) (rate(g5c_amf_registrations_total[5m]))", "{{result}}")], 8, 6, 8, 7, unit="ops")
panel("5G-AKA by result (/s)", [("sum by (result) (rate(g5c_amf_authentications_total[5m]))", "{{result}}")], 16, 6, 8, 7, unit="ops")
panel("SBI request rate by function", [("g5c:sbi_request_rate:rate5m", "{{job}}")], 0, 13, 8, 7, unit="reqps")
panel("SBI p99 latency by function", [("g5c:sbi_latency_p99:5m", "{{job}}")], 8, 13, 8, 7, unit="s")
panel("SBI 5xx by function (/s)", [('sum by (job) (rate(g5c_sbi_requests_total{status=~"5.."}[5m]))', "{{job}}")], 16, 13, 8, 7, unit="reqps")
panel("Access token checks by result (/s)", [("sum by (job, result) (rate(g5c_oauth_checks_total[5m]))", "{{job}} {{result}}")], 0, 20, 8, 7, unit="ops")
panel("NSSF slice selections (AMF) by result (/s)", [("sum by (result) (rate(g5c_amf_nssf_selections_total[5m]))", "{{result}}")], 8, 20, 8, 7, unit="ops")
panel("UPF throughput (bytes/s)", [("sum by (direction) (rate(g5c_upf_bytes_total[5m]))", "{{direction}}")], 16, 20, 8, 7, unit="Bps")
panel("UPF packets dropped / N4 timeouts (SMF)", [("sum(rate(g5c_upf_dropped_packets_total[5m]))", "UPF dropped"), ("sum(rate(g5c_smf_n4_timeouts_total[5m]))", "N4 timeouts")], 0, 27, 12, 7, unit="ops")
panel("Functions registered at the NRF / suspended", [("sum(g5c_nrf_profiles)", "registered"), ("increase(g5c_nrf_suspended_total[1h])", "suspended (1 h)")], 12, 27, 12, 7)

dash = {"title": "g5c 5G core", "uid": "g5c-core", "schemaVersion": 39, "version": 1, "refresh": "15s", "time": {"from": "now-1h", "to": "now"},
        "tags": ["g5c", "5gc"], "templating": {"list": [{"name": "DS", "type": "datasource", "query": "prometheus", "label": "Data source"}]},
        "panels": panels}
out = os.path.join(ROOT, "deploy", "ops", "grafana-g5c.json")
with open(out, "w") as f:
    json.dump(dash, f, indent=1)
print("wrote", out, len(panels), "panels")
