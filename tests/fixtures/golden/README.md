# Golden traces

Reference captures of the **Open5GS oracle** (v2.8.0, unmodified) driven by **UERANSIM** (test-only peers), plus the
NGAP PDUs extracted from them. They are behavioural references for comparison, not inputs to our implementation's source.

| File | Scenario | Notes |
|------|----------|-------|
| `s1_registration_open5gs_v2.8.0_ueransim.pcapng`, `s1_ngap_pdus.hex` | S1: NG Setup, registration, 5G-AKA with SQN resync, Security Mode, Initial Context Setup | The UE also tries a PDU session, which fails because that run had no UPF. |
| `s2_open5gs_v2.8.0_ueransim.pcapng`, `s2_ngap_pdus.hex` | S2: S1 + PDU session establishment, N4 (PFCP) and N3 (GTP-U) traffic, ping through the UPF | Recorded inside an unprivileged namespace (no sudo). |
| `s3_open5gs_v2.8.0_ueransim.pcapng`, `s3_ngap_pdus.hex` | S3: S2 + PDU session release and de-registration | Contains PFCP session establishment/deletion for the SMF/UPF phases. |
| `ngap_handover_*_pdus.hex`, `ngap_release_scenario_pdus.hex` | NGAP PDUs from the ORAN emulator vs Open5GS captures | Different subscriber keys; used for codec round-trips only. |

All S1-S3 use PLMN 001/01, SUPI imsi-001010000000001 and the test key K=465B5CE8..., OPc=E8ED289D... (public test values).
Regenerate: `deploy/oracle/scenario.sh s1|s2|s3` (WSL), copy the newest pcap from `~/g5c-oracle/pcap/`, then
`python3 tools/pcap_ngap_to_hex.py <pcap> > <name>_ngap_pdus.hex`.
