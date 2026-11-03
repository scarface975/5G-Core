# Interoperability

Only what has been run and has evidence in this repository. A product that is not listed here has not been tested. Each entry names how to reproduce it and a file that must exist.

| Peer | Core | Result | What was seen |
|---|---|---|---|
| OCUDU gNB with srsUE (srsRAN 4G in 5G SA mode) over ZeroMQ (gNB + UE (virtual radio)) | ours (all functions) | pass | NG Setup accepted (PLMN 00101, TAC 7), registration with 5G-AKA, security mode, PDU session, ping 5 of 5 through the user plane; five runs in a row |
| UERANSIM nr-gnb and nr-ue (gNB + UE (simulator)) | Open5GS 2.8.0 core with our AMF in its place | pass | registration, authentication, security mode, PDU session through the Open5GS SMF and UPF, release and de-registration (recorded trace) |
| UERANSIM nr-gnb and nr-ue (gNB + UE (simulator)) | Open5GS 2.8.0 AMF with our SMF and our UPF in its place | pass | PDU session establishment and release with PFCP between our SMF and our UPF, GTP-U through our UPF (recorded trace) |
| UERANSIM nr-ue 3.3.0, patched copy (UE (simulator)) | ours (AUSF EAP-AKA') | pass with a patched peer | EAP-AKA' authentication against our AUSF: key derivation, AT_MAC and AT_RES verified by an independent implementation |
| Open5GS 2.8.0 AMF, AUSF, SMF, PCF (core functions) | our UDM, UDR and PCF in their place | pass | Open5GS authenticates and sets up sessions against our UDM and UDR; Open5GS SMF takes policy from our PCF and follows a mid-session policy change with a PFCP update |
| Open5GS 2.8.0 (core functions (differential)) | ours (nine functions) | 129 cases compared, 0 unexplained | the same requests to both cores, answers compared field by field; every difference has a stated reason |

## Limits and how to run each again

**OCUDU gNB with srsUE (srsRAN 4G in 5G SA mode) over ZeroMQ**

- Limits: srsUE cannot decipher 5G NAS with NEA1 to NEA3 (the sequence number is read from the 4G position), so the demo configures NEA0 with NIA2; DEMO_CIPHERING=NEA2 for a UE that implements TS 33.501
- Run: `CORE=ours deploy/demo/zmq_demo.sh`
- Evidence: `docs/demo/zmq-demo.md`

**UERANSIM nr-gnb and nr-ue**

- Limits: the recorded scenario S3; one UE
- Run: `OUR_AMF=1 deploy/oracle/scenario.sh s3`
- Evidence: `tests/fixtures/golden/s3_our_amf_open5gs_core_ueransim.pcapng`

**UERANSIM nr-gnb and nr-ue**

- Limits: the recorded scenario S3; one UE
- Run: `OUR_SMF=1 OUR_UPF=1 deploy/oracle/scenario.sh s3`
- Evidence: `tests/fixtures/golden/s3_our_smf_our_upf_open5gs_amf_ueransim.pcapng`

**UERANSIM nr-ue 3.3.0, patched copy**

- Limits: stock UERANSIM 3.3.0 rejects the AT_KDF attribute of a conforming server (Length 1, RFC 5448 3.2); the copy built by build_ueransim_eap.sh accepts it
- Run: `deploy/oracle/build_ueransim_eap.sh`
- Evidence: `deploy/oracle/build_ueransim_eap.sh`

**Open5GS 2.8.0 AMF, AUSF, SMF, PCF**

- Limits: scenarios S3 and S4 of the oracle
- Run: `OUR_UDM=1 OUR_PCF=1 deploy/oracle/scenario.sh s4`
- Evidence: `deploy/oracle/README.md`

**Open5GS 2.8.0**

- Limits: what the nine differential tests send; free5GC is not a reference
- Run: `tools/cli/g5c-compat run`
- Evidence: `tests/fixtures/compat/differentials.log`

## Not tested

- any commercial gNB or O-RAN radio unit
- any commercial UE or modem
- free5GC as a peer
- srsRAN Project gNB (OCUDU is the gNB tested)
- real radio with an SDR

