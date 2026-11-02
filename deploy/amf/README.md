# Running the AMF

```
amf [--check] configs/amf.yaml
```

- **N2 (NGAP over SCTP, PPID 60)** is accepted on `amf.ngap` (port 38412). The kernel's SCTP support must be loaded (`modprobe sctp`; in a container the
  host's module is used). One association per gNB; the AMF answers NG Setup for the PLMN and tracking areas it serves, accepts RAN Configuration Update and
  NG Reset, and routes every UE-associated message by its AMF-UE-NGAP-ID.
- **N1 (5GMM)**: initial, mobility and periodic registration, identification (SUCI), 5G-AKA through the AUSF (with resynchronisation), NAS security mode
  with NEA2 / NEA0 and NIA2 (`amf.security`), 5G-GUTI allocation and reallocation (configuration update), service request (also with the ciphered NAS message
  container), paging with T3513 repetition, UE- and network-initiated de-registration, implicit de-registration (mobile reachable timer), UE context release,
  retransmission timers T3550 / T3555 / T3560 / T3570 / T3522.
- **Mobility**: Xn handover by Path Switch Request (fresh NH / NCC per TS 33.501 A.10) and N2 handover (Handover Required / Request / Command / Notify,
  cancel and failure), with several gNBs.
- **N11**: Nsmf_PDUSession create / update / release SM context towards the SMF, selected from `amf.smf` or discovered through the NRF by S-NSSAI and DNN.
- **Namf_Communication** (`/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages`) is served for the SMF; the callbacks of the SMF (SM context status), the UDM
  (de-registration, subscribed-data change) and the PCF (AM policy update / terminate) are under `/namf-callback/v1/`; **Namf_EventExposure**
  (`/namf-evts/v1/subscriptions`) reports registration state, connectivity state, reachability and location.
- **Persistence**: with `amf.state_file` the registered UEs (GUTI, native security context, allowed NSSAI, PDU session references) are written after every
  change and restored at start-up in CM-IDLE, so a restarted AMF still serves their service requests without a new authentication.
- **Health and metrics**: `/health/live`, `/health/ready`, `/metrics` - NG Setup results, NGAP / NAS message counts, registrations, authentications, service
  requests, pagings, handovers, N1N2 transfers, PDU session requests, gauges for registered / connected UEs and gNBs.

What the AMF does not do (see `docs/conformance/phase5-matrix.json`): SNOW 3G / ZUC (ADR-0012), emergency services, non-3GPP access, AMF-to-AMF context
transfer (Namf_Communication UEContextTransfer) and AMF sets / relocation, inter-system (EPS) mobility, SMS over NAS, UE policy delivery, MICO, NSSAA,
network slice selection through the NSSF, OAuth2 on the SBI.

Interop: `OUR_AMF=1 deploy/oracle/scenario.sh s2|s3` runs UERANSIM against this AMF with Open5GS's SMF / UPF / AUSF; with `OUR_UDM=1 OUR_PCF=1 OUR_UPF=1
OUR_SMF=1` added, only the AUSF and the NRF are Open5GS's.
