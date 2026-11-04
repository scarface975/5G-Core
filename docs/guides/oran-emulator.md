# The ORAN emulator against this core

`deploy/oran/prove.sh` runs the N2, NAS and N3 drivers of the ORAN_emulator project (`oran/tools/n2_*`) against the whole core in a private user and network namespace (no sudo):

```
ORAN_EMULATOR=/path/to/ORAN_emulator/oran deploy/oran/prove.sh [ues]
```

The core is configured to match the emulator, never the other way round: AMF at 127.0.0.5:38412, PLMN 999/70, TAC 1, SST 1, subscribers imsi-999700000000001 upward with the emulator's K and OPc, and the data network's gateway at 10.45.0.1 (the target of its ICMP echo). The report is `$G5C_RUN/oran-proof/report.txt`; the drivers' own output, the GTP-U frame (`gtpu.pcap`), a capture of N3 (`n3.pcap`) and the metrics of the AMF, SMF and UPF are next to it.

## What it proves
| Step | Driver | What the core did |
|---|---|---|
| NG Setup | `n2_attach_test` | accepted the gNB (SCTP, APER decoded by our codec) |
| Registration | `n2_register_test` | 5G-AKA through AUSF and UDM, security mode (NIA2 / NEA2), registration accept |
| PDU session | `n2_session_test` | SMF, PCF and UPF set up the session; PDUSessionResourceSetupRequest with the UPF tunnel; a GTP-U frame |
| Release | `n2_teardown_test` | PDU session release, de-registration, UE context release |
| Many UEs | `n2_multi_test` | 16 UEs registered back to back over one association, sessions, ICMP echo through each UE's own tunnel and back, release |
| Cross-check | our metrics | registrations accepted and none rejected, user-plane packets counted by the UPF, no function logged an error |

Not part of the run: the emulator's DPDK fronthaul, MAC, RLC and PHY layers (they need hugepages and a NIC), and its dashboard.

## What the run found
1. **RAN node name.** The emulator sent `ORAN_emulator gNB`. TS 38.413 types the field as PrintableString, which has no underscore; our AMF refused the NG Setup. Open5GS accepts it. Fixed in the emulator (`ORAN-emulator gNB`).
2. **Initial Context Setup answer.** The drivers answered an Initial Context Setup Request only when it carried a PDU session. A registration accept travels in one without sessions, and TS 38.413 8.3.1 wants an answer to every one. Our AMF waits for the answer before it sets up the first session, so the session never arrived. Fixed in the emulator's drivers.
3. **Downlink right after the session.** The emulator pings the moment its N2 response is sent. The reply reached the UPF before the SMF had told it the gNB's tunnel, and was dropped. The SMF now creates the downlink rule as buffer-without-notification and the UPF releases what waited when the tunnel is set (a core change, with its tests updated).
4. **Gateway address.** The test namespace gave the data-network interface the pool's network address (10.45.0.0) instead of 10.45.0.1, so the echo was forwarded and answered with an ICMP redirect. Fixed in the cluster script.

The emulator's changes are in its own repository, uncommitted: `oran/src/n2/oran_n2.c` (the name) and `oran/tools/n2_{session,teardown,multi}_test.c`, `n2_gnbd.c`, `n2_demo.c` (the answer).
