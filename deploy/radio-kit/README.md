# Radio lab kit

A gNB and a UE that exchange simulated radio over ZeroMQ, registering at our core, getting an IP address and pinging through the user plane. Nothing to plug in, no sudo (user and network
namespaces).

```
deploy/radio-kit/g5c-radio-kit check    # are the gNB, the UE, namespaces and the installed core there?
deploy/radio-kit/g5c-radio-kit run      # core + gNB + UE; exits 0 when a ping crossed the radio, the gNB and the core
deploy/radio-kit/g5c-radio-kit sdr      # what changes for a real SDR (not run in this repository)
```

| Piece | What | Where |
|---|---|---|
| gNB | OCUDU with the ZeroMQ radio driver | `GNB_BIN`, default `/home/work/ocudu/build/apps/gnb/gnb`; configuration `gnb.yml` (PLMN 00101, TAC 7, band 3, 20 MHz) |
| UE | srsUE from srsRAN 4G, 5G SA mode, ZeroMQ | `UE_BIN`, default `/home/work/srsRAN_4G/build/srsue/src/srsue`; configuration `ue.conf` (the public test subscriber) |
| Core | ours, all functions | installed by `scripts/c_install.sh` |

The two programs are not part of this repository and are not shipped: build them as `g5c-radio-kit check` says. The lab runs the real procedures (NG Setup, 5G-AKA, security mode, PDU session,
user plane); `docs/demo/zmq-demo.md` has the findings that shaped it, among them that srsUE cannot decipher 5G NAS with NEA1 to NEA3, so the lab uses NEA0 with NIA2
(`DEMO_CIPHERING=NEA2` for a UE that implements TS 33.501).

What this kit is not: a radio product. The ZeroMQ link carries I/Q between two processes; there is no RF, no fading beyond what the UE's channel emulator offers, and no timing or
spectrum behaviour of a real radio. Real RF with an SDR is described by `g5c-radio-kit sdr` and has not been run here.
