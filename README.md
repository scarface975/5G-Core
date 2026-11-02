# 5G Core

Clean-room, production-grade 5G Core (SA, 3GPP Rel-16 baseline) built from the 3GPP specifications, in C.

First milestone: **AMF, SMF, UPF, PCF, UDM** - built and interoperating (a UERANSIM UE registers, establishes a PDU session and pings through them, with
Open5GS's AUSF and NRF as the only third-party NFs). End goal: all 11 NFs.

- Start here: [docs/README.md](docs/README.md)
- Strategy (phase plan): [docs/strategy/5G_Core_Phase_Strategy.pdf](docs/strategy/5G_Core_Phase_Strategy.pdf)
- Progress log: [docs/update.md](docs/update.md)
- Running an NF: [deploy/amf](deploy/amf/README.md), [deploy/smf](deploy/smf/README.md), [deploy/upf](deploy/upf)
