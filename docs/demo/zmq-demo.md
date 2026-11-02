# The ZMQ demo: OCUDU gNB + srsUE over ZeroMQ against our core

The goal: show a UE (srsUE, srsRAN 4G in 5G SA mode) and a gNB (OCUDU) exchanging simulated I/Q over ZeroMQ, registering at **our** 5G core, getting an IP address, and pinging an address of
the core through the user plane. The binaries and configuration are those of the startup guide (`/home/work/ocudu/build/apps/gnb/gnb` with `/etc/open5gs/gnb.yml`,
`/home/work/srsRAN_4G/build/srsue/src/srsue` with `/etc/open5gs/ue.conf`); the demo never changes them.

## What exists now
`deploy/demo/zmq_demo.sh` runs the whole thing in an unprivileged user + network namespace (no sudo): the core, the gNB, the UE in a namespace of its own (its traffic has to go through
the radio, the gNB and the core), a host behind the UPF.

| Command | What it does |
|---|---|
| `CORE=open5gs deploy/demo/zmq_demo.sh` | the baseline: Open5GS as the core. Shows that the radio side works on this machine |
| `CORE=ours deploy/demo/zmq_demo.sh` | our whole core (NRF, AUSF, AMF, UDM, UDR, PCF, UPF, SMF, NSSF, BSF) |
| `DEMO_OAUTH2=1 CORE=ours ...` | the same with the NRF's access tokens enforced between all our functions |
| `DEMO_UE_DEBUG=1 ...` | the UE logs every NAS message in hex (in the copy of its configuration) |
| `DEMO_HOLD=60 ...` | keeps everything up for 60 s after the ping |

Result today: the gNB's NG Setup is accepted (PLMN 00101, TAC 7, SST 1), the UE registers (5G AKA, security mode, registration accept), gets a PDU session and IP `10.46.0.2` on `tun_srsue`,
and pings `10.46.0.1` (the UPF's TUN address) and `10.99.0.1` (a host behind the UPF) 5 of 5, round trip 30 to 75 ms (it goes through ZeroMQ and the gNB's PHY). Five runs in a row against our
core passed, 24 to 26 s each. Logs, the gNB's NGAP pcap and the UE's NAS pcap are in `$HOME/g5c-oracle/demo/`.

## Findings that shaped it
1. **srsUE cannot decipher 5G NAS with NEA1, NEA2 or NEA3.** `nas_base.cc` `cipher_decrypt()` takes the sequence number from `msg[5]`; in a 5G NAS message `msg[2..5]` is the MAC and the sequence
   number is `msg[6]` (the 4G layout has it at 5). The count is right only when the last MAC byte equals the sequence number (about 1 in 256). Open5GS never trips it because its default
   ciphering order is NEA0 first. Our AMF prefers NEA2, so for this UE the demo tells it to use NEA0 (integrity stays NIA2): `DEMO_CIPHERING=NEA2` for a UE that implements TS 33.501 (UERANSIM does,
   and the oracle runs NEA2 with it).
2. The gNB of the guide serves TAC 7; the oracle's cores serve TAC 1. The script sets the core's TAC from the gNB's configuration.
3. The gNB and srsUE buffer stdout when it is a file: the script runs them line-buffered (`stdbuf -oL`) so it can see "gNB started".

## Roadmap to a solid demo
No dates. Each step has tests of its own and is done when its evidence is in the regression.

| # | Step | Evidence |
|---|---|---|
| 0 | the harness, the Open5GS baseline and our core passing | done: the table above; a step of `scripts/g5c_regress.sh --oracle` |
| 1 | **solid in the namespace**: repeat 20 times for each core; the UE's idle mode (srsUE inactivity, service request), de-registration and re-registration, the gNB restarted, a function restarted under the UE; a 10-minute ping and a throughput run; the UE's NAS and the gNB's NGAP pcaps kept as golden traces | a `soak` mode of the script with its numbers; golden traces under `tests/fixtures/golden/` |
| 2 | **the demo the way the guide runs it, on the host**: our core started from terminals as the guide does for Open5GS (NRF first, then the rest, then the UPF as root for its TUN device), the guide's `gnb.yml` and `ue.conf` unchanged: the AMF on `127.0.0.5:38412`, the UE pool 10.45.0.x, the UPF's TUN at 10.45.0.1; a script that checks that Open5GS is stopped (the addresses collide) | `deploy/demo/host_demo.md` and scripts; I test everything except the `sudo` part, which only you can run |
| 3 | **subscribers without the Open5GS web UI**: provisioning from `ue.conf` in one command (the harness does it through the oracle's tooling now), the UDM's admin API / `g5c-ctl` for the rest; optionally a small page that lists and adds subscribers | `g5c-ctl` command, test |
| 4 | **what the audience sees**: one console that shows the milestones of the guide (gNB: NG Setup; AMF: registration, authentication, security mode, accept; SMF / UPF: session, N4; UE: IP address, ping) with the pcaps captured for Wireshark; our dashboard (Atlas) updated with the demo | demo console script, `docs/demo` |
| 5 | **NEA2 / NIA2 end to end with srsUE**, to show a ciphered NAS: a one-line fix (`msg[6]`) in a *separate copy* of your srsUE source, built into its own directory, so your build stays as it is; the fix is also what would go upstream | built binary, a demo run with `DEMO_CIPHERING=NEA2` |
| 6 | **more than one UE**: ZeroMQ links one UE to one gNB cell, so several srsUE need either several cells or the ZMQ broker; and the load test of Phase 6 with the load tool (you said later) | decided when we get there |
| 7 | the rest of Phase 8 goes on in parallel and is not a prerequisite: mutual TLS between the functions (the demo can run with it once it exists), secrets and keys, operations | ADR-0025 |

## Open questions for you
- Step 2: do you want the demo to replace Open5GS on the same addresses (the guide's `gnb.yml` unchanged), or run beside it on other addresses?
- Step 5: are you happy for me to patch a *copy* of srsUE (not your build) to show NEA2?
- Step 6: is one UE enough for the first demo?
