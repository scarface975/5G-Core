# Host demo: OCUDU gNB + srsUE (ZMQ) against our 5G core, replacing Open5GS

Same layout as the startup guide: one terminal per function, one for the gNB, one for the UE, one for the ping. Your `gnb.yml` and `ue.conf` stay as they are
(`/etc/open5gs/`). Our AMF takes Open5GS's address (127.0.0.5:38412), the UPF's TUN device is `ogstun` 10.45.0.1/16, the UE gets 10.45.0.x.

The command is `/home/work/g5c-demo` (created by `prepare`; before that it is
`/mnt/c/Users/Work/Documents/5G_core/deploy/demo/g5c-demo`).

## Once
Terminal 0, as your user (no sudo). It builds and installs our functions, checks the gNB and srsUE exist, and makes `/home/work/g5c-demo`:
```bash
bash /mnt/c/Users/Work/Documents/5G_core/deploy/demo/g5c-demo prepare
```
Open5GS must not run (same addresses). `prepare` and `check` tell you; if it does:
```bash
sudo systemctl stop 'open5gs-*'
```
(or Ctrl+C the Open5GS terminals).

## Every demo
Open 14 WSL terminals (the UE's ping can reuse terminal 1). In each, run its line, in this order.

| # | Terminal | Command |
|---|---|---|
| 1 | data path (run, then reuse it) | `sudo /home/work/g5c-demo net` |
| 2 | NRF | `sudo /home/work/g5c-demo nrf` |
| 3 | SCP | `sudo /home/work/g5c-demo scp` |
| 4 | UDR | `sudo /home/work/g5c-demo udr` |
| 5 | UDM | `sudo /home/work/g5c-demo udm` |
| 6 | AUSF | `sudo /home/work/g5c-demo ausf` |
| 7 | PCF | `sudo /home/work/g5c-demo pcf` |
| 8 | NSSF | `sudo /home/work/g5c-demo nssf` |
| 9 | NEF | `sudo /home/work/g5c-demo nef` |
| 10 | SMF | `sudo /home/work/g5c-demo smf` |
| 11 | UPF | `sudo /home/work/g5c-demo upf` |
| 12 | AMF | `sudo /home/work/g5c-demo amf` |

Then, in terminal 1 (the subscriber of `ue.conf` goes into our UDM; this replaces the Open5GS web UI):
```bash
sudo /home/work/g5c-demo provision
```
Terminal 13, the gNB (exactly as the guide):
```bash
sudo /home/work/ocudu/build/apps/gnb/gnb -c /etc/open5gs/gnb.yml
```
Wait for "gNB started"; the AMF terminal prints `NG Setup from ... (ocucp01)`.

Terminal 14, the UE (the guide's command plus `--gw.netns=ue1`, which puts its tunnel in a namespace so the ping must cross the radio, gNB and core):
```bash
sudo /home/work/srsRAN_4G/build/srsue/src/srsue /etc/open5gs/ue.conf --gw.netns=ue1
```
Wait for `PDU Session Establishment successful. IP: 10.45.0.2`. Then in terminal 1 (or a 15th):
```bash
sudo /home/work/g5c-demo ping
```
That is `ping -c 5 10.45.0.1` from the UE's namespace. Anything else: `sudo /home/work/g5c-demo ping -c 20 10.45.0.1`.

## What each terminal shows
- NRF: `registered <TYPE> <id>` as each function starts.
- SMF: `N4 association with UPF upf-1 established`; later `PDU session 1 of imsi-... created`.
- UPF: `UPF up: N4 ..., N3 ..., N6 ogstun`; later `session 1 established ... UE 10.45.0.2`.
- AMF: `N2 (SCTP) listening on 127.0.0.5:38412`, `NG Setup from ... (ocucp01)`, `imsi-... registered`.
- UDM: `subscriber ... provisioned`, `authentication vector generated`, `AMF registration stored`.
- AUSF: `5G AKA authentication succeeded`.
- PCF: `AM policy association ... created`, `SM policy ... created`.
- SCP / NSSF / NEF: quiet unless something goes wrong.
- Between the functions everything runs over mutual TLS (https, a certificate per function from a CA that `net`/the first function creates in `/home/work/g5c-demo-run/pki`) with the NRF's access tokens on top. No warnings about missing TLS any more; each terminal prints `SBI listening on ... (https)`.

## Rules
- **Restart order**: if you stop the UE or gNB, restart the gNB first, then the UE (srsRAN's ZMQ radio does not recover when one side restarts alone).
- Status: `/home/work/g5c-demo status` (as root it also shows ogstun and the UE address).
- Stop everything: `sudo /home/work/g5c-demo stop`. Fresh start (also removes ogstun, ue1 and demo state): `sudo /home/work/g5c-demo reset`, then repeat from `net`.
- The core uses NEA0 for NAS ciphering (integrity NIA2) because srsUE cannot decipher NEA1/2/3 in 5G NAS (a bug in its `cipher_decrypt`; see `docs/demo/zmq-demo.md`).
- Options (put in front of every function command, same value everywhere): `DEMO_TLS=0` (cleartext between the functions), `DEMO_OAUTH2=0` (no access tokens), `DEMO_BSF=1` (the optional BSF: `sudo env DEMO_BSF=1 /home/work/g5c-demo bsf`, and start the PCF with it too).
- Tested without sudo: `deploy/demo/host_selftest.sh` runs these exact commands in a private namespace (PASS including the restart and a second ping).

## NEA2 (ciphered NAS) with a patched copy of srsUE
Your srsUE stays untouched. A copy with a one-line fix is built in `/home/work/srsRAN_4G_nea2` (the patch is `nea2-fix.patch` there: `msg[5]` becomes `msg[seq_offset]` in `nas_base.cc` `cipher_decrypt`).
Built with: `cd /home/work/srsRAN_4G_nea2/build && cmake .. -DENABLE_ZEROMQ=ON && make -j7 srsue`.
Tested: patched UE + core with NEA2 = registration, PDU session, ping 5/5; your original UE + core with NEA2 = never registers (that is the bug).

To demo it, start the AMF with NEA2 (the other functions as before) and the patched UE:
```bash
sudo env DEMO_CIPHERING=NEA2 /home/work/g5c-demo amf
```
```bash
sudo /home/work/srsRAN_4G_nea2/build/srsue/src/srsue /etc/open5gs/ue.conf --gw.netns=ue1
```
Go back to your own UE and NEA0 by starting the AMF without `DEMO_CIPHERING`.

## Certificates: renewing them while the demo runs
Certificates are valid for 90 days. To replace them without stopping anything (each terminal logs `certificates reloaded`):
```bash
sudo env G5C_TLS=1 G5C_RUN=/home/work/g5c-demo-run /mnt/c/Users/Work/Documents/5G_core/deploy/run/g5c-cluster.sh certs renew
```
