# Oracle test harness (TEST ONLY)

An isolated **Open5GS** core plus **UERANSIM** UE/gNB used to (a) record golden traces and (b) later interop-test our
NFs one at a time. Nothing here ships in the product (ADR-0002). Runs in WSL Ubuntu.

## Isolation guarantees
Safe to run next to another Open5GS instance on the same machine (e.g. `~/o5gs-run`):
loopback `127.1.0.x` (other instance: `127.0.0.x`), MongoDB database `g5c_oracle`, PLMN `001/01`,
TUN `ogstun5g` / `10.46.0.0/16`, all state in `~/g5c-oracle`. `oracle.sh down` only signals PIDs it recorded.
Configs are generated at run time from a template dir (`O5GS_TEMPLATE_CONF`, default `~/o5gs-run/conf`) with
`sed` remapping, so no Open5GS-derived files live in this repo.

## Prerequisites (already present on the dev box)
Open5GS binaries in `/usr/bin` (v2.8.0), `mongod` running, `mongosh`, `dumpcap`/`tshark`.
UERANSIM is built outside the repo: `git clone https://github.com/aligungr/UERANSIM ~/test-peers/UERANSIM && make -C ~/test-peers/UERANSIM`
(AGPL-3.0 / commercial dual licence; test-only, never redistributed).
Do **not** open the Open5GS source tree (`~/../open5gs/src`) while implementing; use binaries, logs and captures only.

## Commands
```
deploy/oracle/oracle.sh {gen|up|down|status|provision|capture-start|capture-stop}
deploy/oracle/scenario.sh s1     # registration + deregistration, no root needed
deploy/oracle/scenario.sh s2     # + PDU session and ping (needs TUN setup below)
```
Run from WSL: `wsl -d Ubuntu -- bash /mnt/c/Users/Work/Documents/5G_core/deploy/oracle/scenario.sh s1`.

## S2 / S3 need no sudo
`scenario.sh s2|s3` re-executes itself inside an unprivileged user + network namespace (`unshare -Urn`), where it owns
loopback, the UPF TUN device and a private MongoDB (`mongo-ns`). A nested namespace (10.99.0.1) plays the data network
behind the UPF and the UE's TUN is moved into its own namespace, so the ping really travels
UE -> gNB (GTP-U) -> UPF -> data network and back. S3 additionally releases the PDU session.

## Interop with our own NFs
```
scripts/c_install.sh
OUR_UDM=1 deploy/oracle/scenario.sh s3
```
Open5GS's UDM is not started; our UDM (127.1.0.1:7773, registered with the oracle NRF) and our UDR-lite
(127.1.0.201:7790) take its place, are provisioned through the UDM admin API (token and keys under `~/g5c-oracle/keys`,
generated test keys only), and Open5GS's AMF, AUSF, SMF and PCF talk to them. Logs: `~/g5c-oracle/log/g5udm.stdout`.

### Our PCF, and a policy change while a session is up
```
scripts/c_install.sh
OUR_PCF=1 deploy/oracle/scenario.sh s3                # Open5GS AMF/SMF use our PCF
OUR_UDM=1 OUR_PCF=1 deploy/oracle/scenario.sh s4      # our UDM and PCF; S4 changes policy mid-session
```
`s4` throttles the subscriber and adds a dedicated PCC rule through the PCF admin API (`127.1.0.13:7777`,
token in `~/g5c-oracle/keys/admin_token`); the PCF notifies Open5GS's SMF, which then updates the UPF over PFCP (see the
pcap in `~/g5c-oracle/pcap/s4-*.pcapng`). PCF log: `~/g5c-oracle/log/g5pcf.stdout`.
