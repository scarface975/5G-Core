# Running the network functions as processes

Every network function is a normal Unix daemon: one binary, one YAML file, logs on stdout/stderr, SIGTERM for a clean stop.
There is nothing to install besides the binaries (`scripts/c_install.sh` puts them in `~/.cache/g5c-bin/bin`).

| NF | binary | listens on (defaults of `g5c-cluster.sh`) |
|---|---|---|
| UDR | `udr` | SBI 127.2.0.201:7790 (provisioning token in `$G5C_RUN/keys/udr-provisioning.token`, shared with the UDM) |
| UDM | `udm` | SBI 127.2.0.1:7773 (+ `/admin/v1`) |
| AUSF | `ausf` | SBI 127.2.0.2:7774 (5G AKA, EAP-AKA', SoR / UPU protection) |
| PCF | `pcf` | SBI 127.2.0.3:7775 (+ `/admin/v1`) |
| SMF | `smf` | SBI 127.2.0.4:7776, N4 (PFCP/UDP) 127.2.0.4:8805 |
| AMF | `amf` | SBI 127.2.0.5:7777, N2 (SCTP, PPID 60) 127.2.0.5:38412 |
| UPF | `upf` | SBI 127.2.0.7:9091 (health, metrics only), N4 127.2.0.7:8805, N3 (GTP-U) 127.2.0.7:2152, N6 = a TUN device |

(NRF, NSSF, NEF and SCP arrive in Phase 7; until then the NFs are wired by URI in their configuration.)

## One terminal per NF, like `open5gs-amfd`

```bash
bash deploy/run/g5c-cluster.sh conf          # writes ~/g5c-run/conf/*.yaml and the test keys
bash deploy/run/g5c-cluster.sh run udr  # terminal 1 - logs on the terminal, Ctrl-C stops it
bash deploy/run/g5c-cluster.sh run udm       # terminal 2
bash deploy/run/g5c-cluster.sh run ausf # ...
bash deploy/run/g5c-cluster.sh run pcf
sudo bash deploy/run/g5c-cluster.sh run upf  # the TUN device needs privileges (CAP_NET_ADMIN), or create it first and drop sudo:
                                             #   sudo ip tuntap add name ogstun mode tun user $USER; sudo ip addr add 10.45.0.1/16 dev ogstun; sudo ip link set ogstun up
bash deploy/run/g5c-cluster.sh run smf
bash deploy/run/g5c-cluster.sh run amf
```

The same without the helper: `~/.cache/g5c-bin/bin/amf ~/g5c-run/conf/amf.yaml`. Check a configuration without starting anything:
`amf --check ~/g5c-run/conf/amf.yaml`.

Logs are text by default (`G5C_LOG_JSON=true` for JSON lines, `G5C_LOG_LEVEL=debug` for more) and every NF serves
`/health/live`, `/health/ready` and Prometheus `/metrics` on its SBI port:

```bash
curl --http2-prior-knowledge http://127.2.0.5:7777/metrics | grep g5c_amf_
bash deploy/run/g5c-cluster.sh status        # which NFs run, RSS, descriptors, CPU, and the AMF / SMF / UPF gauges
```

## All at once, in the background

```bash
bash deploy/run/g5c-cluster.sh up            # start everything, wait for each to be live
bash deploy/run/g5c-cluster.sh logs          # follow all logs   (logs amf: one NF)
bash deploy/run/g5c-cluster.sh restart smf   # stop and start one NF (state files and the UDR store survive)
bash deploy/run/g5c-cluster.sh kill upf      # kill -9, for failure injection; `start upf` brings it back
bash deploy/run/g5c-cluster.sh down
```

Provision a subscriber (the admin token is in `~/g5c-run/keys/admin_token`):

```bash
curl --http2-prior-knowledge -X POST http://127.2.0.1:7773/admin/v1/subscribers \
  -H "authorization: Bearer $(cat ~/g5c-run/keys/admin_token)" -H 'content-type: application/json' \
  -d '{"supi":"imsi-001010000000001","k":"465b5ce8b199b49faa5f0a2ee238a6bc","op":"cdc202d5123e20f62b6d676ac72cb318"}'
```

To let a RAN on another host reach the core, set the addresses before `conf` / `up`: `G5C_AMF_ADDR` (N2 and SBI),
`G5C_UPF_ADDR` (N3 / N4), `G5C_SMF_ADDR`, and `G5C_N6_DEV` / `G5C_UE_POOL` for the data network.

## Tests that need no privileges

A private user + network namespace (own loopback, own TUN device; nothing leaves the process tree):

```bash
bash deploy/run/g5c-cluster.sh ns load 1000 16 2       # 1,000 UEs over 16 gNBs, two waves: registration, PDU session, de-registration
bash deploy/run/g5c-cluster.sh ns chaos 400 60         # the same load while NFs are killed (kill -9) and restarted; a clean wave must then pass
bash deploy/run/g5c-cluster.sh ns soak 500 3600        # waves for an hour; every NF's RSS must stay flat
bash deploy/run/g5c-cluster.sh ns shell                # a shell inside the namespace with the cluster up
```

The load generator is `nf/amf/tests/load_core.c` (`G5C_LOAD_*` variables are listed at the top of the file). Each simulated UE derives its own keys
(Milenage, 5G-AKA, NAS and AS keys) and verifies what the network sends, so a wrong MAC or key fails the run; the counts of UE contexts, SMF sessions and
UPF sessions are read from the NFs' `/metrics` and must return to where they started.

`ctest` runs the same through `cluster_load` and `cluster_chaos` (skipped where user namespaces are unavailable), and `scripts/g5c_regress.sh` reports
the scale and chaos results in its summary.

## Discovery mode (the default since the NRF exists)

`g5c-cluster.sh` starts the NRF first (127.2.0.10:7777). Every other configuration then carries only `nrf: { uri: 'http://127.2.0.10:7777' }`: the UDM
and PCF find the UDR, the AUSF the UDM, the SMF the UDM, PCF and AMF, the AMF the AUSF, UDM, PCF and SMF, all through Nnrf_NFDiscovery. Look at it:

```bash
curl --http2-prior-knowledge 'http://127.2.0.10:7777/nnrf-nfm/v1/nf-instances'                     # who is registered
curl --http2-prior-knowledge 'http://127.2.0.10:7777/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF'
curl --http2-prior-knowledge 'http://127.2.0.10:7777/metrics' | grep g5c_nrf_
```

`G5C_DISCOVERY=0` writes the earlier configurations (peer addresses named, no NRF). The registry is in `~/g5c-run/state/nrf.json`.
