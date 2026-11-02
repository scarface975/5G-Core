# Operations runbooks

For a cluster started by `deploy/run/g5c-cluster.sh` (or the demo launcher `deploy/demo/g5c-demo`); `$RUN` is its run directory (`~/g5c-run`, `~/g5c-demo-run` for the demo). Alerts are in
`deploy/ops/prometheus-rules.yml`, the dashboard in `deploy/ops/grafana-g5c.json`, the scrape configuration in `deploy/ops/prometheus-scrape.yml`. Every function logs one line per significant
event to `$RUN/log/<function>.log`; changes made through the admin APIs are also logged with the tag `g5c_audit` (who changed which subscriber or policy):

```bash
grep g5c_audit $RUN/log/*.log
```

## Function down
Alert `G5cFunctionDown`. 1. `g5c-cluster.sh status` shows which function and why (pid, RSS, descriptors). 2. `tail -50 $RUN/log/<function>.log`: a start-up error is the last lines (bad
configuration, a certificate that does not match its key, a port in use). 3. `g5c-cluster.sh restart <function>` (state files and the UDR store survive). The functions that matter most for
sessions in progress are the UPF and the SMF; the rest re-register at the NRF by themselves when they come back (heart-beat every `registry.heartbeat_timer`, default 10 s).

## NRF registrations
`G5cNrfRegisteredFunctionsLow` / `G5cNrfSuspendedFunctions`. `curl` the NRF's `/nnrf-nfm/v1/nf-instances` (with the operator certificate when TLS is on:
`curl --cacert $RUN/pki/ca.crt --cert $RUN/pki/admin.crt --key $RUN/pki/admin.key https://127.2.0.10:7777/nnrf-nfm/v1/nf-instances`) to see who is registered. A function that is running but not
registered cannot reach its peers: look in its log for `register` errors (no route to the NRF, an access token refused, a certificate the NRF does not accept).

## Access token refusals
`G5cTokenChecksRejected`. Metric `g5c_oauth_checks_total{result}` says why: `missing`, `invalid`, `expired`, `audience`, `scope`. `expired` in bursts after an NRF restart is normal (the NRF has a new
key; consumers fetch the new key set and a token again within seconds). Persistent `invalid` or `audience` means a caller that is not one of our functions or was configured with the wrong NF
type. `missing` from a function of ours means its `oauth2.acquire` is off. Open5GS functions in the same cluster do not send tokens: run with `G5C_OAUTH2=0`.

## NAS integrity failures
`G5cNasIntegrityFailures`. A UE whose keys are out of step (it lost its context) is the usual cause and clears with a new registration. A rise across many UEs: look for a gNB or a
test tool that replays or rewrites NAS, and check `g5c_amf_authentications_total`.

## Authentication failures
`G5cAuthenticationFailures`. `g5c_amf_authentications_total{result}`: `failed` is a wrong RES* (a SIM with another K or OPc than provisioned: compare with `g5c-ctl subscriber get <supi>`), `ausf_error` is
the AUSF or the UDM answering an error (see their logs: `authentication vector generated` lines show the UDM answering; `5G AKA authentication succeeded` the AUSF).

## Registrations rejected
`G5cRegistrationsRejected`. The AMF log says the cause per UE (`reg_reject`): `5GS services not allowed` (no subscriber at the UDM: provision it), `TA not allowed` (the gNB's TAC is not
in the AMF's `tais`), `no slices available` (the NSSF refused every requested and subscribed slice, or none is served: `g5c_amf_nssf_selections_total{result="refused"}`).

## SBI errors
`G5cSbiServerErrors` / `G5cSbiLatencyHigh`. `g5c_sbi_requests_total{route,status}` names the route. 503 from a producer is a dependency down (the UDR for the UDM, the NRF for token keys). A slow route
with all functions up: check `g5c_scp_inflight` and `g5c_scp_quarantined` (a producer that failed repeatedly is skipped for a while), and the RSS and CPU of the function in `g5c-cluster.sh status`.

## UPF lost
`G5cUpfLost` / `G5cN4Timeouts` / `G5cPduSessionsDropToZero`. The SMF heart-beats the UPF over PFCP (`n4.heartbeat`); after `failures` misses the association is lost and the sessions on it are released
(`g5c_smf_sessions_released_upf_loss_total`). Restart the UPF (`sudo g5c-demo upf` or `g5c-cluster.sh restart upf`: it needs root for its TUN device); the SMF re-associates by itself; UEs
re-establish their sessions on their next service request or when they register again.

## No gNB
`G5cNoGnbConnected`. The gNB's NG Setup did not reach the AMF: its `amf_addr` must be the AMF's `amf.ngap.address` (SCTP port 38412), its PLMN and TAC in the AMF's `tais`, and the
address reachable. The AMF log shows `N2 association ... accepted` and `NG Setup from ...`, or the reject cause (`unknown-PLMN` is a TAC / PLMN mismatch).

## Capacity
`G5cUeAddressPoolHigh` / `G5cUpfDroppedPackets`. The UE pool is the `dnns[].ipv4_pool` of the SMF; a larger pool or a second UPF with its own pool. UPF drops: `g5c_upf_dropped_packets_total{reason}`.

## Certificates (mutual TLS)
Cluster started with `G5C_TLS=1` (the default of the demo). Expiry: `g5c-cluster.sh certs status` (the PKI script warns under 14 days: `deploy/run/g5c-pki.sh status $RUN/pki`).
Renewal without a restart: `g5c-cluster.sh certs renew` issues new certificates from the cluster CA and sends SIGHUP to every function; each reloads its certificate, key and CA for new
connections, as server and as client, and logs `certificates reloaded`. A damaged or mismatched file is refused (`certificate reload failed, the old ones stay in use`) and nothing changes.
Replacing the CA itself: issue every certificate from the new CA, put both CAs in `ca.crt` (concatenated PEM) on all functions, SIGHUP, then remove the old CA and SIGHUP again.
The CA key (`$RUN/pki/ca.key`) belongs offline on a production cluster: `issue` only needs it where certificates are made.

## Reading the SBI in Wireshark (TLS)
Start the function with `G5C_TLS_KEYLOG=/path/keys.log` in its environment (systemd: `Environment=` in a drop-in), capture on the SBI port with `tools/g5c-capture`, then in Wireshark set
Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename to the same file. The file holds session secrets: debugging only, delete it afterwards, never leave the variable set in production.

## Secrets
Keys and tokens are files named in the configuration (never values), mode 600, listed in `$RUN/keys`. `g5c-cluster.sh ns secrets` checks that none of them is in a log, a configuration
or a state file and that K and OPc are not in the clear at rest. The UDM's master key encrypts K and OPc (AES-256-GCM, the SUPI as associated data): losing it makes the stored credentials
unusable; keep a copy where the cluster is not.
