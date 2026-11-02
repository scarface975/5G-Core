# Upgrade and rollback guide

Release 0.9.0-rc1. The functions are separate processes that register at the NRF and find each other there, so a core is upgraded one function at a time while it carries traffic. This is what
`g5c-cluster.sh ns upgrade` does under load on every regression (every function restarted gracefully one at a time with the new binaries, then with the previous ones: a clean wave of new
subscribers must pass at the end).

## What survives a restart
| Function | State | After the restart |
|---|---|---|
| UDR | the store (journalled file or PostgreSQL) | everything, including subscribers and subscriptions |
| UDM, AUSF | state files (`state_file`), the AUSF's encrypted with its master key | authentication contexts in progress |
| AMF | `amf.state_file`: UE contexts and registrations | the registrations are restored; the radio connections are not (the gNBs reconnect and the UEs come back with a service request or a new registration) |
| SMF | `smf.state_file`: PDU sessions | sessions are kept; the UPF's sessions are checked against them when the association is re-established |
| UPF | none: its sessions live in memory | the SMF notices the new recovery time stamp (PFCP association) and releases the sessions that were on it; the UEs re-establish them |
| NRF | `registry.state_file` and its token signing key | the other functions re-register by themselves at their next heart-beat |
| SCP, BSF, NEF, NSSF, PCF | their state files where they have one | their cached data is rebuilt from the NRF and the UDR |

## Procedure
Order: the functions that hold the least state first, the UPF and the AMF last, the NRF at the very end.
```
udr udm ausf pcf nssf nef bsf scp smf amf upf nrf
```
For each function: install the new binary beside the old one (`/usr/local/bin/<f>.new`), `mv` it over the old one, `systemctl restart g5c@<f>`, then wait for `GET /health/ready` and the
NRF's registration (`g5c_nrf_profiles`). The next function only when the previous is ready. Between the UPF and the AMF the UEs on the radio see at most a re-establishment of their
sessions. Check after each step: `g5c_amf_registered_ues` unchanged, no alert of `deploy/ops/prometheus-rules.yml`.

A single host with the install script: `sudo bash deploy/install.sh` copies the new binaries (the old ones are overwritten: keep a copy, `cp -a /usr/local/bin /root/g5c-prev-bin`), then restart as above.

## Rollback
The same procedure with the previous binaries (the copy). State files are read by the previous release without conversion within 0.9; a release that changes a state file's format says so in
`CHANGELOG.md` and reads the old format. If a function does not start after an upgrade, its log says why (`journalctl -u g5c@<f>`; a bad key of the configuration is named); put the previous binary
back and restart it. Nothing else has to change.

## Configuration changes
A new configuration key never changes behaviour without being set. An unknown key is refused at start (so a typo is not silently ignored): `<f> --check` before the restart.

## Keys and certificates
Certificates are renewed without a restart (`g5c-pki.sh renew`, then `systemctl reload g5c@<f>` for each function). The UDM's master key is rotated with `master_key_previous_file` and `POST /admin/v1/keys/rewrap`
(see `docs/guides/admin-guide.md`), tested by `g5c-cluster.sh ns ops`.

## Version
`g5c_build_info{version=...}` of every function's `/metrics`, the first log line of each start, `cat /usr/share/doc/g5c/VERSION`.
