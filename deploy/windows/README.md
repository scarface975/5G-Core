# Double-click launchers (Windows) for the network functions

Each function runs in its own console window and prints its log continuously, the way `open5gs-amfd` does. The functions are Linux programs, so
the windows start them inside WSL Ubuntu; nothing else is needed.

| File | Function | What it talks to |
|---|---|---|
| `0-prepare.bat` | builds the functions once (a few minutes) and writes the configuration | |
| `1-nrf.bat` | NRF | every other function registers here, heart-beats, and finds its peers here (Nnrf_NFManagement / NFDiscovery / AccessToken) |
| `12-scp.bat` | SCP | indirect communication (TS 29.500 6.10): every function sends its requests to the other functions through it (except to the NRF); started by `9-start-all.bat` right after the NRF |
| `13-bsf.bat` | BSF | the PCF registers the binding of every PDU session that has a UE address; the NEF asks which PCF holds a UE address (Nbsf_Management); started by `9-start-all.bat` before the UDR |
| `2-udr.bat` | UDR | stores subscribers and policy data; used by the UDM and PCF (N35 / N36) |
| `10-nssf.bat` | NSSF | slice selection and NSSAI availability (N22); started by `9-start-all.bat` after the UDR |
| `11-nef.bat` | NEF | traffic influence and monitoring events for application functions (northbound APIs); started by `9-start-all.bat` |
| `3-udm.bat` | UDM | UDR; serves the AMF, SMF and AUSF (N8 / N10 / N13); subscriber admin API |
| `4-ausf.bat` | AUSF | finds the UDM at the NRF; serves the AMF (N12): 5G AKA and EAP-AKA'; SoR / UPU protection for the UDM |
| `5-pcf.bat` | PCF | UDR; serves the SMF (N7) and AMF (N15) |
| `6-upf.bat` | UPF | listens for the SMF on N4 and for the gNB on N3; creates the TUN device for N6 (starts as root through WSL, no password) |
| `7-smf.bat` | SMF | UDM, PCF, UPF (N4), AMF (N1N2 transfer) |
| `8-amf.bat` | AMF | gNB on N2 (SCTP); UDM, AUSF, PCF, SMF |
| `9-start-all.bat` | opens windows 1-8 in dependency order | |
| `90-status.bat` | which functions run, memory, and the AMF / SMF / UPF counters | |
| `99-stop-all.bat` | stops every function | |

The AUSF and UDR shims are listed because the five functions (AMF, SMF, UPF, PCF, UDM) cannot register a UE without them until Phase 7 builds the real ones.

## First time

1. Double-click `0-prepare.bat` and wait for "Done".
2. Double-click `9-start-all.bat` (or `1-nrf.bat` ... `8-amf.bat` one by one, in that order).
3. Check with `90-status.bat`: all eight `up`, the NRF log shows each function registering, and the SMF log shows `N4 association with UPF upf-1 established`.

Ctrl+C or closing a window stops that function; start its `.bat` again to bring it back (state files and the subscriber store survive; the NRF keeps its
registry in its state file, and the functions register again by themselves when they find it back).

## Addresses (all inside WSL, so the gNB and UE must run in WSL too)

| Function | SBI (HTTP/2) | Other |
|---|---|---|
| NRF | 127.2.0.10:7777 | `/nnrf-nfm/v1`, `/nnrf-disc/v1`, `/oauth2/token`, `/oauth2/jwks` |
| UDR | 127.2.0.201:7790 | |
| UDM | 127.2.0.1:7773 | admin API `/admin/v1`, token in `~/g5c-run/keys/admin_token` (WSL) |
| AUSF | 127.2.0.2:7774 | |
| PCF | 127.2.0.3:7775 | |
| SMF | 127.2.0.4:7776 | N4 PFCP/UDP 127.2.0.4:8805 |
| AMF | 127.2.0.5:7777 | **N2 SCTP 127.2.0.5:38412** (PLMN 001/01, TAC 1 and 2, slice SST 1) |
| UPF | 127.2.0.7:9091 (health, metrics) | N4 PFCP/UDP 127.2.0.7:8805, **N3 GTP-U 127.2.0.7:2152**, N6 TUN `ogstun` 10.45.0.1/16 (UE pool 10.45.0.0/16) |

**Discovery.** The functions are not told each other's addresses: each configuration names only the NRF (`nrf: { uri: 'http://127.2.0.10:7777' }`), and the
UDM, PCF, AUSF, SMF and AMF ask it for their peers (UDR, UDM, AUSF, PCF, SMF, AMF) when they need them. The only fixed address between functions is the
SMF's list of UPFs for N4. The files are `~/g5c-run/conf/*.yaml` in WSL (written once by `0-prepare.bat`; delete the folder to have them written again,
after changing `settings.bat`). `G5C_DISCOVERY=0` in `settings.bat` (`G5C_EXTRA_ENV`) gives the configurations of the earlier static wiring and no NRF.

For a gNB on the Windows side or another machine, set the address the gNB can reach in `settings.bat`, for example
`set G5C_EXTRA_ENV=G5C_AMF_ADDR=<WSL ip> G5C_UPF_ADDR=<WSL ip>` (use the same value in every window), and remove `~/g5c-run/conf`.

## Provisioning a subscriber and testing without a RAN

```bash
# in WSL
curl --http2-prior-knowledge -X POST http://127.2.0.1:7773/admin/v1/subscribers \
  -H "authorization: Bearer $(cat ~/g5c-run/keys/admin_token)" -H 'content-type: application/json' \
  -d '{"supi":"imsi-001010000000001","k":"465b5ce8b199b49faa5f0a2ee238a6bc","op":"cdc202d5123e20f62b6d676ac72cb318"}'
# what the NRF knows
curl --http2-prior-knowledge 'http://127.2.0.10:7777/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF'
# 200 simulated UEs through the running windows
G5C_LOAD_REMOTE=1 G5C_LOAD_UES=200 G5C_LOAD_GNBS=8 ~/g5c-cbuild/plain/nf/amf/load_core
```

Logs are also appended to `~/g5c-run/log/<function>.log`. `G5C_LOG_LEVEL=debug` in `G5C_EXTRA_ENV` turns on more detail.
