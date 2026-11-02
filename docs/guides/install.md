# Installation guide

Release 0.9.0-rc1. A host runs some or all of the twelve functions: NRF, SCP, BSF (optional), UDR, NSSF, NEF, UDM, AUSF, PCF, SMF, AMF and UPF. The AMF terminates N2 (SCTP, port 38412), the UPF
N3 (GTP-U, UDP 2152), N4 (PFCP, UDP 8805, with the SMF) and N6 (a TUN device); the rest is the service based interface (HTTP/2 over mutual TLS).

## 1. Requirements
| | |
|---|---|
| OS | Linux with SCTP support in the kernel (`modprobe sctp`), x86-64; Ubuntu 24.04 is what the release is built and tested on (also WSL2 Ubuntu) |
| Libraries at run time | OpenSSL 3, nghttp2, libuv, libpq (only for the UDR's PostgreSQL store) |
| To build | gcc, cmake 3.20, pkg-config, the development packages of the four libraries above (`sudo apt install build-essential cmake pkg-config libssl-dev libnghttp2-dev libuv1-dev libpq-dev`) |
| Hardware | one host is enough for a lab: 8 vCPU, 4 GB. Each function needs 10 to 25 MB at 2000 sessions; the UPF needs `/dev/net/tun` and CAP_NET_ADMIN |
| Not needed | MongoDB, Open5GS, a database server (the UDR can keep its store in a journalled file; PostgreSQL is optional) |

## 2. Get the binaries
From a release archive (`g5c-0.9.0-rc1.tar.gz`, with `SHA256SUMS` and a detached signature): verify, unpack, install.
```bash
sha256sum -c SHA256SUMS
gpg --verify g5c-0.9.0-rc1.tar.gz.asc g5c-0.9.0-rc1.tar.gz     # with the release public key (release/g5c-release-pub.asc)
tar xzf g5c-0.9.0-rc1.tar.gz && cd g5c-0.9.0-rc1
```
From the source tree: `bash scripts/c_install.sh` builds and puts the functions into `~/.cache/g5c-bin/bin`.

## 3. Install on a host
```bash
sudo bash deploy/install.sh              # or: sudo bash install.sh from the release archive
```
This puts the functions into `/usr/local/bin`, the units `g5c@<function>.service` and `g5c.target` into `/etc/systemd/system`, creates the user `g5c`, `/etc/g5c` (keys in `/etc/g5c/keys`, mode 700),
`/var/lib/g5c` and a CA in `/etc/g5c/pki`, and the example configurations in `/etc/g5c/examples`. It never overwrites a configuration that exists.

## 4. Configure
Copy an example to `/etc/g5c/<function>.yaml` and edit it. What every function shares: `name`, `plmn`, `sbi: { address, port, tls }`, `nrf: { uri }`, `scp_client`, `oauth2`, `log`. The functions find their
peers through the NRF, so no peer address is in a configuration except the NRF's. A bad configuration is refused at start with the key that is wrong (`<function> --check /etc/g5c/<function>.yaml`
checks without starting).

Per function: the AMF's `amf.ngap.address` (the address the gNBs connect to), `amf.tais` (the tracking areas it serves; the gNB's TAC must be one of them), `amf.slices`, `amf.security`; the SMF's
`smf.upfs`, `smf.dnns` (UE address pools), `smf.cdr.file` (charging records); the UPF's `upf.gtpu`, `upf.pfcp`, `upf.n6.device`; the UDM's `hn_keys`, `master_key_file`, `admin_token_file`; the UDR's `store`.
Secrets are always files named in the configuration (mode 600, owner `g5c`), never values. A file name may be `exec:/absolute/command args`: the command's output is the secret (a vault or KMS client).

## 5. Certificates (mutual TLS)
Every function listens on https and demands a client certificate from the cluster CA; the cluster default also requires the NRF's access tokens.
```bash
sudo -u g5c bash deploy/run/g5c-pki.sh issue /etc/g5c/pki amf 10.0.0.5        # a certificate per function, its address(es) as names
```
Point `sbi.tls: { cert: /etc/g5c/pki/amf.crt, key: /etc/g5c/pki/amf.key, ca: /etc/g5c/pki/ca.crt }` at it. Renewal without a restart: issue again (`g5c-pki.sh renew`) and `systemctl reload g5c@amf`.

## 6. Start
```bash
sudo systemctl enable --now g5c@nrf g5c@scp g5c@udr g5c@nssf g5c@udm g5c@ausf g5c@pcf g5c@smf g5c@amf g5c@upf
systemctl status 'g5c@*'        # all up
journalctl -u g5c@amf -f        # the log of one function
```
Start the NRF first; the others register at it. Provision a subscriber (the UDM's admin API; `g5c-ctl` is its command line):
```bash
g5c-ctl --udm https://udm.example:7773 --token-file /etc/g5c/keys/udm-admin.token subscriber add --supi imsi-001010000000001 --k <32 hex> --opc <32 hex> --slice 1 --dnn internet
```
A gNB then connects to the AMF's `ngap.address`:38412.

## 7. Check
`GET /health/ready` on every function (operator certificate), `g5c_build_info` in `/metrics` (the version that runs), the log line `g5c 0.9.0-rc1: amf starting`, and the AMF's log
`NG Setup from ...` when a gNB connects. For a complete, scripted example of all of this on one machine see `deploy/demo/g5c-demo` and `docs/demo/host-demo.md`.

## 8. Without systemd (a lab, a demo)
`deploy/run/g5c-cluster.sh up` writes configurations, a PKI and keys for a whole cluster under `~/g5c-run` and starts it (`down`, `status`, `logs`, `certs renew`); `run <function>` starts one in the
foreground of a terminal.

## 9. Containers and Kubernetes
`deploy/docker/Dockerfile` and `deploy/compose/compose.yaml` build and run the functions in containers; `deploy/k8s/` has manifests. **Neither has been built or applied: no container runtime and no
Kubernetes cluster was available when they were written.** Treat them as a starting point and run `docker build` and a `kubectl apply --dry-run=server` before relying on them.
