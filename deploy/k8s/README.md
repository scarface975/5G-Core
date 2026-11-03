# Kubernetes manifests

`base/` is a kustomize base for the whole core, generated from the compose model (`deploy/compose/compose.yaml` and its `config/`) by `python3 tools/gen/gen_k8s.py`, so the two cannot drift. `tests/support/test_k8s.py`
checks that they are fresh and that every reference resolves.

**Status: generated and cross-checked, never applied.** There is no container runtime or cluster in the environment this repository is tested in: the image (`deploy/docker/Dockerfile`) has not been built here either.
A Helm chart and an operator are not part of this release.

## What is in it
* one namespace `g5c` (pod security: enforce baseline, warn restricted);
* per function: a ConfigMap (the sample configuration), a Deployment (one replica, `Recreate`), a Service on its SBI port, and a claim for `/var/lib/g5c` where the function keeps state; the AMF's N2 is an SCTP
  port, the UPF's N3 and N4 are UDP ports;
* pods that are restricted: non-root, read-only root file system, all capabilities dropped, seccomp `RuntimeDefault`, no service account token. The UPF alone adds `NET_ADMIN` and mounts `/dev/net/tun` (its N6 device);
* default-deny network policies, with the traffic inside the namespace allowed, N2 to the AMF and N3 to the UPF from anywhere;
* the addresses of the compose network that the sample configurations contain (`10.100.0.x`) are rendered when a pod starts, by an init container: a function's own address becomes its pod IP, a peer's becomes the
  address of that peer's Service;
* secrets are not generated: the pods mount the keys they need from one Secret, `g5c-secrets`.

## Use
```
bash deploy/compose/gen-secrets.sh                     # makes the keys and tokens in deploy/compose/secrets and keys
kubectl create namespace g5c
kubectl -n g5c create secret generic g5c-secrets --from-file=deploy/compose/secrets --from-file=deploy/compose/keys
docker build -t REGISTRY/g5c:0.9.0-rc1 -f deploy/docker/Dockerfile . && docker push REGISTRY/g5c:0.9.0-rc1
cd deploy/k8s/base && kustomize edit set image g5c=REGISTRY/g5c:0.9.0-rc1 && cd - && kubectl apply -k deploy/k8s/base
```

## What you must still decide
* **Reaching the core from the radio network.** N2 (SCTP) and N3 (UDP) are ClusterIP Services here. A gNB outside the cluster needs a `LoadBalancer` or `hostNetwork` that carries SCTP, and the UPF advertises its pod IP
  as the N3 address, so the gNB must be able to route to pod addresses (or the UPF must run with `hostNetwork`).
* **Probes** are TCP-level because the sample configurations serve cleartext HTTP/2, which the kubelet's HTTP probe cannot speak. With `sbi.tls` set, use `httpGet` probes.
* **State** is a `ReadWriteOnce` claim per function and one replica: this is not a high-availability deployment (shared-state HA is an open item of the release).
* **TLS and tokens** are off in the sample configurations. Production needs `sbi.tls`, `oauth2`, certificates (`deploy/run/g5c-pki.sh`) and the admin tokens of `docs/guides/admin-guide.md`.
* The SCP's compose allow-list `10.100.0.0/24` is opened to `0.0.0.0/0` (the network policies confine the traffic).
