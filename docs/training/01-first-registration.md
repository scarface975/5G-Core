# Exercise 01: Start a core and register UEs

## Goal
Bring the whole core up in a private network namespace, register twenty simulated UEs with PDU sessions, and read the numbers the core gives about it.

## Do it by hand
From the root of the repository, in a built tree on Linux (WSL is fine; the cluster script needs user namespaces and no root). `tools/cli/g5c-lab check 01` does the whole exercise on a private cluster and judges it.

1. `bash deploy/run/g5c-cluster.sh ns scenario scenarios/basic-wave.yaml` runs the whole exercise. By hand, in a shell that has a user namespace (see the cluster script's header): `g5c-cluster.sh up`, then `g5c-cluster.sh load 20 4`.
2. `g5c-cluster.sh status` lists the twelve functions and their ports. `g5c-cluster.sh url amf` prints where the AMF's SBI is.
3. `tools/cli/g5c-kpi $(g5c-cluster.sh url amf)/metrics $(g5c-cluster.sh url smf)/metrics $(g5c-cluster.sh url upf)/metrics` computes the service KPIs.

## What you should see
Registrations accepted: 20 or more. Registration and PDU session success rates of 99 % or more. All functions answer `/health/live`.

## Why
Every function is a separate process that registers at the NRF and finds its peers there; the load tool plays the gNBs and UEs (AKA keys and all) over real SCTP, so the numbers come from the real signalling path.
