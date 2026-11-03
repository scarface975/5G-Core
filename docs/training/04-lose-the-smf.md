# Exercise 04: Kill the SMF in the middle of a wave

## Goal
See what a restart of a function does to the traffic in flight, and that the core recovers by itself.

## Do it by hand
From the root of the repository, in a built tree on Linux (WSL is fine; the cluster script needs user namespaces and no root). `tools/cli/g5c-lab check 04` does the whole exercise on a private cluster and judges it.

1. `g5c-cluster.sh load 600 8` in one terminal; in another, `g5c-cluster.sh kill smf`, wait a second, `g5c-cluster.sh start smf`.
2. Run a second, small wave: `g5c-cluster.sh load 50 4`.

## What you should see
UEs in flight when the SMF died may fail (that is not judged); the clean wave afterwards completes.

## Why
The AMF, the PCF and the UPF keep working, the SMF re-registers at the NRF and the others find it again; nothing needs a manual step.
