# Exercise 07: Survive a signalling storm

## Goal
Let eight gNBs send registrations back to back and see the AMF admit about twenty a second and refuse the rest at once, with a back-off timer.

## Do it by hand
From the root of the repository, in a built tree on Linux (WSL is fine; the cluster script needs user namespaces and no root). `tools/cli/g5c-lab check 07` does the whole exercise on a private cluster and judges it.

1. Configure `amf: overload: { registrations_per_s: 20, burst_s: 1, t3346_s: 10 }`.
2. `G5C_LOAD_STORM_SECONDS=4 g5c-cluster.sh load 400 8` and read the `storm:` line it prints.
3. Then run a normal wave: it works.

## What you should see
Thousands of registrations refused with cause #22 (`g5c_amf_registrations_total{result="congestion"}`), 100 or so admitted, the AMF ready throughout.

## Why
A refusal costs the AMF almost nothing, while a registration costs a whole authentication; admitting a fixed rate keeps the core serving the UEs it accepts.
