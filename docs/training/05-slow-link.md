# Exercise 05: Slow down the link to the UPF

## Goal
Add 150 ms to every packet toward the UPF with `tc netem` and see it in the session set-up time.

## Do it by hand
From the root of the repository, in a built tree on Linux (WSL is fine; the cluster script needs user namespaces and no root). `tools/cli/g5c-lab check 05` does the whole exercise on a private cluster and judges it.

1. `g5c-cluster.sh impair upf 150` (delay in ms, then loss, reorder, duplication and jitter in %), then `g5c-cluster.sh load 12 4`.
2. `g5c-kpi` shows `sm_context_create_p95` above 0.1 s. `g5c-cluster.sh impair clear` removes the impairment.

## What you should see
The 95th percentile of Create SM Context rises above 100 ms, and every registration still succeeds.

## Why
The SMF waits for the N4 answer of the UPF before it accepts the session, so the latency of the link adds directly to the set-up time.
