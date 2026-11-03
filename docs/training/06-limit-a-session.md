# Exercise 06: Hold a session to its rate

## Goal
Give every session 1 Mbit/s, offer 4 Mbit/s per UE and watch the UPF let through about 1 and count what it drops.

## Do it by hand
From the root of the repository, in a built tree on Linux (WSL is fine; the cluster script needs user namespaces and no root). `tools/cli/g5c-lab check 06` does the whole exercise on a private cluster and judges it.

1. Start the cluster with `G5C_AMBR_UL='1 Mbps' G5C_AMBR_DL='1 Mbps'` (the PCF's default policy), then `G5C_LOAD_TRAFFIC_MBPS=4 G5C_LOAD_TRAFFIC_MS=1500 g5c-cluster.sh load 4 2`.
2. Read `upf_dropped_packets_total{reason="rate_limit"}` on the UPF's `/metrics`.

## What you should see
The delivered rate per UE is between 0.5 and 1.3 times 1 Mbit/s and the rate-limit drop counter is at least 100.

## Why
The PCF decides the session AMBR, the SMF turns it into a QER, the UPF enforces it with a token bucket: three functions, one number.
