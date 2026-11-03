# Exercise 11: Read N2 and N4 as a ladder

## Goal
Turn a packet capture into one call-flow ladder per UE and per N4 session, with red flags.

## Do it by hand
From the root of the repository, in a built tree on Linux (WSL is fine; the cluster script needs user namespaces and no root). `tools/cli/g5c-lab check 11` does the whole exercise on a private cluster and judges it.

1. `tools/cli/g5c-ladder tests/fixtures/golden/s2_open5gs_v2.8.0_ueransim.pcapng` (needs `tshark`).
2. Capture your own: `tools/cli/g5c-capture core --print` gives the filter, and `G5C_TLS_KEYLOG=/path` on the functions lets Wireshark decrypt the SBI.

## What you should see
A ladder per UE keyed by the RAN UE NGAP ID, one for the NG setup, one per N4 session, and a list of findings (none for a clean capture).

## Why
Most failures are a missing or unanswered message; a ladder shows the gap at a glance, and it is the first thing a support engineer draws.
