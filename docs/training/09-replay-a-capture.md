# Exercise 09: Replay a customer's capture against the core

## Goal
Take a capture of a registration made against another core and find where our core answers differently.

## Do it by hand
From the root of the repository, in a built tree on Linux (WSL is fine; the cluster script needs user namespaces and no root). `tools/cli/g5c-lab check 09` does the whole exercise on a private cluster and judges it.

1. `tools/cli/g5c-replay show tests/fixtures/golden/s1_registration_open5gs_v2.8.0_ueransim.pcapng` lists the exchange.
2. `tools/cli/g5c-replay run <capture> --amf 127.2.0.5:38412` with the cluster up and the subscriber missing, then after `g5c-cluster.sh load 5 1`.

## What you should see
First: our core answers the registration with `Registration reject #7` where the recorded core sent `Authentication request`. After the subscriber exists: the answers match, and the replay stops where the keys of the recorded session would be needed.

## Why
A gNB can resend NG Setup and an unprotected Registration Request on its own; everything after the first authentication depends on secrets only the recorded UE had.
