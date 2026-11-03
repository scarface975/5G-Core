# Exercise 02: Make the AMF refuse registrations on purpose

## Goal
Use the failure-injection hook to make every registration fail with 5GMM cause #11 (PLMN not allowed), the way a RAN or UE vendor tests its reject handling.

## Do it by hand
From the root of the repository, in a built tree on Linux (WSL is fine; the cluster script needs user namespaces and no root). `tools/cli/g5c-lab check 02` does the whole exercise on a private cluster and judges it.

1. Put `inject: { registration_reject: [{ supi: imsi-00101, cause: 11 }] }` under `amf:` in the AMF configuration (the cluster script takes it from `G5C_AMF_EXTRA`).
2. Run `g5c-cluster.sh load 5 2`: the load tool stops at the first refusal of each gNB.
3. Read `g5c-cluster.sh logs amf`: each refusal is a line `registration of <supi> rejected, cause #11 (injected failure (amf.inject))`.

## What you should see
`g5c_amf_injected_total{kind="registration_reject"}` is at least 1, `g5c_amf_registrations_total{result="accepted"}` is 0, and the AMF stays ready.

## Why
Injection is configuration, so a test bench can make the core misbehave in a repeatable way without patching it; the counter proves the failure was ours, not the UE's.
