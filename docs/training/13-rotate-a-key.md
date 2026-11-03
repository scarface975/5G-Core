# Exercise 13: Rotate the master key of the subscriber database

## Goal
Change the key that protects K and OPc at rest, re-wrap every stored credential, and see that nothing is lost.

## Do it by hand
From the root of the repository, in a built tree on Linux (WSL is fine; the cluster script needs user namespaces and no root). `tools/cli/g5c-lab check 13` does the whole exercise on a private cluster and judges it.

1. `g5c-cluster.sh ns ops` runs it all. By hand: put the new key in `master_key_file` and the old one in `master_key_previous_file`, restart the UDM, `POST /admin/v1/keys/rewrap`, remove the previous key, restart.
2. The answer counts `rewrapped`, `alreadyCurrent` and `failed`.

## What you should see
`failed` is 0, the subscribers still authenticate after the old key is gone, and the audit lines show who re-wrapped (`by=`).

## Why
Credentials are encrypted under the master key with the SUPI as associated data, so a record cannot be moved to another subscriber, and a rotation is a rewrite of the stored envelopes, not of the keys themselves.
