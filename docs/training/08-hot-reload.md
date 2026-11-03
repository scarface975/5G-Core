# Exercise 08: Change a limit without a restart

## Goal
Edit the AMF's configuration file while it runs, send it SIGHUP, and watch the new limit take effect; then break the file and see the change refused and undone.

## Do it by hand
From the root of the repository, in a built tree on Linux (WSL is fine; the cluster script needs user namespaces and no root). `tools/cli/g5c-lab check 08` does the whole exercise on a private cluster and judges it.

1. Lower `registrations_per_s` in the AMF's file and `kill -HUP <pid>` (or `g5c-cluster.sh reload amf 'registrations_per_s: 100000' 'registrations_per_s: 20'`).
2. Run a storm (exercise 7) before and after.
3. Add an unknown key to `amf.overload` and reload: the report says `rolled-back`, the limit stays.

## What you should see
`g5c_config_reloads_total{result="applied"}` is 1, then `rolled_back` is 1; the same storm admits thousands before the change and about eighty after it.

## Why
The new file is validated like at start-up, applied section by section where the function can do it live, and put back if a section fails or the function suffers.
