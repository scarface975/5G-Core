# Exercise 03: Ask the core why a subscriber failed

## Goal
Use `g5c-why` on the logs of exercise 2 and read, in plain words, what happened to each subscriber.

## Do it by hand
From the root of the repository, in a built tree on Linux (WSL is fine; the cluster script needs user namespaces and no root). `tools/cli/g5c-lab check 03` does the whole exercise on a private cluster and judges it.

1. Repeat exercise 2 (the failure injection).
2. `tools/cli/g5c-why $(g5c-cluster.sh logdir)` prints, per subscriber, what happened, the likely cause, the function and clause, what to check and the runbook entry.
3. Try `--supi imsi-001010000000001`, `--json`, and `--all` (failures that name no subscriber).

## What you should see
An entry per subscriber that says the failure was injected on purpose, with cause #11, `see: docs/ops/runbooks.md#registrations-rejected`.

## Why
The explanation comes from rules over the log lines the functions already write, and lines of one trace are joined across functions, so a refusal at the AMF shows the error of the function that caused it.
