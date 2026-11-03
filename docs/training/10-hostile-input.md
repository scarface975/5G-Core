# Exercise 10: Throw hostile input at the functions

## Goal
Send malformed bodies, JSON bombs and hostile path parameters to every route, and corrupted NGAP messages to the AMF, and see that nothing breaks.

## Do it by hand
From the root of the repository, in a built tree on Linux (WSL is fine; the cluster script needs user namespaces and no root). `tools/cli/g5c-lab check 10` does the whole exercise on a private cluster and judges it.

1. `tools/cli/g5c-mutate sbi $(g5c-cluster.sh url udm) --only /nudm-sdm --max-routes 6` (start the cluster with `G5C_OAUTH2=0`, otherwise every request is answered 401).
2. `tools/cli/g5c-mutate n2 <capture> --amf 127.2.0.5:38412 --sbi $(g5c-cluster.sh url amf)`.

## What you should see
Every route answers with a 4xx, the share of requests that reached a route's own parsing is high, no route fails, and the AMF still answers an NG Setup after every corruption.

## Why
5xx and silence are the signs of a parser that trusted its input; the sweep also fails a route that accepts what is not JSON.
