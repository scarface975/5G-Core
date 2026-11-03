# Exercise 12: Break a certificate and watch the core refuse

## Goal
Run the functions with mutual TLS and see what happens with no certificate, a foreign CA's certificate, a garbage file during a reload, and a revoked certificate.

## Do it by hand
From the root of the repository, in a built tree on Linux (WSL is fine; the cluster script needs user namespaces and no root). `tools/cli/g5c-lab check 12` does the whole exercise on a private cluster and judges it.

1. `g5c-cluster.sh ns tls` does all of it in a private network: it makes a CA (`deploy/run/g5c-pki.sh`), starts the core with mutual TLS and tries each failure.
2. By hand: `G5C_TLS=1 g5c-cluster.sh up`, then `g5c-pki.sh revoke <function>` and reload the CRL with SIGHUP.

## What you should see
Cleartext to a TLS port, a client without a certificate and a certificate of another CA are all refused; a garbage certificate during a reload leaves the old one in use; renewal needs no restart.

## Why
Security between the functions is the certificate, not the network: a function with the wrong certificate is not a function of this core.
