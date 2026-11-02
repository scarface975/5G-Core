# ADR-0001: Implementation language — Rust

Status: Superseded by ADR-0013 (2026-10-07). Kept for the record: the original reasoning.

## Context
Network-facing parsers (NAS, NGAP, PFCP, GTP-U, SBI JSON) are the main attack surface of a core. The UPF needs
predictable latency. Dev host is Windows; Linux build/test runs in WSL2 Ubuntu.

## Decision
Rust (stable, edition 2021) for all NFs and libraries. `unsafe` is forbidden workspace-wide
(`[workspace.lints]`); any future exception (e.g. AF_XDP bindings in the UPF) needs its own ADR.
Go was the runner-up for control-plane NFs.

## Consequences
+ Memory safety in decoders, no GC pauses in UPF. + Strong permissive-licensed ecosystem.
- Smaller hiring pool than Go. - Longer compile times.
Builds run in WSL via `scripts/dev.ps1` / `scripts/dev.sh` (target dir on the Linux filesystem).
