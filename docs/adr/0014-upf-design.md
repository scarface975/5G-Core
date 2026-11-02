# ADR-0014: UPF design - an I/O-free engine, a single-threaded userspace runtime (Stage A), AF_XDP later (Stage B)

Status: Accepted for Stage A (2026-10-08); the Stage B throughput target is proposed below and needs an owner decision (ADR-0005 leaves it open)

## Context
Phase 3 asks for a correct UPF first and a fast one second (ADR-0005: userspace datapath, then AF_XDP/eBPF). The UPF is the NF where
mistakes are hardest to see: a wrong bit in a feature mask or a mis-ordered rule still "works" until a different peer arrives.

## Decision
1. **Engine and runtime are separate.** `nf/upf` (library `g5c_upf`) is the engine: the N4 handler, the rule store (PDR, FAR, QER, URR, BAR),
   the packet pipeline and the timers. It performs no I/O: input arrives through `upf_n4_message`, `upf_gtpu_packet`, `upf_n6_packet` and
   `upf_tick`; output leaves through three callbacks. `g5c_upf_rt` binds them to UDP sockets, a TUN device and a timer. Consequences: the
   engine is tested without sockets, root or a TUN (real Open5GS messages replayed in-process), fuzzed through the same entry points, and
   benchmarked at the pipeline level. A Stage B runtime reuses it unchanged.
2. **One thread, one epoll loop** for Stage A. No locks in the datapath, no shared mutable state, deterministic tests. Input is drained in
   bounded batches (recvmmsg for N3, 256 packets for N6) and output is batched (sendmmsg), which doubled downlink throughput.
3. **Rules are interpreted, not compiled.** Per packet: session lookup (hash on TEID or UE address), a linear scan of at most a few PDRs by
   precedence, QER buckets, FAR action. Measured at about 50 ns per packet on one core, so the pipeline is not the bottleneck; the kernel is.
4. **Modifications are transactional.** A Session Modification snapshots the rules and restores them if any element fails (TS 29.244
   requires the request to fail as a whole).
5. **Every bit layout comes from the pinned specification text**, not from memory, with the real captured bytes as a second source (tests
   decode and re-encode every typed IE of eight real Open5GS messages). A differential analysis against Open5GS's own UPF (same SMF, same
   scenario) runs in the regression suite.
6. **Scope limits, stated in the conformance matrix:** no UE address allocation in the UPF (the SMF allocates), no N3/N9 over IPv6, no GBR
   guarantee (MBR is enforced), no ATSSS/multi-access/redundant transmission, PFD management accepted and ignored, NAT is host configuration.

## Measured (this host: 8 logical cores, WSL2, loopback, 1400-byte packets)
Engine alone about 20 Mpps. End to end through the runtime with real UDP sockets: between 2.3 and 4.9 Gbit/s uplink and 1.4 to 2.2 Gbit/s downlink of UPF capacity
per core (the host varies a lot, and was an order of magnitude slower for a few minutes after the VM started), against the Stage A criterion of at least 1 Gbit/s.
Downlink is bounded by one read() system call per packet on a TUN device; a TUN cannot batch reads. With UERANSIM in the loop the gNB simulator is the limit, not the UPF.

## Stage B (proposed, not started)
AF_XDP sockets with a shared UMEM, one worker per queue pinned to a core, RSS across queues, the engine sharded by session so a TEID or UE
address always lands on the same worker, N6 on a second AF_XDP or XDP-redirect path. **Proposed target: 10 Gbit/s of 1400-byte packets on a
host with two 10 GbE NICs, loss below 0.01%.** This needs a physical NIC with XDP support, which the development host does not have, so the
target stays a proposal until hardware is available.
