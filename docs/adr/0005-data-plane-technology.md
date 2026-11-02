# ADR-0005: UPF data plane — userspace first, then AF_XDP/eBPF

Status: Accepted (2026-09-30)

Stage A: userspace datapath (TUN/UDP) for correctness. Stage B: AF_XDP/eBPF fast path; DPDK optional.
Throughput targets are fixed by a later ADR once Stage A is measured. Linux only (WSL2/VM on the dev host).
