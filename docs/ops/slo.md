# Service level objectives and capacity

Measured on one host (WSL2, 8 vCPU, loopback, every function a separate process, a scripted gNB / UE load generator, no radio). They are what the regression gates (`tools/check_slo.py`, the
performance gates of the UPF and the UDM) hold the code to; they are not a promise for other hardware. A shared host swings by a factor of three between runs, so the objectives sit well
below the best measurements.

## Control plane (registration with a PDU session, and de-registration)
| Objective | Target | Measured (1000 to 2000 UEs, 16 gNBs) | Gate |
|---|---|---|---|
| Throughput of registrations with a session | at least 50 UE/s | 53 to 169 UE/s without TLS, 66 to 145 UE/s with mutual TLS | `check_slo.py` on the cluster load logs |
| Registration latency, p99 | at most 1000 ms | 105 to 702 ms | same |
| PDU session establishment, p99 | at most 500 ms | 63 to 314 ms | same |
| De-registration, p99 | at most 500 ms | 60 to 341 ms | same |
| Memory after a wave | flat: the last sample at most 125% + 20 MB of the second | flat in the 30 s soak | `cluster_soak` |
| Descriptors after a wave | back to the starting count + 4 | 7 to 11 | `cluster_load` |
| Authentication vectors (UDM, one core) | at least 2000 /s | 2000 to 2900 /s | `udm_perf_gate` |

Mutual TLS costs about a fifth of the throughput at the same latency percentile in the quiet runs (138 against 169 UE/s); the rest of the spread is the host.

## User plane
| Objective | Target | Measured | Gate |
|---|---|---|---|
| UPF userspace forwarding, one core, 1400 byte packets | at least 1 Gbit/s each way | uplink 1.2 to 1.5, downlink 1.2 to 1.4 Gbit/s | `upf_io_bench_gate` |
| UPF 10 to 100 Gbit/s (ADR-0014) | not claimed | not measured | needs a NIC with XDP and a second host: open |

## Availability and recovery
| Objective | Target | Evidence |
|---|---|---|
| A function killed (SIGKILL) and restarted under load | the cluster recovers, a clean wave with new subscribers passes | `cluster_chaos`, `cluster_chaos_tls` |
| Upgrade: every function restarted gracefully one at a time under load | no function left down, a clean wave passes | `cluster_upgrade` |
| Rollback: the same with the previous binaries | same | `cluster_upgrade` (second half) |
| Certificate renewal | no restart, traffic continues | `cluster_tls` |
| Master key rotation | credentials open before, during and after | `cluster_ops` |

## Capacity limits that are configuration
UE addresses: the pools of `smf.dnns[].ipv4_pool`. UPF sessions: `upf.max_sessions` (200 000 in the cluster). Unauthenticated contexts in the AMF: `amf.max_unauthenticated`. Handler workers per function:
`workers`. RSS at 2000 sessions: about 10 to 25 MB per function.

## Not covered (open)
A 72 hour and a 7 day soak (the harness `ns soak` runs a fixed time; the long run needs a host that stays up), load to a customer's target, throughput of the user plane beyond one core
without a NIC, and a commercial test tool's run.
