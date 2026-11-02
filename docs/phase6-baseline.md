# Phase 6 baseline report: the five-function core as a system

Measured on the development host (WSL2, 8 logical cores, 7 GB), every network function a separate process on loopback inside a private user + network
namespace, driven by `nf/amf/tests/load_core.c` through `deploy/run/g5c-cluster.sh`. Build: plain `-O2`, no sanitiser. The figures are a baseline to compare
later changes against, not a capacity claim for other hardware.

## Scale: registration, PDU session and de-registration of N UEs

Each simulated UE runs 5G-AKA (Milenage on its side, the AUSF / UDM / UDR chain on ours), security mode with NIA2/NEA2, registration accept with GUTI,
a PDU session establishment through AMF -> SMF -> PCF / UDM / UPF (N4), and then a UE-originated de-registration. 32 gNBs, each on its own SCTP association.

| UEs | registered with a session in | rate | registration p50 / p99 | PDU session p50 / p99 | de-registration p50 / p99 | de-registered in |
|---|---|---|---|---|---|---|
| 10,000 | 20.7 s | 484 UE/s | 38 ms / 79 ms | 25 ms / 41 ms | 29 ms / 61 ms | 9.8 s |

Latency stays flat as the population grows (before the fixes below it grew from 7 ms to 250 ms and the run did not complete beyond about 4,700 UEs).
Peak resident memory of the functions at 10,000 registered UEs with a session each: AMF 114 MB, SMF 105 MB, PCF 125 MB, UDR-lite 193 MB, UDM 21 MB,
UPF 21 MB, AUSF-lite 10 MB (about 11 KB per UE in the AMF, 10 KB in the SMF). After the UEs de-register the counts of AMF contexts, SMF sessions and UPF
sessions return to zero. CPU for the whole 10,000-UE run (registration, session, de-registration): AMF 42 s, SMF 27 s, UDR-lite 26 s, UDM 26 s, PCF 11 s,
AUSF-lite 5 s, UPF 2 s.

## Failure injection

`g5c-cluster.sh ns chaos`: the same load while a random function (UPF, SMF, AMF, UDM, PCF, AUSF-lite, UDR-lite) is killed with SIGKILL and restarted
every few seconds. In a 60 s run with 16 kills, 8,762 UE cycles completed, the rest were counted as failures (never a hang), and a clean wave of 100
new UEs afterwards passed in every detail. See "Known gap" for what a kill can leave behind.

## Soak

`g5c-cluster.sh ns soak 500 <seconds>`: waves of 500 UEs back to back; RSS of every function is sampled after each wave. 240 s (77 waves, 38,500
register / session / de-register cycles): AMF, SMF, UPF, UDM, PCF and AUSF-lite flat within a few MB; UDR-lite grows from 18 to 35 MB with a decreasing
rate (its documents are constant size, so this is allocator behaviour, to be re-checked in the long run). The 72 hour run is the same command with 259200
seconds and was not run in this environment.

## Bugs found by the phase (all fixed, each with a test or a standing check)

| # | Where | Found by | Defect | Fix |
|---|---|---|---|---|
| 1 | AMF | load run | the "unauthenticated connections" limit counted every connection, so the AMF refused new UEs with an overload Error Indication once 4,096 were connected | only connections that have not completed authentication are counted |
| 2 | AMF | cluster CPU profile | the timer thread scanned every pending timer on each wake-up (UEs hold timers for hours): quadratic in UEs | binary min-heap; wake-up only when the earliest timer changes |
| 3 | AMF | cluster CPU profile | the state file (all UEs) was rewritten after every change, back to back under load | write-behind with a delay that grows with the cost of the write (about a tenth of a core at most); a graceful stop flushes |
| 4 | SMF | pdu-session latency vs concurrency | one worker executed every deferred job, and slept for the AMF-ordering delay inside the job: about 60 sessions/s at any load | a pool of four (config `smf.workers`), the delay is a scheduled job instead of a sleep |
| 5 | SMF | CPU profile | session lookup was a list scan under the table lock, and the state snapshot looked every session up again: quadratic | hash indexes on reference and on (SUPI, PSI) |
| 6 | SMF | CPU profile | state file rewritten after every change | same write-behind as the AMF |
| 7 | UDR-lite | registration latency of 250 ms in the cluster | the whole store was serialised, written and fsynced inside every mutation, under the store lock | snapshot plus journal of changed subscribers, written behind; crash image recovery tested |
| 8 | AMF | soak | the AMF created an SDM subscription at every registration and never deleted it: the UDM grew by 0.9 KB per registration (99 MB after 95,000 cycles) | the subscription id is kept (and persisted) and deleted with the context; an end-to-end assertion covers it |
| 9 | SMF | chaos run (recovery wave failed with cause #38) | after a UPF restart the SMF noticed the changed Recovery Time Stamp in a heartbeat answer and released the sessions, but did not set the association up again: the UPF refused every establishment with cause 72 until the SMF itself was restarted | a detected restart sets the association up again at once (a UPF restart as a process is now part of the chaos run) |
| 10 | test peer | load run | the scripted gNB did not set SCTP_NODELAY, so every message after a message without a reply waited for the 200 ms delayed SACK; real gNBs set it. The AMF's own sockets already did | the scripted gNB sets it |

## Known gap

An SMF killed with SIGKILL inside the write-behind window of its state file (25 ms, or ten times the cost of one write) leaves PFCP sessions on the UPF
that the restarted SMF does not know. A Recovery Time Stamp change cannot be used to clear them, because the SMF keeps its stamp to keep its restored
sessions. Closing the window needs an N4 session audit, tracked as `P6-GAP-04`.

## Not done in this phase (and why)

- The 72 hour soak: needs a host left alone for three days; the command is ready.
- srsUE with the OCUDU gNB, an O-RAN emulator, S6-S8 on them: deferred by the owner until the remaining functions exist (`P6-GAP-02`).
- A combined signalling + user-plane traffic run at scale (`P6-GAP-03`); the UPF's own benchmark gives 3.2 Gbit/s uplink / 1.8 Gbit/s downlink per core.

## Decision checkpoint before Phase 7

All exit criteria that can be run here pass; no P1 bug is open; the defects the scale run exposed are fixed and covered. Phase 7 builds the NRF, AUSF,
UDR, NSSF, NEF and SCP; the shims (`udr-lite`, `ausf-lite`) are what the soak shows to be the least efficient pieces, so replacing them is not a
regression risk for the baseline above. Release 17 is opened as a track after Phase 7 (ADR-0017).
