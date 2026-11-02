# ADR-0023: SCP design (Phase 7, sixth and last function)

Status: Accepted (2026-10-26)

## Decision
- **Pinned source.** TS 29.500 (already pinned): 5.2.3.2 (custom headers), 5.2.7.4 (errors an SCP makes), 6.10 (indirect communication), 6.11 (late requests). Nothing is taken from
  memory; the clauses cited in the matrix (`SCP-*`) are checked against the pinned text by `tools/check/check_matrix.py`.
- **A proxy of the SBI, not of any one service.** The SCP does not parse service bodies. Every request it receives is classified: `3gpp-Sbi-Target-apiRoot` present (Model C: the
  consumer chose the producer), `3gpp-Sbi-Discovery-*` present without it (Model D: the SCP discovers), or neither (400 MANDATORY_IE_MISSING). The request goes to the producer with
  the path and query kept (the `ck` parameter and the SCP's own prefix removed), the hop-by-hop headers dropped and `Via: 2.0 SCP-<name>` added.
- **Discovery (Model D).** The discovery headers become the query of an Nnrf_NFDiscovery request at the NRF of the common `nrf:` section (or the one a consumer names in
  `3gpp-Sbi-Nrf-Uri`); the requester type comes from the User-Agent when the consumer did not send it. The answers are cached per query (`cache_ttl_s`, `cache_max`). The profiles
  become candidate apiRoots (the service's own address and scheme, priority, capacity and load).
- **Selection and reselection.** Candidates are ordered by priority, then randomly weighted by capacity and remaining load; producers in quarantine come last. A producer that is
  unreachable, times out or answers 503 (`retry_on_503`) is replaced by the next candidate, up to `attempts`; `failures` failures in a row put a producer in quarantine for `seconds`.
  The producer that answered is named in `3gpp-Sbi-Producer-Id: nfinst=<id>`; when it is not the one the consumer named, its apiRoot is returned in `3gpp-Sbi-Target-apiRoot` (6.10.4) so
  the consumer can bind to it. `3gpp-Sbi-Routing-Binding` restricts or prefers an instance (`nfinst`) or set (`nfset`).
- **Errors.** What the SCP makes carries ProblemDetails and `Server: SCP-<name>`: 400 (MANDATORY_IE_MISSING, INVALID_DISCOVERY_PARAM, NF_DISCOVERY_FAILURE), 403 TARGET_NOT_ALLOWED, 413,
  503 NF_CONGESTION, 504 (TARGET_NF_NOT_REACHABLE, TIMED_OUT_REQUEST). What a producer answers is relayed with `Via` and no `Server` of the SCP (6.10.8.3). A request whose Via already
  names this SCP is a loop and is refused.
- **Late requests (6.11.2).** A request whose `3gpp-Sbi-Sender-Timestamp` plus `3gpp-Sbi-Max-Rsp-Time` has passed is refused with 504 TIMED_OUT_REQUEST; the two headers are
  otherwise forwarded unmodified (the specification allows that).
- **Chains.** `scp.next` makes this SCP a hop in front of another: the request goes on with the apiRoot selected here, or (`delegate_discovery`) with the discovery headers for the next
  SCP to resolve. Prefixes of each SCP are handled on the way in.
- **Control of what it may reach.** `scp.targets.allow` (host names, `*.example.org`, IPv4 CIDRs) limits where the SCP forwards: a Target-apiRoot outside it is refused, a discovered
  producer outside it is not a candidate. The SCP is otherwise an open relay for whoever can reach its port, so it belongs on the internal network of the core.
- **The client side is in the library, not in each function.** `g5c_client_set_scp` (`libs/sbi/src/client.c`) rewrites every request but those to the NRF and to the SCP itself: it
  sets Target-apiRoot to the producer and sends the request to the SCP; the User-Agent carries the NF type (`AMF-<name>`). The common configuration section `scp_client: { uri }` turns
  it on for a function (it is not called `scp` because the SCP's own block has that name). Registration and discovery at the NRF stay direct, as the NRF is what the SCP itself needs.
  The cluster script starts the SCP right after the NRF and sets `scp_client` everywhere by default (`G5C_SCP=0` for direct calls).
- **Capacity.** A request waits for its producer in one SBI worker, so the SCP's worker pool is sized by `scp.routing.workers` (default 256; the SBI server default of 32 would
  make the SCP the bottleneck of the core); `max_inflight` (default 4096) turns excess load into 503 rather than a growing queue.
- **Registration.** The SCP registers at the NRF with type SCP and `scpInfo.scpPorts`.

## Interop facts that shaped it
Open5GS's functions take an SCP as `client.scp` and `delegated.nrf.{nfm,disc}`; they send the Target-apiRoot even when they delegate and know the producer, and they discover through
the SCP with `target-nf-type NRF` for registration. Open5GS's SCP puts the bare instance id in Producer-Id where TS 29.500 5.2.3.2.8 has `nfinst=<id>` (ours follows the specification),
and answers 500 where we answer 400 / 504. Both are listed in the differential's allow-lists (`tools/diff/scp_diff.py`). The oracle runs Open5GS's whole core and UERANSIM through our SCP in
Model C and in Model D with delegated registration.

## Gaps (matrix rows SCP-GAP-*)
HTTP redirection (307 / 308) is relayed, not followed or produced; the SCP does not obtain or check access tokens (OAuth2 is the planned pass over all functions, NRF-GAP-04);
overload and load control information and message priority are relayed, not interpreted; reselection by NF set and service set goes no further than `nfinst` / `nfset` in the Routing-Binding;
default notification subscriptions are not supported (the pseudo URI is 404); there are no SEPP functions (N32) and the sample configuration has no TLS between the SCP and the functions.

## Consequences
Every function can be put behind the SCP by one configuration key, and the whole core runs, loads and survives chaos that way. The SCP is stateless apart from the discovery cache and
the quarantine, so several can run side by side behind one address. What it does not do is refused or relayed unchanged, never silently altered.
