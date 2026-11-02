# ADR-0024: BSF design (Phase 7, an optional twelfth function)

Status: Accepted (2026-10-26)

## Context
The BSF (TS 23.501 7.2.15, TS 23.503) is not a required function of a 5GC but a standard one: where more than one PCF serves a network, something has to say which PCF holds the
SM policy association of a PDU session, so that an AF or NEF request for "this UE address" reaches it, and so that the same PCF can be chosen for the sessions of a UE (SamePcf).
Open5GS ships a BSF (its PCF registers every session at it); the commercial cores list it, usually as a function of the PCF or of the signalling-routing layer, and it is not
always visible as a separate network function. Amarisoft's data sheets list the AMF, AUSF, SMF, UPF, UDM and 5G-EIR as the built-in functions of its 5GC and say nothing of a PCF, BSF
or SCP (checked against the 2021 Callbox data sheets only; the current product documentation was not found), so a lab core of that kind does not use one. The owner asked for it to be
built (2026-10-26): with several PCFs in the demo, or an NEF in front of them, it is what makes the right PCF reachable.

## Decision
- **Pinned source.** TS 29.521 v16.11.0 (downloaded with the owner's permission, pinned in `docs/specs/pinned.json`, SHA-256 checked by `tools/spec/verify_pins.py`). `tools/spec/gen_bsf_api.py` writes
  `nf/bsf/src/api_schemas.gen.c` and `api_ids.gen.h` from `TS29521_Nbsf_Management.yaml`; bodies are validated by the shared `libs/oaschema` (`--check` fails when the committed tables are stale).
- **Nbsf_Management** (`/nbsf-management/v1/pcfBindings`): POST registers (201 with Location and the PcfBinding with the negotiated features), GET discovers (200 with the binding, 204 when nothing
  matches, 400 MULTIPLE_BINDING_INFO_FOUND when more than one does), DELETE deregisters (204 / 404), PATCH updates with a merge patch (BindingUpdate). The query parameter and body errors use the causes
  of TS 29.500 5.2.7.2 with `invalidParams`.
- **A binding is found by its UE address** without scanning: a hash by IPv4 address, a hash by the first 64 bits of an IPv6 prefix of /64 or longer (the longest prefix wins, a /128 beats a /64), a
  hash by MAC address, a short list for the IPv6 prefixes shorter than /64 and one for framed routes (an address itself beats a route). The SamePcf check goes through a hash by SUPI, DNN and S-NSSAI
  when the combination is complete and through the list of the bindings that hold SM policy addressing when it is not. `dnn`, `snssai`, `supi`, `gpsi` and `ipDomain` narrow a discovery
  (an absent SD and FFFFFF are the same S-NSSAI, TS 23.003 28.4.2); the same IPv4 address in two slices is two bindings.
- **Features.** MultiUeAddr, BindingUpdate, SamePcf and ExtendedSamePcf are offered (configurable); the answer is the intersection with what the consumer offered, ExtendedSamePcf only with SamePcf; ES3XX
  is not. Without ExtendedSamePcf a registration must carry a UE address and a PCF address, as the specification says (the specification gives the BSF no explicit reason to refuse one that does not,
  but the consumer "shall include" them and a binding without either cannot be found or used). Members of a feature that was not negotiated are refused with 400.
- **Stale bindings are the operational risk, so a new registration for a UE address, DNN, S-NSSAI and IP domain replaces any binding that holds them, whichever PCF registered it** (an address is unique
  within its DNN, slice and IP domain: the earlier binding is a PCF that restarted, a session that moved, or an address that was handed to another UE), and a PCF that registers with a newer
  `recoveryTime` has its older bindings removed (TS 29.521 4.2.2.2 gives the BSF this clean-up; the per-PCF newest time is kept, so the scan happens once per PCF restart, not per registration). Both can be turned off.
- **State** is a JSON file written behind the request by a thread of its own (one write for a burst, atomic replace); a damaged file is refused at start, a binding that does not parse is dropped.
- **The PCF registers** (`nf/pcf/src/bsfreg.c`): when an SM policy association is created with an IPv4 address or an IPv6 prefix it queues a registration (UE address, IP domain, DNN, S-NSSAI, SUPI,
  GPSI, its own instance id, address as an IP endpoint, optionally an FQDN, its start time as recoveryTime) and when the association ends (delete, or the PCF's own termination) a deregistration. A thread
  of its own works the queue in order, so the SMF's request never waits for the BSF and a removal follows its registration. The BSF is the configured `bsf.uri` or the one found at the NRF (a negative answer
  is remembered for 30 s); a BSF that is missing or refuses costs a log line and a counter. `bsf: { enabled: false }` turns it off.
- **The NEF discovers** (`nf/nef/src/nef.c`, `nef_pcf_root`): for an AsSessionWithQoS request it asks the BSF for the PCF of the UE's address (with IP domain, DNN and S-NSSAI when the AF gave them), calls the
  PCF the binding names (IP endpoint first, then FQDN), and falls back to a PCF of the NRF when there is no binding or no BSF. A configured `nef.pcf` still overrides everything.
- **Deployment.** The cluster starts the BSF before the PCF by default (`G5C_BSF=0` for none), compose and the Windows launchers have it, `OUR_BSF=1` swaps it into the oracle, scenario s8 checks the
  binding from the outside.

## Interop facts that shaped it
Open5GS's PCF registers `{supi, ipv4Addr, dnn, snssai, pcfIpEndPoints [{ipv4Address, port}]}` (no transport, no suppFeat) and deletes the binding at the release; our BSF accepts it and Open5GS's PCF
completes the sessions (oracle S8 with our BSF). Our PCF registers at Open5GS's BSF and Open5GS's BSF finds the binding by the UE address and drops it on DELETE (S8 with our PCF).
Open5GS's BSF is partial, and `tools/diff/bsf_diff.py` lists every difference with the clause that says what ours does: it ignores `dnn`, `snssai` and the other narrowing parameters, answers 404 where the
specification says 204, takes the first of several matches, ignores an unknown query parameter, takes the first of two UE addresses, leaves `ipv4Addr` and `supi` out of the discovery answer, refuses a plain
IPv6 prefix such as `2001:db8:1:2::/64` ("Invalid IPv6 prefix"), cannot register a MAC address, has no PATCH, and **its `open5gs-bsfd` aborts on a registration that carries only the Diameter host and realm
of the PCF**. Its profile at the NRF lists `allowedNfTypes` SCP, PCF and AF, so Open5GS's NRF does not discover it for an NEF although TS 29.521 4.1.2 names the NEF as a consumer: with Open5GS's BSF our
NEF takes the PCF from the NRF.

## Gaps (matrix rows BSF-GAP-*, PCF-BSF-GAP-01)
The BSF does not supervise the PCFs at the NRF to drop the bindings of one that was deregistered; redirection (ES3XX); producer-side OAuth2; the PCF registers without features (no BindingUpdate, SamePcf,
MultiUeAddr, no Diameter identities); nothing collocates the BSF with another function.

## Consequences
With several PCFs a request for a UE address reaches the PCF that holds the session, with one PCF nothing changes (the NRF fallback); the cost is one queued call per PDU session at the PCF and one
discovery per AsSessionWithQoS request at the NEF.
