# ADR-0002: Clean-room implementation and licensing policy

Status: Accepted (2026-09-30)

## Decision
1. Implement from 3GPP specifications only. Open5GS (AGPL-3.0), UERANSIM (AGPL-3.0, dual-licensed with a commercial licence; verified against the v2026-09 checkout), srsRAN (AGPL-3.0) are
   black-box test peers/oracles; no code, config schemas or generated code is copied from them.
2. Product licence: proprietary/commercial (our choice). Every source file carries `SPDX-License-Identifier: LicenseRef-Proprietary`.
3. Dependencies must be MIT / Apache-2.0 / BSD / ISC / MPL-2.0 (or equivalent permissive). Enforced by
   `scripts/c_lint.sh` and `docs/legal/THIRD_PARTY.md` in CI (ADR-0013). No GPL/AGPL/SSPL/BUSL.
4. Protocol logic cites its governing 3GPP clause (module docs or PR description).
5. Test tools run only from `tests/` and `deploy/compose`, never shipped in release artifacts.
6. A local Open5GS source checkout exists on the dev machine. Engineers do not open its `src/` tree while implementing protocol logic; the oracle is used as binaries, logs and packet captures only.
7. Patent (SEP/FRAND) review by counsel before commercial launch — outside engineering scope.

This is an engineering policy, not legal advice.
