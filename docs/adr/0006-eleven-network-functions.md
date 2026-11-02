# ADR-0006: The eleven network functions

Status: Accepted (2026-09-30)

AMF, SMF, UPF, PCF, UDM (Phases 1-5) plus NRF, AUSF, UDR, NSSF, NEF and SCP (Phase 7).
BSF was the alternative for the 11th slot; it can be added after SCP without architectural change.
Until Phase 7, `shims/` provide minimal nrf-lite, ausf-lite and udr-lite services.
