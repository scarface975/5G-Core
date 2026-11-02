# Pinned 3GPP documents (Release 16)

Everything we implement against, with the exact version downloaded from the official 3GPP archive and its SHA-256.
The documents themselves live in `docs/specs/src/` (git-ignored, not redistributed); fetch with `tools/spec/fetch_specs.ps1`,
extract text with `tools/spec/spec_text.py`, check integrity with `python tools/spec/verify_pins.py`. Full hashes: `pinned.json`.

| Specification | Version | Release | File | SHA-256 (first 16) |
|---|---|---|---|---|
| TS 23.003 | v16.12.0 | 16 | `23003-gc0.zip` | `33a5785840cf3893` |
| TS 23.501 | v16.20.0 | 16 | `23501-gk0.zip` | `1c9864f75fedf87a` |
| TS 23.502 | v16.19.0 | 16 | `23502-gj0.zip` | `1289941e25ee8c31` |
| TS 23.503 | v16.15.0 | 16 | `23503-gf0.zip` | `e4627cf6a1199e9c` |
| TS 24.008 | v16.7.0 | 16 | `24008-g70.zip` | `a528c9fbc2b6b73c` |
| TS 24.501 | v16.15.0 | 16 | `24501-g.zip` | `2b484ccb1e7a25e1` |
| TS 29.244 | v16.13.0 | 16 | `29244-gd0.zip` | `72de37db0c59ecde` |
| TS 29.281 | v16.2.0 | 16 | `29281-g20.zip` | `1cd5d70ebbe60393` |
| TS 29.500 | v16.15.0 | 16 | `29500-gf0.zip` | `116c179a7e10ced1` |
| TS 29.501 | v16.8.0 | 16 | `29501-g80.zip` | `478bd5828a865198` |
| TS 29.503 | v16.18.0 | 16 | `29503-gi0.zip` | `f2ddc6ebf9f44d96` |
| TS 29.504 | v16.14.0 | 16 | `29504-ge0.zip` | `ae36ef329fd7e8c1` |
| TS 29.505 | v16.12.0 | 16 | `29505-gc0.zip` | `9c88c27b3fc4155a` |
| TS 29.507 | v16.11.0 | 16 | `29507-gb0.zip` | `ba0af38d11cf4268` |
| TS 29.509 | v16.11.0 | 16 | `29509-gb0.zip` | `0d7c95a311e806cb` |
| TS 29.510 | v16.15.0 | 16 | `29510-gf0.zip` | `8d88c5a4fa7ab0c2` |
| TS 29.502 | v16.17.0 | 16 | `29502-gh0.zip` | `4101f891835a40e5` |
| TS 29.512 | v16.23.0 | 16 | `29512-gn0.zip` | `f5512749cc94d5ca` |
| TS 29.518 | v16.19.0 | 16 | `29518-gj0.zip` | `68fa3abe4380f40a` |
| TS 29.519 | v16.14.0 | 16 | `29519-ge0.zip` | `92ff1b30635bf3f6` |
| TS 29.571 | v16.15.0 | 16 | `29571-gf0.zip` | `6cd31273284db59e` |
| TS 33.220 | v16.4.0 | 16 | `33220-g40.zip` | `2cbb45fb8dabb3db` |
| TS 33.401 | v16.4.0 | 16 | `33401-g40.zip` | `4666be3e16c7a36f` |
| TS 33.501 | v16.20.0 | 16 | `33501-gk0.zip` | `f3cf4b2e80563883` |
| TS 35.208 | v16.0.0 | 16 | `35208-g00.zip` | `98128c768443d870` |
| TS 38.413 | v16.18.0 | 16 | `38413-gi0.zip` | `b004072805f25c57` |
| TS 38.415 | v16.6.0 | 16 | `38415-g60.zip` | `0a54fa84efb85eb7` |
| TS 29.531 | v16.11.0 | 16 | `29531-gb0.zip` | `533432bbd5e932d0` |
| TS 29.522 | v16.18.0 | 16 | `29522-gi0.zip` | `06e8bfe312b44e21` |
| TS 29.591 | v16.7.0 | 16 | `29591-g70.zip` | `e67fdf39cbc1fad9` |
| TS 29.514 | v16.23.0 | 16 | `29514-gn0.zip` | `e1a1e45fdaf16a26` |
| TS 29.122 | v16.19.0 | 16 | `29122-gj0.zip` | `fb32407a667b2044` |
| TS 29.521 | v16.11.0 | 16 | `29521-gb0.zip` | `1372f0ebb474cd71` |

Also downloaded but only cover pages (algorithm text is licensed ETSI SAGE material): TS 35.216, 35.217, 35.222, 35.223 (v16.0.0).
Release policy: see ADR-0003 (Release 15 baseline, Release 16 ceiling, per-feature Release 17+ policy).
