# `deploy/`

Open-source ACME DNS-01 server and release tooling for `celtiberi/hogman`:

- [`challenge-dns/`](challenge-dns/README.md) — authoritative DNS-01 challenge server (`_acme-challenge.*` TXT, `SOA`, `NS`, `CAA`; never `A`/`AAAA`) with per-pen rolling rate limits and optional Google Trust Services EAB minting.
- `build-bins.sh` — compiles the `hogman` client (5 platforms), `registrar` (Linux amd64/arm64), and `challenge-dns` (Linux amd64/arm64) inside a digest-pinned Go container with `-tags=ts_omit_peerapiserver -trimpath`.
- `release.sh` — verifies GitHub build provenance from `.github/workflows/build.yml`, packages source and binary tarballs owned by `0:0`, and publishes immutable GitHub Releases (alongside `.github/workflows/release.yml`, which also builds, pushes, attests, and verifies the multi-arch `ghcr.io/celtiberi/hogman-sidecar` scratch image from the exact same attested Linux binaries; on the first release, confirm the GHCR package visibility is set to Public and linked to `celtiberi/hogman`).
- `changelog-fold.sh` & `test-changelog-fold.sh` — validates `changelog.d/` fragments, renders GitHub Release notes, and folds fragments into `CHANGELOG.md`.
