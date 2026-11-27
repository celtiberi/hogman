# `deploy/`

Open-source ACME DNS-01 server and release tooling for `celtiberi/hogman`:

- [`challenge-dns/`](challenge-dns/README.md) — authoritative DNS-01 challenge server (`_acme-challenge.*` TXT, `SOA`, `NS`, `CAA`; never `A`/`AAAA`) with per-pen rolling rate limits and optional Google Trust Services EAB minting.
- `build-bins.sh` — compiles the `hogman` client (5 platforms), `registrar` (Linux amd64/arm64), and `challenge-dns` (Linux amd64/arm64) inside a digest-pinned Go container with `-tags=ts_omit_peerapiserver -trimpath`.
- `release.sh` — verifies GitHub build provenance from `.github/workflows/build.yml`, packages source and binary tarballs owned by `0:0`, and publishes immutable GitHub Releases (alongside `.github/workflows/release.yml`, which pushes the multi-arch `ghcr.io/celtiberi/hogman-sidecar` scratch image by digest from the exact same attested Linux binaries, attests and verifies it, and applies `:v<ver>` + `:latest` after `Publish`; on the first release, confirm the GHCR package visibility is set to Public and linked to `celtiberi/hogman`). If `Publish` succeeds but the final tagging step fails, recover using the digest recorded in the GitHub Release notes: `docker buildx imagetools create -t ghcr.io/celtiberi/hogman-sidecar:v<ver> -t ghcr.io/celtiberi/hogman-sidecar:latest ghcr.io/celtiberi/hogman-sidecar@sha256:<digest>`.
- `changelog-fold.sh` & `test-changelog-fold.sh` — validates `changelog.d/` fragments, renders GitHub Release notes, and folds fragments into `CHANGELOG.md`.
