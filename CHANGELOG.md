# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security
- Enforce same-origin (`Origin` / `Sec-Fetch-Site`) and `Content-Type: application/json` checks on mutating mesh API endpoints to block CSRF from member-hosted or external sites.
- Restrict `server` devices on the mesh API to read-only `GET /api/me` (minimal `{member, this_device, zone}` payload) and `GET /api/directory`, returning `403` on all mutations and `/api/admin/*` endpoints.

### Fixed
- Hold `Service.mu` across the full `Redeem()` and `Claim()` paths, roll back partial member/invite/Headscale user/device-key writes on failure, allow owners to seize active names directly in `Claim()`, and log errors during `Kick()`.
- Use unique temp files via `os.CreateTemp` in `writeZone()` and emit `AAAA` DNS records alongside `A` records for dual-stack servers.
- Run `go test` in `core/registrar/Dockerfile` and add registrar unit tests (`core/registrar/http_test.go`, `core/registrar/service_test.go`) plus server-device and CSRF checks in `core/test/run.sh`.

### Added
- `REVIEW.md` documenting project review findings, DNS/Cloudflare operational notes, and security rationale.

## [Baseline] - 2026-11-19

### Added
- Core Hogman stack (`core/`): Headscale, Caddy edge and portal, CoreDNS, `step-ca` with name-constrained root and intermediate CAs, `registrar` service/CLI, `hogman-join` tool with native Tailscale and embedded `tsnet` side-by-side mode, and local end-to-end test suite (`core/test/run.sh`).
- Project website (`site/`) deployed to Fly.io and served on `hogman.network`.
- Architecture and design specification (`DESIGN.md`).
