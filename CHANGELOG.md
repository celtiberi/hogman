# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security
- Enforce same-origin (`Origin` / `Sec-Fetch-Site`) and `Content-Type: application/json` checks on mutating mesh API endpoints to block CSRF from member-hosted or external sites.
- Restrict `server` devices on the mesh API to read-only `GET /api/me` (minimal `{member, this_device, zone}` payload) and `GET /api/directory`, returning `403` on all mutations and `/api/admin/*` endpoints.

### Fixed
- Use a deterministic non-ephemeral local proxy port (`17000`–`26999`) in `hogman-join` side-by-side mode, share one `http.Transport` across plain-HTTP proxy requests, preserve TCP half-close (`CloseWrite`) in `CONNECT` tunnels, and fall back to Tailscale peer status for `.nodes.<zone>` MagicDNS names.
- Parse `Enabled:` in macOS `networksetup -getautoproxyurl`, avoid overwriting active foreign or multi-pen `/proxy.pac` settings, XML-escape LaunchAgent plists, drop the undocumented `--yes` tailnet-switch override, validate invite/device link fragments in `core/join-page/index.html`, fix a `SIGPIPE` race in `core/test/run.sh`'s join-page check, and update `core/README.md`.
- Add unit tests in `core/join/agent_test.go` covering deterministic port selection, TCP half-close `CONNECT` tunneling, zone guards and shared `http.Transport` reuse, `.nodes.<zone>` fallback lookup, macOS PAC parsing/collision rules, and XML-safe LaunchAgent plist generation.
- Hold `Service.mu` across the full `Redeem()` and `Claim()` paths, roll back partial member/invite/Headscale user/device-key writes on failure, allow owners to seize active names directly in `Claim()`, and log errors during `Kick()`.
- Use unique temp files via `os.CreateTemp` in `writeZone()` and emit `AAAA` DNS records alongside `A` records for dual-stack servers.
- Run `go test` in `core/registrar/Dockerfile` and add registrar unit tests (`core/registrar/http_test.go`, `core/registrar/service_test.go`) plus server-device and CSRF checks in `core/test/run.sh`.

### Changed
- Redirect `www.hogman.network` permanently (`301`) to `https://hogman.network{uri}` in `site/Caddyfile` while keeping `hogman.fly.dev` as a direct fallback.
- Configure RFC1918 `trusted_proxies` CIDRs in `core/templates/headscale.yaml` so Headscale honors `X-Real-IP` forwarded by Caddy `edge`.

### Added
- `deploy/`: `bootstrap.sh` for a fresh Ubuntu server, and `hogman-host`, which runs many pens on one server behind a shared front door (each pen walled off on its own network), with `test-host.sh` (18 checks).
- Core: front-door mode (`FRONT_DOOR=true`, `compose.front.yaml`, `config/edge-behind-front.Caddyfile`) and a per-pen relay port (`STUN_PORT`).
- README rewritten in the website's style, with crops of the artwork in `docs/img/`.
- Website: "We'll keep your pen" (hosted pens, and what hosting lets us see), and "Add a device" in the joining steps.
- Portal (`home.<zone>`): shows who you are and your devices, lets members remove their other devices, and offers "Add a device" / "Add a server": a one-time link plus a QR code for the coming phone app.
- Registrar: `POST /api/devices` also returns `join_qr_svg`, drawn inside the pen (`rsc.io/qr`) so the secret link never goes to an outside QR service.
- Join page: on a phone, explains that the app is coming instead of showing desktop commands.
- `REVIEW.md` documenting project review findings, DNS/Cloudflare operational notes, and security rationale.
- `LICENSE`: the project's code is now licensed under AGPL-3.0; README gains status and license sections.

## [Baseline] - 2026-11-19

### Added
- Core Hogman stack (`core/`): Headscale, Caddy edge and portal, CoreDNS, `step-ca` with name-constrained root and intermediate CAs, `registrar` service/CLI, `hogman-join` tool with native Tailscale and embedded `tsnet` side-by-side mode, and local end-to-end test suite (`core/test/run.sh`).
- Project website (`site/`) deployed to Fly.io and served on `hogman.network`.
- Architecture and design specification (`DESIGN.md`).
