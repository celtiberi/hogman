# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security
- Enforce same-origin (`Origin` / `Sec-Fetch-Site`) and `Content-Type: application/json` checks on mutating mesh API endpoints to block CSRF from member-hosted or external sites.
- Restrict `server` devices on the mesh API to `GET /api/me` (minimal `{member, this_device, zone, network}` payload), `GET /api/directory`, and acting on themselves only (claim a free name or one already pointing at them, release names that point only at them, remove themselves), returning `403` on everything else, including `/api/admin/*`.
- Switch Headscale IP allocation to `random`, verify caller mesh IPs against live Headscale nodes in `identify()`, harden admin-vs-owner RBAC and subdomain cleanup, rate-limit `POST /hogman/v1/redeem`, cap per-member invites/keys/names, revoke open keys on suspend, and configure server timeouts (PR #5).
- Add strict anti-framing (`X-Frame-Options: DENY`, `frame-ancestors 'none'`), CSP (`script-src 'self'`, `style-src 'self'`), `nosniff`, and `no-store` headers on `portal` and `/join`, block `/api/*` and `/swagger*` on edge proxies, bind `edge-behind-front` strictly to `{$PUBLIC_HOST}`, and enable `trusted_proxies_strict` + forward `X-Forwarded-For: {client_ip}` on `/hogman/*` behind the shared front door (PR #6).
- Harden `hogman-join`: reject URL credentials, require full IPv4/IPv6 exclusions and valid cert dates on the root CA, validate `/hogman/v1/network` metadata, store temp root certs at `0700`/`0600`, restrict proxy `forward()` to `http`, and quote systemd `ExecStart` paths (PR #7).
- Validate pen names, hostnames, and IPv4 addresses strictly in `deploy/hogman-host` and `core/hogman`, tighten host/pen secret directory and file permissions (`700`/`600`), add SSH lockdown verification and `sshd` key-only config in `deploy/bootstrap.sh`, scrub personal examples from `deploy/`, and add `mem_limit`, `pids_limit`, `read_only`, non-root user, and capability drops in `core/compose.yaml` (PR #8).

### Fixed
- Use a deterministic non-ephemeral local proxy port (`17000`–`26999`) in `hogman-join` side-by-side mode, share one `http.Transport` across plain-HTTP proxy requests, preserve TCP half-close (`CloseWrite`) in `CONNECT` tunnels, and fall back to Tailscale peer status for `.nodes.<zone>` MagicDNS names.
- Parse `Enabled:` in macOS `networksetup -getautoproxyurl`, avoid overwriting active foreign or multi-pen `/proxy.pac` settings, XML-escape LaunchAgent plists, drop the undocumented `--yes` tailnet-switch override, validate invite/device link fragments in `core/join-page/index.html`, fix a `SIGPIPE` race in `core/test/run.sh`'s join-page check, and update `core/README.md`.
- Add unit tests in `core/join/agent_test.go` covering deterministic port selection, TCP half-close `CONNECT` tunneling, zone guards and shared `http.Transport` reuse, `.nodes.<zone>` fallback lookup, macOS PAC parsing/collision rules, and XML-safe LaunchAgent plist generation.
- Hold `Service.mu` across the full `Redeem()` and `Claim()` paths, roll back partial member/invite/Headscale user/device-key writes on failure, allow owners to seize active names directly in `Claim()`, and log errors during `Kick()`.
- Use unique temp files via `os.CreateTemp` in `writeZone()` and emit `AAAA` DNS records alongside `A` records for dual-stack servers.
- Run `go test` in `core/registrar/Dockerfile` and add registrar unit tests (`core/registrar/http_test.go`, `core/registrar/service_test.go`) plus server-device and CSRF checks in `core/test/run.sh`.
- Retry `caddy reload` briefly in `deploy/hogman-host:reload_front()` to avoid cold-start races against Caddy's admin socket, and add traversal, host-validation, and file-permission regression checks to `deploy/test-host.sh` (PR #8).

### Changed
- Redirect `www.hogman.network` permanently (`301`) to `https://hogman.network{uri}` in `site/Caddyfile` while keeping `hogman.fly.dev` as a direct fallback.
- Configure RFC1918 `trusted_proxies` CIDRs in `core/templates/headscale.yaml` so Headscale honors `X-Real-IP` forwarded by Caddy `edge`.

### Added
- GitHub Actions: end-to-end suites on every pull request (`e2e.yml`), and compiled programs for every commit on main (`build.yml`). `deploy/release.sh` uses GitHub's build of the commit when Docker isn't running locally (`deploy/build-bins.sh` holds the compile step for both).
- Pen directory on `home.<zone>` ("Sites in this pen", showing every resolvable site, who runs it, and an optional one-line note rendered via `textContent`), plus `--note` on `hogman-join share` / `hogman name claim` and `POST /api/names` (sanitized and capped at 140 runes server-side, returned by `GET /api/directory`, persisted across bare `share` restarts, and cleared with `--note ""`).
- Docs lead with the happy path: "Start here" (joining, putting things in your pen with `share`, running your pen, use cases, FAQ) and "Going deeper" (how it works, your own web server as an advanced page, raising your own pen). Use cases now share from an always-on computer with a server link instead of hand-configuring servers.
- Docs section at hogman.network/docs: how it works in full, guides (joining, sharing, running a server, running your pen, raising your own), use cases worked through, and FAQ with troubleshooting. Sources in `site/docs-src` (`python3 site/docs-src/build.py`). The home page's technical section is shorter and links there; no software version numbers on the site.
- `hogman-join share NAME WHAT ['<server link>']`: one command puts a port, a local web address or a folder on the pen as `https://NAME.<pen>.hogman`. Each share is its own small `tag:server` device (tsnet) that names itself, gets a certificate from the pen's CA (ACME TLS-ALPN-01 over the mesh) and proxies or serves files; no Caddy, no open ports, no administrator rights. `--background`, `share list`, `share stop NAME`; `leave` takes a pen's shares down first. `/api/me` now includes the pen's network info. End-to-end checks cover a folder shared from a side-by-side laptop and a port shared with only a server link.
- "Under the hood" on hogman.network and in the README: the real parts (WireGuard and Headscale, the per-pen DNS zone, the name-constrained CA, default-deny policy, invites with root fingerprints, the boot, hosted-pen layout) and a step-by-step of what happens when a member opens a site.
- "How it works" on hogman.network and in the README: three plain steps (make a pen, invite your people, private inside and invisible outside) and a before/after line, replacing a short-lived technical diagram. The `share` example moved to the joining section.
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
