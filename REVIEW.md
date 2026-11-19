# Hogman project review

Evaluated at commit `2166b62b`.

## DNS and Cloudflare operational note (`hogman.network`)

- `hogman.network` and `www.hogman.network` are delegated to Cloudflare (`virginia.ns.cloudflare.com`, `watson.ns.cloudflare.com`) and point to the Fly.io app (`hogman.fly.dev`, ingress `66.241.125.85` and `2a09:8280:1::213:c8aa:0`) with **DNS-only** (gray cloud) records.
- Keep those records gray-clouded while Fly manages Let's Encrypt certificates for `hogman.network` and `www.hogman.network` (orange-cloud proxying intercepts HTTP-01/TLS challenges unless Cloudflare SSL/TLS and origin certs are configured instead).
- The initial failure to reach `https://hogman.network` locally after adding the DNS records was caused by an upstream recursive resolver caching a negative `NODATA` response for the Cloudflare zone SOA minimum TTL (1800 seconds) prior to record propagation, while `www.hogman.network`, `1.1.1.1`, and `8.8.8.8` already resolved cleanly.

## Why `server` devices inheriting full member/owner API privileges is dangerous

Authentication on the in-mesh portal API (`https://home.<zone>/api/*`) has no passwords, cookies, or tokens. Caddy forwards the caller's mesh IP in `X-Forwarded-For`, and `identify()` in `core/registrar/http.go` calls `WhoIs(src)` in `core/registrar/service.go` to map that IP to a device and its owning member.

On a Hogman network, personal devices and server devices have very different threat surfaces:

- **Personal devices** (laptops, desktops) accept no inbound connections from anyone on the mesh.
- **Server devices** (`kind = "server"`) are reachable by every active member on every TCP/UDP port (`ip: ["*"]` in the Headscale policy) and typically run web apps, reverse proxies, webhooks, bots, or shared services.

Because `WhoIs()` previously treated every live device owned by a member identically regardless of `device.Kind`, a `server` device belonging to the owner or an admin inherited full owner/admin privileges against `https://home.<zone>/api/*`:

1. Suppose the network owner spins up a server inside the pen (for example, a feed reader, link previewer, webhook runner, or multi-user web app) and claims `stuff.<zone>` for it.
2. Any other member can reach that server over the mesh. If the app has a server-side request forgery (SSRF) bug, runs user-supplied plugins, or is compromised, code running on that server can issue HTTP requests to `https://home.<zone>/api/admin/...`.
3. Because the request originates from the server's mesh IP, `registrar` sees the owner's `Member` record and treats the server as the owner. The attacker can then:
   - promote their own account to `admin` or `owner` (`POST /api/admin/members/<attacker>/role`),
   - mint new invites (`POST /api/invites`),
   - suspend or kick other members (`POST /api/admin/members/<handle>/kick`),
   - issue personal/server keys (`POST /api/devices`) or reassign names (`POST /api/names`).

**Fix:** Check `device.Kind` in `MeshHandler`. Allow `server` devices only read-only `GET /api/me` (returning a minimal payload of `member`, `this_device`, and `zone`—omitting `devices`, `names`, and `invites` so `hogman-join` verification still works when joining a server) and `GET /api/directory`. Return `403` for all mutating routes and all `/api/admin/*` endpoints when the caller is a `server` device.

## Actionable findings

1. [x] **Registrar CSRF protection on IP-authenticated mesh API** (`core/registrar/http.go`, PR #2): Enforce same-origin (`Sec-Fetch-Site` in `{"same-origin", "none"}` when sent, blocking `"same-site"` because `.hogman` is not on the Public Suffix List; `Origin` matching `https://home.<zone>` when sent) and `Content-Type: application/json` on state-changing requests (`POST`/`PUT`/`PATCH`), plus safe optional-JSON body parsing (`readOptionalJSON`) for `/api/admin/members/{handle}/{action}`.
2. [x] **Restrict `server` devices on mesh API** (`core/registrar/http.go`, PR #2): Deny `device.Kind == "server"` on all mutations and `/api/admin/*` routes (`403`), and trim `GET /api/me` for servers to `{member, this_device, zone}`.
3. [x] **`Redeem()` & `Claim()` locking/rollback races, owner name seizure, `Kick()` error logging** (`core/registrar/service.go`, `core/registrar/store.go`, PR #2): Hold `s.mu` across the full `Redeem()` and `Claim()` workflows; roll back member/invite/Headscale user/device-key records on partial failures; allow owners (`a.IsOwner()`) to seize active names directly in `Claim()`; log errors in `Kick()` instead of discarding them.
4. [x] **Atomic unique temp file in `writeZone()` + IPv6 `AAAA` records** (`core/registrar/service.go`, `core/registrar/store.go`, PR #2): Use `os.CreateTemp` in `writeZone()` instead of a fixed `.db.zone.tmp` path, and include `AAAA` records for servers with an IPv6 mesh address.
5. [ ] **Side-by-side (`tsnet`) deterministic non-ephemeral proxy port** (`core/join/alongside.go`): Replace `127.0.0.1:0` ephemeral port assignment with a deterministic port in `[17000, 27000)` derived from the zone name (scanning forward if busy) so reboots do not collide with ephemeral sockets.
6. [ ] **Side-by-side `agent.go` shared `http.Transport`, TCP half-close handling, and `.nodes.<zone>` MagicDNS lookup** (`core/join/agent.go`): Reuse one `http.Transport` on `agent`, propagate half-close (`CloseWrite`) and wait for both directions in `connect()`, and fall back to `LocalClient().Status()` peers for `.nodes.<zone>` names when CoreDNS does not answer for them.
7. [ ] **macOS PAC `Enabled:` parsing, stop overwriting existing `/proxy.pac`, and plist XML escaping** (`core/join/service_darwin.go`, `core/join/proxy_helpers.go`): Parse both `Enabled:` and `URL:` from `networksetup -getautoproxyurl`, leave any active non-matching PAC URL alone (including `/proxy.pac` from a corporate proxy or another Hogman pen), re-enable a disabled matching PAC URL, and XML-escape LaunchAgent plist text.
8. [ ] **Remove `--yes` tailnet-switch override in `hogman-join`, strict fragment allowlist in `core/join-page/index.html`, update `core/README.md`** (`core/join/main.go`, `core/join-page/index.html`, `core/README.md`): Do not let an undocumented `--yes` flag disconnect an existing Tailscale network; validate `t`, `k`, `fp`, and `location.host` in `join-page/index.html` and reconstruct a clean link instead of interpolating raw `location.href`; update the `join/` layout line in `core/README.md` to reflect embedded `tsnet`.
9. [ ] **Canonical `www.hogman.network` -> `hogman.network` 301 redirect** (`site/Caddyfile`): Redirect `www.hogman.network` permanently to `https://hogman.network{uri}` so canonical URLs and OpenGraph metadata stay consistent.
10. [ ] **RFC1918 `trusted_proxies` in `core/templates/headscale.yaml`**: Configure `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` so Headscale accepts `X-Real-IP` forwarded by the Caddy `edge` container.

## Open follow-ups (deferred)

- **Single-writer registrar IPC**: Have `./hogman` CLI invocations talk to the running `registrar serve` process over a Unix domain socket rather than opening SQLite and pushing Headscale policies / writing the zone file from a second process.
- **Multi-pen PAC merging**: In side-by-side mode, if a member regularly stays joined to two or more Hogman pens simultaneously on macOS, generate or merge a combined PAC file so the second pen does not require manual proxy selection.
- **Static site hosting & `hogman.fly.dev` canonicalization**: Decide whether `hogman.fly.dev` should also redirect to `hogman.network`, and optionally move `site/public/` to Cloudflare Workers Static Assets to eliminate Fly scale-to-zero cold starts.
- **`core/hogman` JSON parsing**: Replace the `sed`-based `json_field` helper in `core/hogman` with `jq` or a small Go subcommand.
- **Suspended members' DNS visibility**: Decide whether names owned by `suspended` members should stay in CoreDNS / `GET /api/directory` (while Headscale grants block all traffic to their servers) or be hidden until resumed.
