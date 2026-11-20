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
5. [x] **Side-by-side (`tsnet`) deterministic non-ephemeral proxy port** (`core/join/alongside.go`, PR #3): Replace `127.0.0.1:0` ephemeral port assignment with a deterministic port in `[17000, 27000)` derived from the zone name (scanning forward if busy) so reboots do not collide with ephemeral sockets.
6. [x] **Side-by-side `agent.go` shared `http.Transport`, TCP half-close handling, and `.nodes.<zone>` MagicDNS lookup** (`core/join/agent.go`, PR #3): Reuse one `http.Transport` on `agent`, propagate half-close (`CloseWrite`) and wait for both directions in `connect()`, and fall back to `LocalClient().Status()` peers for `.nodes.<zone>` names when CoreDNS does not answer for them.
7. [x] **macOS PAC `Enabled:` parsing, stop overwriting existing `/proxy.pac`, and plist XML escaping** (`core/join/service_darwin.go`, `core/join/proxy_helpers.go`, PR #3): Parse both `Enabled:` and `URL:` from `networksetup -getautoproxyurl`, leave any active non-matching PAC URL alone (including `/proxy.pac` from a corporate proxy or another Hogman pen), re-enable a disabled matching PAC URL, and XML-escape LaunchAgent plist text.
8. [x] **Remove `--yes` tailnet-switch override in `hogman-join`, strict fragment allowlist in `core/join-page/index.html`, update `core/README.md`** (`core/join/main.go`, `core/join-page/index.html`, `core/README.md`, PR #3): Do not let an undocumented `--yes` flag disconnect an existing Tailscale network; validate `t`, `k`, `fp`, and `location.host` in `join-page/index.html` and reconstruct a clean link instead of interpolating raw `location.href`; update the `join/` layout line in `core/README.md` to reflect embedded `tsnet`.
9. [x] **Canonical `www.hogman.network` -> `hogman.network` 301 redirect** (`site/Caddyfile`, PR #4): Redirect `www.hogman.network` permanently to `https://hogman.network{uri}` so canonical URLs and OpenGraph metadata stay consistent.
10. [x] **RFC1918 `trusted_proxies` in `core/templates/headscale.yaml`** (`core/templates/headscale.yaml`, PR #4): Configure `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` so Headscale accepts `X-Real-IP` forwarded by the Caddy `edge` container.

## Open follow-ups (deferred)

- **Single-writer registrar IPC**: Have `./hogman` CLI invocations talk to the running `registrar serve` process over a Unix domain socket rather than opening SQLite and pushing Headscale policies / writing the zone file from a second process.
- **Multi-pen PAC merging**: In side-by-side mode, if a member regularly stays joined to two or more Hogman pens simultaneously on macOS, generate or merge a combined PAC file so the second pen does not require manual proxy selection.
- **Static site hosting & `hogman.fly.dev` canonicalization**: Decide whether `hogman.fly.dev` should also redirect to `hogman.network`, and optionally move `site/public/` to Cloudflare Workers Static Assets to eliminate Fly scale-to-zero cold starts.
- **`core/hogman` JSON parsing**: Replace the `sed`-based `json_field` helper in `core/hogman` with `jq` or a small Go subcommand.
- **Suspended members' DNS visibility**: Decide whether names owned by `suspended` members should stay in CoreDNS / `GET /api/directory` (while Headscale grants block all traffic to their servers) or be hidden until resumed.

## Second security review (commit `99a5de9`)

Addressed across four independent, non-overlapping pull requests:

1. [x] **Mesh IP-reuse identity hijack & empty IP bypass** (`core/templates/headscale.yaml`, `core/registrar/{http,service,store}.go`, PR #5): Switch Headscale IP allocation from `sequential` to `random`, reject empty/invalid `X-Forwarded-For` headers and empty-IP database matches in `DeviceByIP()`, and confirm live Headscale node IDs via `VerifyLiveCaller()` in `identify()`.
2. [x] **Inconsistent admin vs. owner/admin RBAC & stale child subdomains** (`core/registrar/service.go`, PR #5): Prevent admins from removing another admin's device, issuing keys/claiming names for owners or admins, or releasing held names or names owned by owners/admins; clean up child subdomains when the owner seizes a parent name.
3. [x] **Public invite redemption DoS, unbounded state quotas, & HTTP timeouts** (`core/registrar/{http,main,service,store}.go`, PR #5): Rate-limit `POST /hogman/v1/redeem` per IP (`429`), pre-validate `hmi_` tokens before acquiring `Service.mu`, cap open device keys/names/open invites/note length per member, revoke open keys on `Suspend()`, filter stale keys in `Sync()`, and set `WriteTimeout`/`IdleTimeout` on both HTTP servers.
4. [x] **Portal & join-page clickjacking and inline script/style exposure** (`core/config/{portal,edge,edge-behind-front}.Caddyfile`, `core/portal/`, `core/join-page/`, PR #6): Add `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and strict `Content-Security-Policy` (`frame-ancestors 'none'`, `script-src 'self'`, `style-src 'self'`) on the portal and `/join`; extract external JS/CSS assets (`portal.{js,css}`, `/join/assets/join.{js,css}`); key inline remove confirmation by device ID.
5. [x] **Headscale admin API / Swagger exposure & wildcard edge virtual host** (`core/config/{edge,edge-behind-front}.Caddyfile`, PR #6): Block `/api/*` and `/swagger*` with `404` on both edge Caddyfiles, and restrict `edge-behind-front.Caddyfile` to `http://{$PUBLIC_HOST}`.
6. [x] **Invite link credential injection & weak CA IP name constraints** (`core/join/link.go`, PR #7): Reject URL `userinfo`, require empty `PermittedIPRanges` with both `0.0.0.0/0` and `::/0` explicitly in `ExcludedIPRanges`, and check the root CA validity window (`NotBefore`/`NotAfter`).
7. [x] **Unvalidated `/hogman/v1/network` metadata & loose zone regex** (`core/join/main.go`, PR #7): Tighten `zoneRE` and verify `login_server` (`https://<host>`), `portal` (`https://home.<zone>`), and `dns_server` (within Tailscale mesh ranges).
8. [x] **World-readable cert tempfiles, failed-setup state leaks, & macOS CN trust matching** (`core/join/{main,alongside,trust_darwin}.go`, PR #7): Write temporary CA certs inside `0700` temp directories at mode `0600`, clean up failed side-by-side directories/keys, and use `security verify-cert` against the exact root cert on macOS.
9. [x] **Spent/failed `authkey` cleanup, proxy HTTP scheme guard, systemd quoting, & loopback caveat** (`core/join/{agent,proxy_helpers,service_linux}.go`, `core/README.md`, PR #7): Delete `authkey` unconditionally after `node.Up`, restrict `forward()` to `http`, quote paths in systemd `ExecStart`, and document the shared-host `127.0.0.1` proxy caveat in `core/README.md`.
10. [x] **Multi-tenant pen name traversal & Caddyfile/Compose host injection** (`deploy/hogman-host`, `core/hogman`, PR #8): Validate pen names strictly across `add`/`pen`/`upgrade`/`remove` and enforce DNS hostname (`valid_host`) and IPv4 (`valid_ipv4`) validation before templating config files.
11. [x] **Personal identifier & domain examples in deploy docs/usage** (`deploy/hogman-host`, `deploy/README.md`, PR #8): Replace personal identifier/domain examples with generic `bobo`/`alice` and `hs.example.com`.
12. [x] **SSH lockdown verification, password-auth hardening, & Docker/UFW note** (`deploy/bootstrap.sh`, PR #8): Add the Tailscale SSH rule before removing `OpenSSH`/`22/tcp`/`22`, fail if an unrestricted public SSH rule remains, disable SSH password auth when `authorized_keys` is present, and note Docker's `iptables` bypass behavior vs. UFW.
13. [x] **Restrictive permissions on host and pen secret directories/files** (`deploy/hogman-host`, `core/hogman`, PR #8): Restrict `$FRONT/data` and pen secret directories (`pki/offline`, `step/secrets`, `secrets/registrar`, `mesh`, `registrar`, `headscale/lib`) to `700` and create `host.env`, CA passwords, `mesh/*.env`, and `headscale_api_key` under `umask 077`.
14. [x] **Container resource limits, capability drops, and read-only hardening** (`core/compose.yaml`, `deploy/hogman-host`, PR #8): Add `mem_limit` and `pids_limit` across services, run `coredns` read-only with `cap_drop: [ALL]` + `cap_add: [NET_BIND_SERVICE]`, and run `registrar` as `${HOGMAN_UID:-1000}:${HOGMAN_GID:-1000}` with `read_only: true`, `tmpfs: [/tmp]`, and `cap_drop: [ALL]`.
