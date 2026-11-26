# Hogman

**Private HTTPS networks ("pens") over WireGuard with real domain names and zero public IP addresses.**

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-14181f)](LICENSE)
[![Status: experimental](https://img.shields.io/badge/status-experimental-b45309)](#security-limits--status)
[![Hogman for Work](https://img.shields.io/badge/work-work.hogman.network-15803d)](https://work.hogman.network)
[![Docs](https://img.shields.io/badge/docs-work.hogman.network%2Fdocs-4b5563)](https://work.hogman.network/docs/)

Hogman lets small businesses, teams, and groups take internal web apps, dashboards, and operational
equipment controllers off the open internet. Invited members reach private HTTPS (`:443`) sites in
any ordinary browser (Chrome, Safari, Firefox) with standard browser certificates; to everyone else
on Earth, there is no public IP address to scan.

- **For businesses & operations:** [work.hogman.network](https://work.hogman.network)
- **Consumer site:** [hogman.network](https://hogman.network)
- **Create a pen:** [get.hogman.network](https://get.hogman.network) or
  [get.work.hogman.network](https://get.work.hogman.network) — invite-only while we test. A free pen
  with an invite code gets a name with a random ending; custom bare names are $25/year (Personal) or
  $250/year (Work).
- **Documentation:** [work.hogman.network/docs](https://work.hogman.network/docs/) ·
  [Policies & billing](https://work.hogman.network/docs/policies.html)
- **How Hogman works:** [Step-by-step architecture map](docs/how-hogman-works.md) ·
  [Architecture & security](https://work.hogman.network/docs/security.html)

Hogman runs pen control planes hosted-only on `hogman.network` (no self-hosted pen server support),
while your sites, folders, and bridged local devices run on your own machines via
`hogman share`. The core networking stack, client CLI, browser extension, and ACME DNS-01
challenge server are open source under [AGPL-3.0](LICENSE) with SLSA-attested release binaries.

---

## How it works

1. **Create a pen** at [get.hogman.network](https://get.hogman.network). You claim an isolated
   private DNS zone (`<pen>.pens.hogman.network`) and an in-pen management portal
   (`https://home.<pen>.pens.hogman.network`) where owners and admins see a summary of members,
   devices, sites, and status, inspect **All devices** and **Recent activity** (audit log), and
   suspend or remove anyone across all their devices in about two seconds.
2. **Invite your people.** Send each person a single-use invite link. They open it, run one
   command, pick a handle, and browse your pen in Chrome, Safari, or Firefox. Everyone without an
   invite sees nothing.
3. **Put HTTPS web servers inside it.** Run one command to share a local port, a static folder, or
   a LAN device's web interface into the pen with its own domain name and a standard browser
   padlock.

### Joining a pen

Invited to a pen? Open the invite link and run the single command it shows:

```text
$ curl -fsSL --proto '=https' --proto-redir '=https' https://<your-pen>.gate.hogman.network/start | HOGMAN_EXPECTED_HOST='<your-pen>.gate.hogman.network' sh -s -- 'https://<your-pen>.gate.hogman.network/join#t=...'

• Downloading hogman for Darwin arm64 from <your-pen>.gate.hogman.network
  checked: SHA-256 matches
  saved as ~/hogman (keep it: it updates, shares and leaves later)

• Redeeming the invite
  Choose your name on the network: alice
  welcome, alice

✓ You're in. You are alice on <your-pen>.pens.hogman.network.
```

- Runs unprivileged as your user (no `TUN` interface, no root daemon) and leaves your regular
  internet, LAN, and any existing Tailscale setup untouched.
- On macOS, Hogman never asks for your Mac password or runs `sudo`: install the Hogman browser
  extension (or paste the printed automatic proxy URL once in *System Settings → Network → Proxies*).
- Add more devices from your pen's home page (*Add a device*), update anytime with
  `~/hogman update`, or leave one pen with `~/hogman leave <pen>` (its short name, full name or link).
  `~/hogman leave-all` leaves every pen and asks first.
- Upgrading from an older `hogman-join` install: `hogman-join update` will fail with a checksum error
  because the client was renamed to `hogman`. Download `~/hogman`, run `update`, and then delete
  `~/hogman-join`:

  ```sh
  curl -fsSLo ~/hogman "https://hogman.network/dl/hogman-$(uname -s)-$(uname -m)"
  chmod +x ~/hogman
  ~/hogman update
  ```
- To take Hogman off a computer entirely: `~/hogman uninstall` (asks first), then delete
  `~/hogman` and remove the browser extension if you added it.
- Owners have no account recovery, so `leave`, `leave-all` and `uninstall` refuse a pen you own.
  Make someone else an owner first. `--force` overrides this only after a warning and typing the
  pen's name exactly.
- **Renewing a sleeping pen:** paid pens enter a 30-day grace period after their paid year ends,
  then go to sleep (containers stopped, state kept for 1 year). To renew a sleeping pen, open its
  sleeping notice (or `https://<signup-host>/#wake=<pen>`) and press **Wake pen for renewal**. Once
  the pen's HTTPS certificate is ready (usually 1–2 minutes), it opens for a 10-minute renew-only
  window (capped at 20 minutes from button press, 3 wakes/day and 10/month per pen, and 2 concurrent
  wakes per host): only active owners and admins on already-joined personal devices can load
  `https://home.<zone>` and click **Renew now**; shares, invites, devices, and access for regular
  members stay off until payment lands. As soon as payment completes, normal access restores
  automatically without a restart. If wake limits or host capacity are reached, contact your host
  operator.

### Hosting HTTPS servers (`share`)

Anything with a web interface works (the local upstream can be plain HTTP; members always connect
over HTTPS on port 443) — a local port, a static directory, or a local LAN controller bridged from
a small always-on computer on site (using a share link from your pen's home page):

```text
$ ~/hogman share cooler-1 http://192.168.1.40 --background '<share-link>'
$ ~/hogman share photos ~/holiday --note "Shared archive"
$ ~/hogman share app 3000 --background

✓ https://app.store-north.pens.hogman.network is up.
  Everyone in the pen can open it.
```

Each share joins as its own isolated server node (`tag:server`), so personal laptops accept zero
inbound connections and zero inbound router ports are opened. Share targets are limited to local
and private LAN addresses (loopback, RFC 1918, ULA, and link-local); public internet IPs, cloud
metadata endpoints, and CGNAT/Tailscale addresses (`100.64.0.0/10`) are refused after DNS
resolution. Take a share down anytime with `~/hogman share stop app`.

Full guides: [Quickstart](https://work.hogman.network/docs/) ·
[Joining a pen](https://work.hogman.network/docs/join.html) ·
[Hosting HTTPS servers](https://work.hogman.network/docs/share.html) ·
[Running a pen](https://work.hogman.network/docs/keeper.html) ·
[FAQ & troubleshooting](https://work.hogman.network/docs/faq.html)

---

## Using Hogman with a VPN

On macOS, Network Extension VPNs (ProtonVPN, Mullvad, WireGuard, corporate VPNs) override the
system automatic proxy while connected, so browsers stop seeing pen names even though `hogman`
stays up.

- **Firefox (works today):** point Firefox's built-in *Settings → Network Settings → Automatic
  proxy configuration URL* to the `http://127.0.0.1:<port>/proxy.pac` address printed by
  `hogman`. Pen sites go to Hogman; ordinary browsing stays on your VPN.
- **Browser extension ([`browser-ext/`](browser-ext/README.md)):** Manifest V3 extension for
  Chrome, Brave, Edge, Arc, Vivaldi, Chromium, Firefox (128+), and LibreWolf that routes only the
  pens you explicitly allow per browser profile straight to `hogman` (fail-closed for everything
  else) while leaving regular traffic on your VPN. Published on the Chrome Web Store, with Firefox
  Add-ons (AMO) review pending; developers can also load unpacked builds from `browser-ext/`.
- **Safari:** Apple does not expose proxy APIs to Safari extensions, so pause your VPN while
  visiting pen sites in Safari.

---

## Architecture & security

What happens when Bob opens `https://cooler-1.store-north.pens.hogman.network`:

```text
1 DNS     cooler-1.store-north.pens.hogman.network -> 100.80.12.7  (pen registrar, mesh-only :53)
2 policy  bob's laptop -> cooler-1 share node                      (allowed: member -> tag:server, :443 only)
3 tunnel  WireGuard, bob -> share node, end to end                 (direct, else pen relay ciphertext)
4 TLS     standard CertMagic cert from the share node              (verified by stock OS trust store)
✓ page loads with a standard padlock

A stranger looking up the same name publicly: NODATA from ns1. Zero A/AAAA records exist.
```

- **Encrypted mesh:** each pen runs its own [Headscale](https://github.com/juanfont/headscale)
  control plane and WireGuard mesh (`tsnet`), with a dedicated relay port for ciphertext fallback
  when firewalls block direct paths.
- **Split-horizon DNS & public HTTPS:** `ns1.hogman.network` serves only temporary
  `_acme-challenge.*` TXT records, `SOA`, `NS`, and `CAA` — never `A`/`AAAA` records. Shares and
  pen home pages obtain standard public certificates via ACME DNS-01 ([CertMagic](https://github.com/caddyserver/certmagic),
  Let's Encrypt primary with Google Trust Services fallback). Private keys stay on the serving host;
  no custom root CA is installed.
- **HTTPS (`:443`) to servers only:** default-deny ACLs block SSH, raw TCP/UDP, exit nodes, and all
  inbound connections to personal devices. `hogman`'s loopback proxy pins every dialed IP to a
  verified mesh peer via `WhoIs`, never touching `127.0.0.1` or LAN hosts.
- **Isolated hosted pens:** each pen runs in 2 unprivileged, read-only containers (`uid 65532`,
  `cap_drop: ALL`, no `NET_ADMIN` or `/dev/net/tun` — `headscale` and `registrar` with embedded
  `tsnet`, authoritative DNS, and portal) on its own Docker bridge (~30–40 MB idle RAM) behind a
  shared `*.gate.hogman.network` front door, with nightly encrypted off-host backups and automated
  health checks.
- **Verifiable releases:** every `hogman` release binary is built by GitHub Actions with SLSA
  provenance:
  ```bash
  gh attestation verify hogman --repo celtiberi/hogman
  ```

Read the step-by-step map in [How Hogman works](docs/how-hogman-works.md) or the full security breakdown in [Architecture & security](https://work.hogman.network/docs/security.html).

---

## Security limits & status

- **Experimental & unaudited:** Hogman is young security software and has not had an independent
  security audit. Evaluate carefully and do not rely on it for safety-critical or high-stakes
  systems yet.
- **Hides devices, does not patch them:** putting an equipment controller or web app in a pen
  removes it from the open internet and narrows reachability to pen members, but it does **not**
  patch firmware or application bugs. Keep vendor updates enabled and change default credentials.
- **Private, not anonymous:** pen and site hostnames appear in public Certificate Transparency logs
  (names only, never site contents). Your pen's keeper and `hogman.network` (as control-plane host)
  can see membership, devices, and mesh DNS lookups, and a compromised host could in principle add a
  rogue device or request a CT-logged certificate. Payloads stay end-to-end encrypted with
  WireGuard + TLS 1.3.
- **No account recovery:** lose every device in a pen and that account is gone; we don't offer
  account recovery. Hosted pens run on our servers, so whoever operates the server could technically
  act on a pen (for example, create a device key); we don't. **If you own a pen, appoint a second
  owner.**
- **Shared parent suffix (`pens.hogman.network`):** for multi-site operations, use separate pens per
  region or store group to limit blast radius. Until `pens.hogman.network` is listed on the Public
  Suffix List, use a separate browser profile for any pen you don't fully trust so cookies stay
  isolated.
- **Current limits & platforms:** macOS and Linux work today; Windows is built but untested; a
  mobile app is in the works. Free and Personal pens default to **25 members** and **50 devices**,
  and Work pens default to **500 members** and **500 devices** (configurable by the host operator;
  active owners retain personal-device lockout headroom so a full pen cannot lock out an owner).
  Regular members may hold at most **3 unused device keys** at a time (**10** for admins and
  owners). Each pen may get certificates for a limited number of distinct new
  names: 5 per rolling hour and 20 per rolling 7 days on Free and Personal pens, 40 and 120 on Work
  pens, under a shared limit across all pens (`home.<pen>` uses one; attempts count, not issued
  certificates; a name already counted in the last 7 days doesn't count again). Pen names, member
  handles, and kicked site names are permanently retired.

**Found a security vulnerability?** Don't open a public issue — report it privately using GitHub's
**Security → Report a vulnerability** button on this repository.

**Anything else:** `hogman-support@proton.me`.

---

## Repository layout

Built on [Headscale](https://github.com/juanfont/headscale), [Tailscale `tsnet`](https://tailscale.com),
[Caddy](https://caddyserver.com), and [CertMagic](https://github.com/caddyserver/certmagic):

| Path | What it does |
|---|---|
| [`core/registrar`](core/registrar) | Membership ledger, invites, devices, names, kicking, ACL policy generation, mesh DNS, and ACME DNS-01 coordination. |
| [`core/join`](core/join) | `hogman` client: enrolls devices, runs the loopback `:443` proxy, hosts `share` nodes, and provides `hogman-native-host` for the browser extension. |
| [`browser-ext`](browser-ext) | Manifest V3 extension for Chrome, Brave, Edge, Arc, Vivaldi, Chromium, Firefox (128+), and LibreWolf (VPN coexistence + per-profile pen allowlists). |
| [`deploy/`](deploy/README.md) | Authoritative DNS-01 challenge server ([`deploy/challenge-dns`](deploy/challenge-dns)) plus build, release, and changelog scripts. |
| [`packaging`](packaging) | Homebrew formula and WinGet manifest templates for the `hogman` CLI. |

### Building and testing from source

`core/join` and `core/registrar` enforce `-tags=ts_omit_peerapiserver` at compile time so Tailscale's
PeerAPI server is never linked in:

```bash
(cd core/join && GOFLAGS="-tags=ts_omit_peerapiserver" go test ./...)
(cd core/registrar && GOFLAGS="-tags=ts_omit_peerapiserver" go test ./...)
(cd deploy/challenge-dns && go test ./...)
node --test browser-ext/test/pac_test.mjs
```

More developer docs:
- [`core/README.md`](core/README.md) — core stack and Docker e2e test harness
- [`browser-ext/README.md`](browser-ext/README.md) — extension architecture, build, and local install
- [`docs/how-hogman-works.md`](docs/how-hogman-works.md) — step-by-step map of every moving part, packet flow, portal auth, revocation, and scaling
- [`docs/security/`](docs/security/) — security design notes and public-certificate architecture
- [`docs/history/initial-design.md`](docs/history/initial-design.md) — initial design spec and decision history

---

## License

Hogman's code is free software under the [GNU Affero General Public License v3.0](LICENSE). You may
use, study, change, and share it; if you run a modified version as a service for others, you must
offer them your changes under the same license.

The artwork (the paintings, logo, and mascot icons) is not covered by that
license. All rights reserved.
