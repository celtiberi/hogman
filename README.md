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

- **For businesses & operations:** [work.hogman.network](https://work.hogman.network) ($120/year per pen)
- **Personal site:** [hogman.network](https://hogman.network) ($50/year per pen, or $0 Free suffixed pens)
- **Create a pen:** [get.work.hogman.network](https://get.work.hogman.network) (Work) · [get.hogman.network](https://get.hogman.network) (Personal) — invite-only testbed while live billing finishes setup
- **Documentation & policies:** [work.hogman.network/docs](https://work.hogman.network/docs/) · [Policies & billing](https://work.hogman.network/docs/policies.html)
- **Architecture & threat model:** [Architecture & security](https://work.hogman.network/docs/security.html)

Hogman runs pen control planes hosted-only on `hogman.network` (no self-hosted pen server support),
while your sites, folders, and bridged local devices run on your own machines via
`hogman-join share`. The entire codebase is open source under [AGPL-3.0](LICENSE) with
SLSA-attested release binaries.

---

## How it works

1. **Create a pen** at [get.hogman.network](https://get.hogman.network). You claim an isolated
   private DNS zone (`<pen>.pens.hogman.network`) and an in-pen management page where you control
   membership — and can suspend or kick anyone across all their devices in about two seconds.
2. **Invite your people.** Send each person a single-use invite link. They open it, run one
   command, pick a handle, and browse your pen in Chrome, Safari, or Firefox. Everyone without an
   invite sees nothing.
3. **Put HTTPS web servers inside it.** Run one command to share a local port, a static folder, or
   a LAN device's web interface into the pen with its own domain name and a standard browser
   padlock.

### Joining a pen

Invited to a pen? Open the invite link and run the short command it shows:

```text
$ curl -fsSL https://store-north.gate.hogman.network/start | sh
Paste your invite link: https://store-north.gate.hogman.network/join#t=(your invite)

• Downloading hogman-join for Darwin arm64 from store-north.gate.hogman.network
  checked: SHA-256 matches
  saved as ~/hogman-join (keep it: it updates, shares and leaves later)

• Redeeming the invite
  Choose your name on the network: alice
  welcome, alice

✓ You're in. You are alice on store-north.pens.hogman.network.
```

- Runs unprivileged as your user (no `TUN` interface, no root daemon) and leaves your regular
  internet, LAN, and any existing Tailscale setup untouched.
- On macOS, it prompts for local-network access and asks once for your Mac password to configure the
  system automatic proxy (`networksetup`).
- Add more devices from your pen's home page (*Add a device*), update with
  `~/hogman-join update`, or disconnect from a pen with `~/hogman-join leave <zone>`.

### Hosting HTTPS servers (`share`)

Anything with a web interface works (the local upstream can be plain HTTP; members always connect
over HTTPS on port 443) — a local port, a static directory, or a local LAN controller bridged from
a small always-on computer on site (using a share link from your pen's home page):

```text
$ ~/hogman-join share cooler-1 http://192.168.1.40 '<share-link>' --background
$ ~/hogman-join share sops ~/site-manuals --note "Equipment manuals"
$ ~/hogman-join share app 3000 --background

✓ https://app.store-north.pens.hogman.network is up.
  Everyone in the pen can open it.
```

Each share joins as its own isolated server node (`tag:server`), so personal laptops accept zero
inbound connections and zero inbound router ports are opened. Take a share down anytime with
`~/hogman-join share stop app`.

Full guides: [Quickstart](https://work.hogman.network/docs/) ·
[Onboarding staff & devices](https://work.hogman.network/docs/join.html) ·
[Bridging equipment & apps](https://work.hogman.network/docs/share.html) ·
[Managing access & offboarding](https://work.hogman.network/docs/keeper.html) ·
[Policies & billing](https://work.hogman.network/docs/policies.html) ·
[FAQ & troubleshooting](https://work.hogman.network/docs/faq.html)

---

## Using Hogman with a VPN

On macOS, Network Extension VPNs (ProtonVPN, Mullvad, WireGuard, corporate VPNs) override the
system automatic proxy while connected, so browsers stop seeing pen names even though `hogman-join`
stays up.

- **Firefox (works today):** point Firefox's built-in *Settings → Network Settings → Automatic
  proxy configuration URL* to the `http://127.0.0.1:<port>/proxy.pac` address printed by
  `hogman-join`. Pen sites go to Hogman; ordinary browsing stays on your VPN.
- **Browser extension ([`browser-ext/`](browser-ext/README.md)):** Manifest V3 extension for
  Chrome, Brave, Edge, and Firefox (128+) that routes only the pens you explicitly allow per
  browser profile straight to `hogman-join` (fail-closed for everything else) while leaving regular
  traffic on your VPN. Store listings are not yet published on the Chrome Web Store or Mozilla
  Add-ons; developers can load unpacked builds from `browser-ext/` today.
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
  inbound connections to personal devices. `hogman-join`'s loopback proxy pins every dialed IP to a
  verified mesh peer via `WhoIs`, never touching `127.0.0.1` or LAN hosts.
- **Isolated hosted pens:** each pen runs in 4 isolated containers on its own Docker bridge (~75 MB
  idle RSS) — `headscale`, `registrar`, and `edge` run non-root (`uid 65532`) with read-only root
  filesystems and dropped capabilities, while `core-mesh` holds only the minimal
  `NET_ADMIN`/`NET_RAW`/`CHOWN`/`DAC_OVERRIDE` capabilities needed for WireGuard `/dev/net/tun` —
  behind a shared `*.gate.hogman.network` front door, with nightly encrypted off-host backups and
  automated health checks.
- **Verifiable releases:** every `hogman-join` release binary is built by GitHub Actions with SLSA
  provenance:
  ```bash
  gh attestation verify hogman-join --repo celtiberi/hogman
  ```

Read the full breakdown in [Architecture & security](https://work.hogman.network/docs/security.html).

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
- **Zero account recovery:** lose every device in a pen and that account is gone — no support
  backdoor exists. **If you own a pen, appoint a second owner.**
- **Shared parent suffix (`pens.hogman.network`):** for multi-location operations, use separate pens
  per region or store group to limit blast radius. Until `pens.hogman.network` is listed on the
  Public Suffix List, use a separate browser profile for any pen you don't fully trust so cookies
  stay isolated.
- **Current limits & platforms:** macOS and Linux work today; Windows is built as an untested
  preview; a mobile app is in the works. Per-pen certificate caps are **5 distinct new names/hour
  and 20/7 days** on Free/Personal pens, or **10/hour and 60/7 days** on Work pens (with a shared
  40/hour soft / 60/hour hard global ceiling; `home.<pen>` uses one slot; attempts count, not issued
  certs; retries of names already counted within the last 7 days are free). Pen names, member
  handles, and removed members' site names are permanently retired.

**Found a security vulnerability?** Don't open a public issue — report it privately via GitHub's
**Security → Report a vulnerability** button on this repository or email
`hogman-support@proton.me`.

---

## Repository layout

Built on [Headscale](https://github.com/juanfont/headscale), [Tailscale `tsnet`](https://tailscale.com),
[Caddy](https://caddyserver.com), and [CertMagic](https://github.com/caddyserver/certmagic):

| Path | What it does |
|---|---|
| [`core/registrar`](core/registrar) | Membership ledger, invites, devices, names, kicking, ACL policy generation, mesh DNS, and ACME DNS-01 coordination. |
| [`core/join`](core/join) | `hogman-join` client: enrolls devices, runs the loopback `:443` proxy, hosts `share` nodes, and provides `hogman-native-host` for the browser extension. |
| [`browser-ext`](browser-ext) | Manifest V3 extension for Chrome, Brave, Edge, and Firefox (VPN coexistence + per-profile pen allowlists). |
| [`deploy/challenge-dns`](deploy/challenge-dns) | Authoritative DNS-01 challenge server (`_acme-challenge.*` TXT, `SOA`, `NS`, `CAA`; never `A`/`AAAA`). |
| [`deploy/hogman-host`](deploy/hogman-host) & [`deploy/signup`](deploy/signup) | Isolated hosted pens, shared `*.gate.hogman.network` front door, backups, monitoring (`hogman-watch.sh`), and web sign-ups. |
| [`infra`](infra) | DNS configuration as code (`dnscontrol`). |
| [`test-arena`](test-arena) | Disposable sandbox testing and automated red-team harness. |

More developer & operator docs:
- [`core/README.md`](core/README.md) — core stack and Docker e2e test harness
- [`deploy/README.md`](deploy/README.md) — operator guide (hosted pens, `challenge-dns`, backups, monitoring)
- [`browser-ext/README.md`](browser-ext/README.md) — extension architecture, build, and local install
- [`docs/security/`](docs/security/) — security design notes and public-certificate architecture
- [`DESIGN.md`](DESIGN.md) — initial design spec and decision history

---

## License

Hogman's code is free software under the [GNU Affero General Public License v3.0](LICENSE). You may
use, study, change, and share it; if you run a modified version as a service for others, you must
offer them your changes under the same license.

The artwork (the paintings, logo, and mascot icons) is not covered by that
license. All rights reserved.
