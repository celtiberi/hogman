# Operator guide

Reference for operating the hosted Hogman server on `hogman.network` — raising pens,
managing sign-ups, backups, uptime alerts, and updates.

> **Hosted pens only (D-24):** Hogman runs pen control planes only on `hogman.network` and does not
> support self-hosted pen servers or custom pen domains. The codebase is open under AGPL-3.0 to
> inspect, test, and verify.

## Server layout

A fresh Ubuntu 24.04 server (2 GB RAM, public IPv4) holds many pens behind a shared Caddy front
door and a host-level ACME DNS-01 challenge server (`challenge-dns`):

- **`bootstrap.sh`**: automatic security updates, Docker, Tailscale (admin SSH access only), UFW
  firewall (80/tcp, 443/tcp, 53/tcp, 53/udp, and per-pen UDP relay ports), and swap.
- **`hogman-host`**: manages the front door (`hogman-front`), host services, pens under
  `/opt/hogman/pens/<name>`, backups, and the sign-up service (`hogman-signup`).

## Initial host setup

1. **Install** on the server:

   ```bash
   curl -fsSL https://github.com/celtiberi/hogman/releases/latest/download/install.sh | sudo bash
   ```

   (`https://hogman.network/install.sh` redirects to the same GitHub Release for convenience; use the
   GitHub Releases URL directly when auditing or skipping the marketing site.) Downloads the
   version-pinned release tarball and GitHub-built binaries (signed SLSA provenance:
   `gh attestation verify FILE --repo celtiberi/hogman`), bootstraps the OS, installs into
   `/opt/hogman`, and starts the shared front door. Pens run as unprivileged user `65532`.

2. **Lock SSH to Tailscale:**

   ```bash
   tailscale up --hostname=your-server                # open the link it prints
   bash /opt/hogman/bootstrap.sh --lock-ssh           # from now on: ssh root@your-server
   ```

3. **Set up challenge DNS (`ns1`):**

   ```bash
   hogman-host challenge-dns-setup 203.0.113.10              # public IPv4
   hogman-host challenge-dns-setup 203.0.113.10 gcp-eab.json # optional Google fallback CA key
   hogman-host fallback-contact ops@example.com              # required with the Google key
   hogman-host challenge-dns cred list
   ```

   Runs `hogman-challenge-dns` as a locked-down systemd service (dedicated user, read-only root,
   only UDP/TCP 53 open, API socket in `/run/hogman-acme`), answering only for the delegated
   pens zone and `_acme-challenge.<gate-domain>`. Default per-pen caps are 5/hour and 20/7 days on
   Free/Personal pens, 40/hour and 120/7 days on Work pens (D-38), and 80/hour soft / 120/hour hard
   globally (reserving 40/hour for quiet/new pens). When `hogman-host signup-notify` is configured,
   `challenge-dns` also receives `CDNS_NTFY_URL` via a `0600` systemd drop-in and pushes an ntfy
   warning once total 7-day certificate usage across all pens reaches 80% of Let's Encrypt's
   300/7-day allowance (`240/300`, at most once per 24 hours). Test delegation with `dig @<ip> pens.hogman.network SOA`
   (and `+tcp`). Google refuses ACME accounts without a contact, so with its key set the
   server hands out fallback account keys only once `fallback-contact` names an operator address;
   pens put that address on their Google accounts only. Let's Encrypt accounts stay without one,
   and no member's address is ever used.

4. **Configure the wildcard front-door cert and pens zone:**

   ```bash
   hogman-host gate-cert-setup gate.hogman.network   # wildcard *.gate.hogman.network
   hogman-host pens-zone pens.hogman.network
   ```

   `hogman-gate-cert` runs as user `65532` with `ProtectSystem=strict` and `LoadCredential`,
   obtaining and renewing `*.gate.hogman.network` via `challenge-dns` once delegated, and reloads
   the front door automatically on renewal.

5. **Set up encrypted backups and sign-ups:** see [Backups](#backups) and [Hosting pens](#hosting-pens-for-other-people).

## Raising and operating a pen

```bash
hogman-host add mypen
hogman-host pen mypen member add you --role owner
hogman-host pen mypen device key you personal   # open on the laptop (first device only)
hogman-host pen mypen invite create --note "alice"
```

Each `add <pen>` gives the pen `<pen>.<GATE_DOMAIN>` for control traffic, `<pen>.<PENS_ZONE>` for
in-mesh names (`home.<pen>.<PENS_ZONE>` and shares), a scoped per-pen `challenge-dns` API
credential, and its own UDP relay port. Used public pen names are recorded permanently (`cdns name used`)
and are never handed out again (D-21).

**Pre-switchover pens:** Pens created on private `.hogman` zones before public certificates became
mandatory (D-22) cannot be upgraded in place and must be recreated with a new pen name. Existing
members who join or update a public pen have legacy Hogman root certificates cleaned automatically.

## How a shared server works

| Shared by all pens | Each pen's own (`pen-<name>-core` bridge) |
|---|---|
| Host, ports 80/443, `challenge-dns`, `*.<GATE_DOMAIN>` wildcard, shared Caddy front door (`/join`, `/join/dl`, strict path allowlist) | 2 unprivileged containers (`read_only`, `cap_drop: ALL`): `headscale` and `registrar` (embedded `tsnet` core node, authoritative DNS `:53`, `https://home.<zone>:443` portal + API with direct WireGuard `WhoIs` identity, `home.<zone>` ACME, ledger & ACLs), keys, SQLite DBs, relay UDP port |

Each pen lives in `/opt/hogman/pens/<name>` and shares no container network with other pens.
Every pen container carries memory (`mem_limit`), PID (`pids_limit`), and CPU (`cpus: 0.5` on
`headscale`, `0.25` on `registrar`, both with `cpu_shares: 256`) limits
so a single busy or spinning pen cannot starve other pens; host-level services (`hogman-front`,
`challenge-dns`, `hogman-signup`, and `sshd`) stay uncapped at default higher CPU weight (`1024`).
Each pen's registrar also enforces configurable per-pen guardrails via `/opt/hogman/pens/<name>/.env`:
`MAX_MEMBERS` (default `500`, counting active and suspended members; permanently retired handles do
not count) and `MAX_DEVICES` (default `500`, counting live devices plus open unused device keys).
Non-admin members may hold at most `3` open unused device keys at a time (`10` for admins and
owners). To prevent owner lockout (D-16), active owners requesting a `personal` device receive `+2`
headroom above `MAX_DEVICES` (and a per-owner floor of `< 2` personal slots even on grandfathered
over-cap pens), CLI `member add` / `device key` commands bypass caps (`bypass_cap`), existing pens
over cap are grandfathered cleanly, and public `/hogman/v1/redeem` returns an identical generic
`409` after invite validation without leaking counts.
`deploy/test-host.sh` exercises two pens on one host, combined multi-pen PAC routing, backup/restore,
legacy 4-container upgrade/rollback and mixed-fleet routing, name burning, and public sign-ups
against `challenge-dns` and Pebble.

## Updating

```bash
curl -fsSL https://github.com/celtiberi/hogman/releases/latest/download/install.sh | sudo bash   # new code; pens untouched; refreshes signup, challenge DNS and gate-cert
hogman-host upgrade bobo                                                                        # restart a pen on the new version
```

`install.sh` resolves `latest` once, then downloads `SHA256SUMS` and every archive from that pinned
release tag (`releases/download/v<ver>/...`) so a concurrent release cannot mix versions. Set
`HOGMAN_VERSION=<ver>` to install a specific release tag directly. For the 4-container to 2-container
migration (embedded `tsnet` registrar), upgrade one pen first, verify that an already-joined device
still resolves `home.<zone>` and loads the portal with no re-join, and only then upgrade the remaining
pens. `install.sh` refreshes the
`challenge-dns` binary via `hogman-host refresh-services` and pre-pulls any missing pinned base and
runtime container images via `hogman-host pull-images` (so the offline sign-up broker never needs
container registry access when raising a pen after a base-image bump; a failed `docker pull` aborts
`install.sh` early rather than leaving the broker broken); `hogman-host signup-setup`
runs `pull-images` as well. If upgrading manually (or without prebuilt binaries), re-run
`hogman-host challenge-dns-setup <public-ip>` (which keeps the existing GCP key) so new
`challenge-dns` features such as per-plan certificate caps take effect. Both `challenge-dns-setup`
and `refresh-services` automatically restart `hogman-signup-broker-1` so the broker picks up the
updated `/usr/local/bin/challenge-dns` binary and `/run/challenge-dns` mount (and
`hogman-challenge-dns.service` sets `RuntimeDirectoryPreserve=yes` so `/run/challenge-dns` keeps its
inode across systemd restarts); if you ever replace `/usr/local/bin/challenge-dns` or recreate
`/run/challenge-dns` by hand, run `docker restart hogman-signup-broker-1` afterward.

If upgrading from a pre-switchover server before `gate-cert-setup` and `pens-zone` are configured,
`install.sh` skips the `signup-setup` refresh with a reminder rather than failing. Once configured,
no-argument `hogman-host signup-setup` defaults the front-door domain to `GATE_DOMAIN`. Members'
devices reconnect automatically after a pen restarts (~20 s).

## Backups

Nightly at 03:30 UTC the server takes SQLite online backups of each pen's `headscale` and
`registrar` databases, pen runtime data (including `registrar/tsnet`, `registrar/acme`, and `home-tls`, omitting
reconstructible `join-dl/` and socket dirs), and `challenge-dns` state (credential hashes and
used pen names), encrypted with `age` to a key the server cannot decrypt:

1. On a separate machine (never store the private key on the server):

   ```bash
   age-keygen -o backup-key.txt      # prints age1...; store private key in password manager
   ```

2. On the server:

   ```bash
   hogman-host backup-setup age1...
   ```

3. Turn on the off-site copy on Backblaze B2 (D-48). The bucket and keys are code
   (`deploy/backup-b2/`, run by the `backup-b2` workflow from the locked `infra` environment):

   ```bash
   # once, on the server: its own key, which only decrypts the B2 key meant for it
   age-keygen -o /etc/hogman/b2-host.key && chmod 600 /etc/hogman/b2-host.key
   age-keygen -y /etc/hogman/b2-host.key
   ```

   In the repository's locked `infra` environment, set two **variables** (public keys, not
   secrets): `B2_SERVER_RECIPIENT` = the server's `age1...` key printed above, and
   `B2_MAINTAINER_RECIPIENT` = your backup key's `age1...` public key. They live there, not in
   the repo, so a pull request can't redirect new keys to someone else.

   Run the `backup-b2` workflow with **new_keys** and approve it. Its 1-day artifact holds
   `server-b2.env.age` (encrypted to the server) and `maintainer-restore-b2.env.age` (encrypted to
   your backup key; keep it with that key). Copy the first one to the server, then:

   ```bash
   hogman-host backup-b2-install server-b2.env.age   # tests with a small upload
   ```

   From then on each nightly backup is also uploaded. The server's key can only **add** files:
   it can't list, read or delete them. Object Lock keeps every copy for 27 days, then a lifecycle
   rule deletes it, within 30 days of upload even with B2's once-a-day sweep (D-37). **Restoring from B2:**
   `deploy/backup-b2/restore-check.sh <backup-key-file> [pen]` decrypts your restore key, downloads the
   newest backup of a pen (SHA-1 checked), decrypts and unpacks it into a private temp folder, and
   prints what's inside. Use `b2.py list` / `b2.py download <host>/<file> --env <read.env>` to fetch a
   specific one, then restore as below.

4. (Until the B2 copy is verified by a test restore) pull encrypted archives to a second
   machine using a restricted SSH key:

   ```bash
   ssh-keygen -t ed25519 -N "" -f ~/.ssh/hogman_backup
   hogman-host backup-allow "$(cat hogman_backup.pub)"
   deploy/backup-pull.sh your-server
   ```

`hogman-host backup` runs an immediate backup. **Restoring:** decrypt the pen tarball with
`age -d -i backup-key.txt`, place `.env` and `data/` in `/opt/hogman/pens/<name>/`, ensure
`challenge-dns` state/credential is restored or re-issued as needed, and run `hogman-host upgrade <name>`.

**Deleted pen retention (D-37):** when a pen is deleted (`hogman-host purge`), its final encrypted
backup and any prior nightly backups are kept for **30 days** (recorded in `.retired`) so mistaken
deletions can be recovered. After 30 days, the daily lifecycle sweep (`hogman-host lifecycle` /
`hogman-host backup-prune`) removes all backups for that pen on the host; legacy backups of pens
removed before D-37 are aged from their filename timestamp. On the off-host backup machine,
`deploy/backup-pull.sh` ages out archives 30 days after they were pulled (`find ... -mtime +30`)
and never deletes local copies on the host's say-so, so a broken or compromised host cannot wipe
off-host archives of live pens. After 30 days, nothing of a deleted pen remains except its retired
name (D-21).

## Knowing when it breaks

Run `deploy/hogman-watch.sh` every 5 minutes on another machine. It checks `/health`,
`/hogman/v1/network`, TLS certificate expiry (on a gate host, the `*.gate` wildcard; it alerts with a
quarter of the certificate's life left, at most 30 days, while renewal starts at a third), the
challenge DNS for the pens zone on pens with public certificates (every name server answers for it
with authority; needs `dig`), backup freshness (36 hours), and optional `WATCH_URLS`, pushing alerts
via [ntfy](https://ntfy.sh):

```bash
echo hogman-$(openssl rand -hex 12)
NTFY_TOPIC=<topic> deploy/hogman-watch.sh --test
NTFY_TOPIC=<topic> WATCH_URLS="https://get.hogman.network/api/status" \
  deploy/hogman-watch.sh bobo.gate.example.com ~/hogman-backups
```

## Hosting pens for other people

`hogman-signup` serves the invite-code sign-up page and waiting list:

```bash
hogman-host backup-setup age1...
hogman-host signup-setup gate.hogman.network get.hogman.network 8
hogman-host signup-code "for alice"                  # standard Personal code: appends -xxxx random ending
hogman-host signup-code --vanity "for alice"         # Personal vanity code: allows a bare pen name
hogman-host signup-code --vanity --work "for acme"   # Work vanity code (PLAN=work, THEME=work, higher cert caps)
hogman-host signup-cloudflare on                     # trust CF-Connecting-IP + block direct-to-origin bypasses
hogman-host signup-turnstile <site-key> < ts-secret  # require Cloudflare Turnstile on signup/waitlist
hogman-host signup-work-host get.work.example.com    # optional Work sign-up host (THEME=work default)
hogman-host theme <pen> work                         # toggle an existing pen's UI theme (work|default)
hogman-host plan <pen> work                          # switch an existing pen's cert-cap plan live (personal|work)
```

**Cloudflare Proxy rollout order:** deploy this release first, apply the DNS change (`CF_PROXY_ON`),
wait for the old record's TTL (~5 minutes) to expire so resolvers switch to Cloudflare, and then run
`hogman-host signup-cloudflare on`. (Running `signup-cloudflare on` before DNS propagates returns
`403` to direct visitors; leaving `signup-cloudflare` off indefinitely collapses all visitors onto
Cloudflare edge IPs for per-IP rate limiting.) In the Cloudflare dashboard, set **SSL/TLS encryption
mode** to **Full (strict)**, and keep **Bot Fight Mode** off (or add a WAF skip rule for
`/api/stripe/webhook`) so Cloudflare does not block Stripe's webhook deliveries.

When `signup-work-host` is configured, the front door serves the same `signup-web` container on both
hosts (with the same Cloudflare Proxy CIDR lock when `signup-cloudflare on` is active), Turnstile
accepts tokens minted on either hostname, Stripe Checkout returns buyers to whichever configured
signup host they started from, and pens raised on the Work host default to `THEME=work` (exposed as
`"theme": "work"` on `/hogman/v1/network` and `/api/me` for the join page and portal). **Rollout
order for `signup-work-host`:** deploy this release first, apply the DNS PR that points the proxied
Work sign-up hostname at this server, and only then run `hogman-host signup-work-host <host>` (so
Caddy can obtain its origin certificate immediately).

The `web` container runs read-only and unprivileged (`65534:65534`), speaking over an internal
network to `broker` (which runs `hogman-host provision` and has outbound internet only if
`hogman-host signup-notify` or `hogman-host signup-mail` is configured). Failed provisions automatically clean up containers and
revoke their challenge-DNS credentials, releasing the pen name if no ACME challenge was ever written
(and keeping D-21 permanent retirement once any certificate challenge occurred). Raised pens are
logged in `/opt/hogman/signup/raised.log`.

**The waiting list:**

```bash
hogman-host waitlist
hogman-host waitlist invite 3
hogman-host waitlist remove 3
hogman-host signup-mail "Hogman <pens@example.com>" < resend-api-key
hogman-host signup-mail test you@example.com
hogman-host signup-setup
hogman-host signup-notify https://ntfy.sh/<topic>
```

Link directly to the waitlist with `https://<signup-host>/#wait`. When `hogman-host signup-mail` is
configured (re-run `hogman-host signup-setup` afterwards so the broker picks up the mail settings),
joining the waiting list sends a one-time confirmation email via Resend (capped at 1 per address per
24 hours in memory and 30 per hour globally) and `hogman-host waitlist invite <id>` emails the
sign-up code.

**Selling pens (Stripe, D-28):** a paid checkout buys one sign-up code, which then works like a
`--vanity` code: the buyer picks a bare pen name, with no random ending. Stripe's hosted Checkout takes the card, so card details never reach this server.

1. In Stripe (test mode first): make a Product with a recurring Price, a **restricted key** with
   **Checkout Sessions: Write** and **Subscriptions: Write** (so manual renewals cancel replaced
   subscriptions automatically), and a webhook endpoint at
   `https://<signup-host>/api/stripe/webhook` for `checkout.session.completed`,
   `checkout.session.async_payment_succeeded`, `invoice.paid`, and `customer.subscription.deleted`.
2. On the server, with the key and the webhook signing secret one per line on standard input:

```bash
hogman-host signup-stripe price_123 [--work price_456] [tax] < stripe-keys
hogman-host signup-stripe work-price price_456         # update Work price without re-piping keys (or: off)
hogman-host signup-stripe floor 5000 12000 usd         # update broker webhook price/currency floor
hogman-host signup-stripe off
```

The broker enforces a minimum payment floor on Stripe webhooks (defaults: `5000` cents Personal,
`12000` cents Work, `usd`). Whenever you lower a Stripe Price below those defaults or switch
currencies, run `hogman-host signup-stripe floor <personal-cents> <work-cents> [currency]` so
legitimate payments are not rejected.

When `--work` (or `work-price`) is set, checkouts started on the Work sign-up host use the Work
Stripe Price over the same single webhook, and both Stripe metadata and `/opt/hogman/signup/payments`
record the tier (`personal` or `work`). When no Work price is configured, the Work host reports
`for_sale: false` and refuses `/api/checkout` (`404`) so it never sells a Work plan at the Personal
price.

The page shows **Buy a pen** while the server has room. After paying, Stripe sends the buyer to
`/paid.html`, which shows their code once Stripe's event arrives. The broker checks every event's
signature itself (the page only passes it on), so a compromised page can't fake a payment, and a
session gets one code however often Stripe retries. Paid sessions are listed in
`/opt/hogman/signup/payments` (session, code, Stripe customer and subscription IDs; no names,
emails or card details). A cancelled subscription is logged in `raised.log` and pushed, and the
operator acts on it by hand for now.

## Everyday

```bash
hogman-host list
hogman-host pen <name> <hogman args>
hogman-host upgrade <name>
hogman-host sleep <name>
hogman-host wake [--renew-only] <name>
hogman-host remove <name>
```

**Sleeping pens and renew-only wakes (I-7):** when a paid pen finishes its 30-day grace period, the
daily lifecycle sweep puts it to sleep (`hogman-host sleep <pen>`), freeing its host capacity slot
while keeping its state for one year. Its front door serves a static sleeping notice linking to
`https://<signup-host>/#wake=<pen>`, where an owner or admin can trigger a 10-minute `renew_only`
wake (measured from when `home.<zone>`'s TLS certificate is ready, hard-capped at 20 minutes from
the press). While `renew_only`, `hogman-host list` shows `renew_only`, `.sleeping` stays on disk,
the pen's Headscale policy and registrar HTTP handlers allow only active owners/admins on personal
devices to reach `GET /api/me` and `POST /api/billing/renew-token`, and `purge --due` refuses it.
Wakes are capped at 3/day and 10/30d per pen, 2 concurrent wakes host-wide, and use the
`RENEW_WAKE_RESERVE` (default `2`) reserve slots without blocking or evicting paying pens; hitting
caps alerts the operator via `ntfy`. Payment restores normal policy live via `hogman-host wake <pen>`
(`sync`) without restarting containers; otherwise the broker returns the pen to sleep at its
persisted deadline while preserving the original `sleep_since` / `delete_after` timestamps.

## Fleet Ops dashboard (v1, read-only)

Run a private, strictly read-only host dashboard inside your own internal ops pen (`deploy/ops/`),
using a host-pushed snapshot file and zero host RPC listeners:

1. Enable the 60-second host snapshot collector (creates `/run/hogman-ops` via `tmpfiles.d` with
   numeric GID `65532` and writes `/run/hogman-ops/snapshot.json` atomically):

   ```bash
   sudo hogman-host ops-setup
   ```

2. Build `hogman-sidecar` (from `core/join/Dockerfile.sidecar`) and configure `/opt/hogman/ops-src/.env`:

   ```bash
   OPS_HANDLES=alice,bob
   OPS_SHARE_NAME=fleet
   ```

3. Enroll the sidecar once on your ops pen with a one-time share link and start the stack:

   ```bash
   cd /opt/hogman/ops-src
   docker compose build
   docker compose run --rm -i hogman-sidecar \
     share fleet unix:///run/hogman-in/app.sock \
     --state-dir=/var/lib/hogman --enroll-only --link-stdin
   docker compose up -d
   ```

**Security boundaries:**
- `ops-web` runs as UID/GID `65532:65532` inside `network_mode: service:hogman-bridge` (`network_mode: none`), with no Docker socket, no SSH keys, and no signup broker token.
- `/run/hogman-ops` is mounted read-only as a **directory** (not the single file) so atomic snapshot renames are picked up on every request.
- `hogman-sidecar` runs with `--identity-headers`; `ops-web` fails closed (`403`) unless `X-Hogman-Handle` is present, non-tagged (personal devices only), and listed in `OPS_HANDLES`.
- Waitlist output contains only counts (`waiting`, `invited`) and the age of the oldest waiting entry — never emails or notes. Customer pen data directories (`pens/<name>/data/`) are never read.
- Per-pen Headscale `SetPolicy` push latency (`setpolicy_samples`, `setpolicy_last_ms`, and `setpolicy_p95_ms` over the latest 100 pushes) is collected by `ops-snapshot.sh` from running registrar container logs (`policy: applied` / `policy: failed` lines only, bounded integer milliseconds, keeping `PrivateNetwork=yes` and zero access to `pens/<name>/data/`). Whenever any live pen's `p95` exceeds `5 s`, the host sign-up broker (which mounts `/run/hogman-ops` read-only) sends an aggregated, rate-limited `ntfy` alert (`ops` limiter, 6-hour per-pen cooldown).
- All mutations (`waitlist invite/remove`, `sleep`, `wake`, `purge`, `plan`, `theme`) stay CLI-only via Tailscale SSH + `hogman-host`.

## Publishing releases

Releases are published by GitHub, not from anyone's machine: `.github/workflows/release.yml`.

1. Start it: **Actions → release → Run workflow** (leave the commit empty to release `main` as it is when you start the run), or
   `gh workflow run release.yml -f commit=<full sha>`.
2. Approve it: the job waits in the `release` environment until a required reviewer approves. That
   approval is the decision to release.

**One-time setup (repository owner):** Settings → Environments → New environment `release`; add
yourself under *Required reviewers*; under *Deployment branches and tags* choose *Selected branches*
and add `main`. Without required reviewers, anyone who can start a workflow could publish.

The workflow refuses a commit that is not on `main`, or that lacks a successful `build`, `e2e` or
`vuln` run on `main`. It then runs `deploy/release.sh` in two steps (`NO_DEPLOY=1 OUT_DIR=…` to
package, `PUBLISH_FROM=…` to publish exactly those files) and, in between, gives every packaged file
GitHub build provenance. Check any download with
`gh attestation verify <file> --repo celtiberi/hogman`.

`deploy/release.sh [git-ref]` can still be run by hand as a fallback. Either way it releases
directly from a green commit on `main` and builds the GitHub Release notes from `changelog.d/`
fragments (plus any remaining `## [Unreleased]` entries) at that commit:

1. Verifies a successful non-PR `.github/workflows/build.yml` run for the exact commit and checks
   GitHub build provenance (`gh attestation verify`) on every compiled binary before packaging.
2. Packages `hogman-<ver>.tar.gz`, `hogman-bin-<ver>.tar.gz`, `install.sh` (from the committed ref),
   `SHA256SUMS`, and `latest`.
3. Uploads every asset into a **draft** release (`v<ver>`), verifies the asset list, then
   publishes and marks it `latest` atomically (`gh release edit --draft=false --latest`).

After publishing `v<ver>`, fold the released `changelog.d/` fragments into `CHANGELOG.md` under
that exact version in a follow-up housekeeping PR:

```bash
deploy/changelog-fold.sh <ver>
```

Enable **Immutable releases** in the repository's GitHub settings (**Settings → General → Releases**)
so published release tags and their assets cannot be modified or replaced after publication.

## Testing locally

```bash
deploy/test-host.sh        # requires Linux, Docker, and jq
```
