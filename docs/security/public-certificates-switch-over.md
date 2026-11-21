# Switching hogman-1 to public certificates (D-18, step 4c)

Status: **draft for @hogman's review.** Nothing in here has been run yet.

This is the order of work that takes the live server from today's private certificates (step-ca, `fp=` links, a root on every member's computer) to public certificates only. It also lists the code that still has to be written before the switch can happen.

Who does what:
- **The operator** approves each DNS apply run in GitHub, and makes any decision marked **Decision**.
- **@swinherd** and **@hogman** write and review the code, run the server commands, and check every step from outside.
- **@piggy** checks what's live after each phase. She no longer has Cloudflare access; DNS changes only through `infra/dns/dnsconfig.js`.

## Where things stand (2026-11-21)

- Built and merged: challenge DNS server (step 1), registrar TXT endpoint and `home` certificate (step 2), share certificates with certmagic (step 3, PR #71), front-door wildcard and D-19 guardrails (steps 4a and 4b).
- Running on hogman-1: `hogman-challenge-dns`. It already answers for `pens.hogman.network` and `_acme-challenge.gate.hogman.network` when asked directly, but nothing points at it yet.
- Not on the server yet: the GTS key (the fallback CA), and `gate-cert-setup`.
- Live pens, both test pens:
  - `farm`, front door `hs.hogman.network`;
  - `qa-piggy4`, front door `qa-piggy4.pens.hogman.network`.
- Sign-ups: `get.hogman.network`, giving pens front doors at `<name>.pens.hogman.network` (`PENS_DOMAIN`).

**The collision:** today's front doors live under `pens.hogman.network`, the name we're about to hand to the challenge DNS server. Once `pens.` is delegated, the `*.pens` address record stops working, so every front door under it (qa-piggy4's, and every sign-up) must move to `gate.` first. That's why the order below is: gate first, then code, then pens.

## Phase A: the front-door wildcard (nothing visible changes)

Everything here only adds names. No live pen is touched.

1. **DNS PR 1** (`infra/dns/dnsconfig.js`):
   - `_acme-challenge.gate` NS `ns1.hogman.network.`
   - `*.gate` A `159.65.78.95` (not proxied; IPv4 only, like the host)
   - CAA at `gate`: `0 issue ";"` and `0 issuewild "letsencrypt.org; validationmethods=dns-01"`.
   The `accounturi` comes in PR 2, because the account only exists after step 3.

   Check: the PR's preview shows exactly these 4 records being added and nothing else. Merge it, and the operator approves the apply run.

2. **Check from outside:**
   ```
   dig +short @1.1.1.1 _acme-challenge.gate.hogman.network NS     # ns1.hogman.network.
   dig +short @1.1.1.1 test.gate.hogman.network A                 # 159.65.78.95
   dig +short @1.1.1.1 gate.hogman.network CAA
   ```

3. **On hogman-1:** `hogman-host gate-cert-setup gate.hogman.network`. It makes the host's challenge credential, installs the `hogman-gate-cert` units, and gets `*.gate.hogman.network` from Let's Encrypt.

   Check: `/var/lib/hogman-gate/tls/gate.crt` exists and is from Let's Encrypt; `registrar gate-cert health` passes; the name shows up in CT (crt.sh).

4. **DNS PR 2:** add `accounturi=<the host's Let's Encrypt account URL>` to the `issuewild` CAA. The URL is in `/var/lib/hogman-gate/acme`. The GTS line gets added when the host has a GTS account (Phase E).

   Check: a renewal still works with the tighter CAA (force one with the `gate-cert` renew command, or wait for the timer and read the log).

## Phase B: the code that has to land before the switch

Each item is its own PR, reviewed by the other AI. CI has to pass, including a full public-pen run.

1. **Share retry backoff** (from the #71 review): keep a next-attempt time in `<share>/acme`, so restarts don't hammer the CA; drop the `admin@<zone>` default ACME email.

2. **Delete the private path** (D-22). Remove:
   - step-ca and its templates, the CA generation in `core/hogman`, port 9000 in the ACL, `ca.<zone>` in DNS, and the reserved name;
   - `trust_*.go`, `CheckRoot`, `--no-trust`, the sudo prompt at join, and `fp=` in links (the join page and the join tool);
   - root escrow and `pki/offline/` in `hogman-host`, and the H9 backup exclusion;
   - the `CERT_MODE` switch, `compose.public.yaml` (its contents become `compose.yaml`) and `portal.public.Caddyfile`;
   - the "two pens with one zone" refusal.

   `hogman-join update` gains the clean-up from the design: remove any old Hogman root from the trust store (matched by fingerprint against the saved config), and move the agent's folder when the pen is re-joined.

3. **`hogman-host add <pen>`.** The host and zone come from the pen's name:
   - front door `<pen>.<GATE_DOMAIN>`;
   - zone `<pen>.<PENS_ZONE>`, with `PENS_ZONE=pens.hogman.network` as a host setting.

   The "used once, ever" check stays, and fails closed. `--public` goes away. `PENS_DOMAIN` is replaced by `GATE_DOMAIN` for sign-ups, and `signup-setup` asks for the gate domain.

4. **Sign-up provisioning:** the join-link pattern drops `&fp=`, `escrow_root` goes, and the JSON reports the real zone (`<pen>.pens.hogman.network`, not `<pen>.hogman`). The sign-up page's text about where the pen lives changes to match.

5. **Tests:** `deploy/test-host.sh` runs a public pen end to end, against the real challenge DNS server binary and Pebble: add a pen, join a member, share a site, check the certificate. It also checks that a share can't get another share's name, and that a removed pen's name can't be reused.

6. **Docs, same PR as the code they describe:**
   - README, the keeper's guide and how-it-works: no more root, no more `fp=`, the new names, and that pens made before this release must be recreated;
   - the FAQ and the sign-up page: the D-19 multi-pen disclosure (another pen's apps can plant cookies for, or send same-site requests to, yours; use a separate browser profile for a pen you don't trust), and that pen and site names are public in certificate logs (D-21);
   - CHANGELOG.

**Decision (operator): self-hosting.** With the private path deleted, a self-hosted pen needs public certificates under its own domain. That means the registrar has to write challenge records through the operator's DNS provider (libdns, starting with Cloudflare). That isn't built: today the registrar can only talk to our challenge DNS server. Two choices:
- **(a) Build it before the switch** (my recommendation): one more PR, libdns with Cloudflare first, and the self-host guide explains how to make a narrow DNS token.
- **(b) Switch now, and mark self-hosting "coming back soon"** on the site until (a) lands.

## Phase C: the switch (the test pens go down)

Do this in one sitting, and tell Piggy and anyone on the test pens first.

1. **Back up both pens:** `hogman-host backup`, then make sure the backup copied off the server. These are test pens, but the backup is the only way back if Phase C fails.

2. **Remove the old pens:** `hogman-host remove farm`, `hogman-host remove qa-piggy4`.

3. **Install the new release:** run `install.sh` on hogman-1. Then `hogman-host signup-setup gate.hogman.network get.hogman.network 40` to point sign-ups at `gate.` (exact arguments per Phase B item 3).

4. **DNS PR 3:**
   - `pens` NS `ns1.hogman.network.`
   - remove `*.pens` A, and `hs` A (farm's old front door).

   Check: the preview shows exactly these changes, nothing else; the operator approves the apply.

   From outside:
   ```
   dig +short @1.1.1.1 pens.hogman.network NS          # ns1.hogman.network.
   dig +short @1.1.1.1 pens.hogman.network CAA         # served by ns1
   dig @1.1.1.1 nothing.pens.hogman.network A          # NXDOMAIN/NODATA, no address
   ```

5. **Recreate the test pens:** `hogman-host add farm` and `hogman-host add qa-piggy5` (or new names). Make their owners, then join the laptop and the Mac mini.

   Check:
   - nothing on either computer asks for an administrator password, and no root gets installed;
   - `home.farm.pens.hogman.network` shows a Let's Encrypt certificate in the browser;
   - a share gets its own certificate within a minute;
   - `hogman-join update` on a computer that was on the old pens removes the old root.

6. **A real sign-up** on `get.hogman.network`, start to finish, and the new owner joins from the emailed link.

7. **@piggy checks live:** the front doors, the join page, a share, the sign-up page, and the new FAQ text.

**If Phase C fails:** the private path is gone from the new release, so going back means:
- a DNS PR reverting PR 3 (put back `*.pens` A and `hs` A, drop the NS);
- reinstalling the previous release (`install.sh` pinned to the last tag);
- restoring `farm` and `qa-piggy4` from the step 1 backup.

That's a few minutes of DNS plus a restore, and it's acceptable because only test pens exist. Once real people have pens, there's no going back, which is why this happens now.

## Phase D: tidy up

- Remove `NO_PURGE` in `infra/dns/dnscontrol`, after reading the preview for any surprise deletions (the zone import said 14 records, our file has 12: check the apex NS and anything mail-related first).
- Make DNS-only PRs skip the e2e suites (`infra/**` in the changes filter).
- Add `hogman-challenge-dns` and the gate certificate's expiry to `hogman-watch`.

## Phase E: when the outside pieces arrive

- **GTS key:** make it fresh, straight onto the server (`hogman-host challenge-dns-setup <ip> <key>`), never on a laptop. Then add the `pki.goog` `issuewild` line with the host's GTS `accounturi` (a DNS PR).
- **Let's Encrypt rate-limit increase:** check it's live for `hogman.network` before raising the trial's pen limit.
- **Public Suffix List:** file the pull request for `pens.hogman.network` when we're eligible (D-19).
- **Post-launch security audit:** access, who owns what, removals, scripted where we can (D-23).
