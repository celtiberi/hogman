# Public certificates (D-18, D-19): design

Status: **revision 2**, folding in @hogman's red-team (PR #61). Waiting for sign-off before any code.

Decisions:
- **D-18:** publicly trusted certificates only, with no private root.
- **D-19:** the Public Suffix List is a goal, not a launch gate.

This design also covers the audit items it settles: H1, and the PKI items rated Medium. See `docs/security/audit-2026-11.md`.

## Goal

Members never install a certificate. Every HTTPS name in a pen gets a certificate that browsers, phones and command-line tools already trust. Each share keeps its own private key, and a pen's server never sees its members' traffic in the clear.

## Standards

| Area | Standard |
|---|---|
| Issuing certificates | ACME, RFC 8555. Challenge: **dns-01** only (§8.4). |
| Who may issue | CAA, RFC 8659, with the `validationmethods` and `accounturi` parameters of RFC 8657. |
| Renewal | ACME Renewal Information (ARI), RFC 9773. |
| CA accounts with keys | External Account Binding (EAB), RFC 8555 §7.3.4. |
| Public logging | Certificate Transparency, RFC 6962. Every issued name becomes public, by design. |
| Browser site boundaries | The Public Suffix List (D-19). |

We follow two existing models rather than invent our own:
- **Tailscale's HTTPS for `*.ts.net`.** A node runs ACME itself, and the control server writes the DNS-01 TXT record for that node's own name.
- **acme-dns.** A dedicated authoritative DNS server, used only for challenge records, whose credentials are each limited to one scope.

## Names

| What | Hosted pens | Self-hosted pens |
|---|---|---|
| Pen zone, mesh only | `<penid>.pens.hogman.network` | A name under the operator's own domain, such as `pen.example.com` |
| Sites and shares | `<site>.<penid>.pens.hogman.network` (up to 4 labels, as today) | `<site>.pen.example.com` |
| Home page | `home.<penid>.pens.hogman.network` | `home.pen.example.com` |
| Public front door (Headscale control, join page, invite redemption) | `<pen>.gate.hogman.network` | The operator's `PUBLIC_HOST` |

- A **pen ID** is 12 random characters from `[a-z2-7]`, about 60 bits. It hides *whose* pen a name belongs to. The names themselves still appear in public CT logs, and we say so.
- **Zones are checked before anything trusts them,** so a hostile pen can't make your browser send other sites through it:
  - hosted zones must match exactly `^[a-z2-7]{12}\.pens\.hogman\.network$`;
  - a self-hosted zone must sit under the invite host's registrable domain (checked against the PSL), and must not be a public suffix itself;
  - `hogman-join` connects to `https://home.<zone>` and checks it with the system's trusted roots **before** it writes the zone into its config or the PAC.
- **Front doors move off `pens.` to `gate.`** A pen's human name and a random pen ID must never share a namespace: someone could otherwise choose a pen name that equals another pen's ID. It also keeps the front door's wildcard certificate (below) out of every pen zone. The PSL entry will be `pens.hogman.network`, which covers only the mesh sites, the ones that run third-party apps.
- **No public A or AAAA records exist for anything under a pen zone.** Browsers never resolve pen names: the PAC sends those hosts to the local agent, which resolves them through the pen's own DNS over the mesh, as today. Public DNS only ever answers the challenge records, CAA, NS and SOA.

## DNS

- **NS delegation, as narrow as each name allows.**
  - `pens.hogman.network`: the whole subzone is delegated to the challenge DNS server. Nothing under it needs a public address.
  - `gate.hogman.network` stays in Cloudflare, with `*.gate` A/AAAA and CAA, because front doors need public addresses. Only `_acme-challenge.gate.hogman.network` is delegated, for the front door's wildcard.
  - The NS target is `ns1.hogman.network`, out of bailiwick. The server binds `:53` on the host's public IPs explicitly, not on `127.0.0.53`, where systemd-resolved sits.
  - Nothing the server can be made to do changes `hogman.network` itself (`install.sh`, releases, the site). That's @hogman's condition that won't be given up.
- **The challenge DNS server is small and authoritative:** our own server on `miekg/dns`, the library the registrar already uses. It serves only:
  - SOA and NS;
  - CAA at `pens.hogman.network`: `0 issue "letsencrypt.org; validationmethods=dns-01"`, `0 issue "pki.goog; validationmethods=dns-01"` and `0 issuewild ";"`;
  - TXT `_acme-challenge.<name>`, written only through its API, and expiring after 10 minutes even if nobody cleans them up.
  - There's no `accounturi` on `pens.`, because every share has its own ACME account, so pinning one account would refuse them all.
  - CAA for the front door's wildcard lives in Cloudflare at `gate.`: `issuewild` for `letsencrypt.org` and `pki.goog`, each with `validationmethods=dns-01` and the host's `accounturi`.
- **Each pen gets its own API credential, scoped to that pen.** It can write TXT records under `_acme-challenge.*.<its penid>.pens.hogman.network`, and nothing else: no other pen, no other record type, nothing under `gate.`.
  - It allows at most 2 live TXT records per name.
  - Its **weekly cap** (10) counts distinct names whose challenge was written this week, not raw TXT writes. A renewal touches its name about once every 60 days, so renewals barely count.
  - The host has one separate credential, which only the front door uses, for the `*.gate.hogman.network` wildcard.
  - The registrar reaches the server's HTTP API over a host-only Docker network, documented in `hogman-host`. The API never faces the internet.
- **Self-hosted pens:** the registrar uses a DNS provider library (libdns) with the operator's DNS API token. The docs recommend the narrowest token the provider allows. They also show the standard trick for making it narrower: delegate `_acme-challenge` with a CNAME to a zone used only for challenges.

## Who gets which certificate

**Shares and other servers in the pen** run ACME themselves, with their own account key and private key.
- They use **certmagic** (Caddy's library), which supports DNS-01 through libdns, ARI, a fallback issuer and cache reuse. It replaces `autocert`, which can't do DNS-01.
- The share's DNS-01 "provider" is a tiny libdns implementation that calls the registrar over the mesh: `POST /api/acme/txt {name, value}` and `DELETE`.
  - The endpoint is for **server devices only**.
  - It applies `serverMayUse`, the same rule as claiming the name, so a share can only ever get a certificate for its own name.
  - It refuses `home`, `ns*`, `nodes` and `_acme-challenge` labels.
- certmagic checks propagation against **public resolvers** (1.1.1.1, 8.8.8.8), not the pen's split DNS, because the pen's DNS doesn't serve challenge records.
- The certmagic cache (account, keys, certificates, ARI state) lives in the share's folder, and survives restarts and `hogman-join update`, so renewals carry ARI's `replaces`.
- Shares hold no DNS credential. For the fallback CA, they hold a single-use EAB pair (see below).

**The home page** (Caddy in the pen) doesn't need a custom Caddy build, and doesn't use `get_certificate`.
- Caddy's `get_certificate http` uses a plain HTTP client: no Unix sockets, no auth, and a request on every handshake. So it was dropped.
- Instead, the registrar gets `home.<zone>` with certmagic and writes the certificate and key **atomically** to `data/home-tls`. That folder is mounted read-write into the registrar and read-only into the portal, and nowhere else, the same isolation as audit H2.
- On renewal, the registrar reloads Caddy through Caddy's admin API, which listens on a **Unix socket** in a folder shared only with the registrar. The admin API is off on TCP.

**The front door** (the host's shared Caddy) gets one `*.gate.hogman.network` wildcard by DNS-01, with the host's credential. That's one certificate for every front door, and it keeps human pen names out of CT.
- A small host-side issuer (`hogman-host`, run on a systemd timer) writes the files.
- `docker exec … caddy reload` picks them up.
- A self-hosted front door keeps today's normal Let's Encrypt certificate for its `PUBLIC_HOST`.

## Certificate authorities, quota and failover

- **Primary: Let's Encrypt.** Before launch, file the rate-limit increase for `hogman.network`, the registered domain, and check that it's actually live before relying on it.
- **Fallback: Google Trust Services** (`pki.goog`). It supports the RFC 8657 CAA parameters and ARI, and requires EAB.
  - GTS issues each EAB key as a **single-use pair that expires after 7 days** (`gcloud publicca external-account-keys create`). certmagic takes the pair directly, so a remotely signed JWS doesn't fit.
  - So the challenge DNS service holds a Google service account limited to `roles/publicca.externalAccountKeyCreator`. When a share sets up its fallback account, the registrar asks the service for **one fresh pair** and passes it to that share alone. The pair binds that share's account once and is useless after that.
  - No long-lived GTS secret ever reaches a pen or a share.
  - ZeroSSL was considered and set aside: it issues through Sectigo, whose CAA handling of `validationmethods` is unreliable, and it doesn't document ARI.
- **When to fail over.** Switch to the fallback only on `rateLimited`, HTTP 429, or a CA 5xx or outage. Never on DNS validation errors (`unauthorized`, `dns`): those mean our DNS is wrong, and retrying at a second CA would burn its failed-validation limit too.
- **Renewal:** 90-day certificates. Renew when ARI says to, or at about 30 days left. Renewals don't count against the new-certificate limit.
- **Spend certificates only on genuinely new names:**
  - a persistent cache per share (kept across restarts and `update`);
  - a duplicate guard (Let's Encrypt allows 5 identical certificates a week);
  - backoff after failed validations (5 per hour per name);
  - the per-pen weekly cap.

## What goes away

- **step-ca:** `core/templates/{ca.json,root_ca.tpl,intermediate_ca.tpl}`, the CA generation in `core/hogman`, port 9000 in the ACL, `ca.<zone>` in DNS and the reserved list, and the legacy `ca.<zone>` proxy on the portal.
- **On members' computers:**
  - `trust_{darwin,linux,windows}.go` and `CheckRoot`;
  - the administrator and sudo prompt at join;
  - `--no-trust`;
  - the root in the portal's "Root certificate" section, and `/root_ca.crt`;
  - the "two pens with one zone" refusal, since zones are now globally unique names.
- **`fp=` in invite and device links:**
  - Links become `https://<front>/join#t=…` and `#k=…`.
  - The join tool verifies the front door with normal public TLS.
  - Shares and the agent verify the home page and other sites with the system roots.
- **Root escrow and `pki/offline/`** in `hogman-host`, and the H9 backup exclusion that went with it.
- **Audit items:** H1 (EKU), and the PKI Mediums (no revocation for the intermediate, the root generated online, the root password stored with the root key, one age key covering every root, the step-ca policy).

## What changes

- **Zone validation.**
  - The join tool's `zoneRE` (`^…\.hogman$`) becomes: a hostname under a domain the pen's own network info vouches for, with no TLD restrictions.
  - The zone must be a subdomain of the network's published base, never a public suffix.
  - The agent's `inZone` and the PAC are unchanged in shape.
- **The join tool and agent** drop the custom root pool: system roots everywhere. `--control-ca` stays for test networks only.
- **The registrar:**
  - new `POST /api/acme/txt` and `DELETE /api/acme/txt` endpoints (mesh only, server or own device);
  - a certmagic issuer for `home`;
  - writes `home`'s certificate to the isolated `data/home-tls` folder, and reloads Caddy over its admin socket;
  - a client for the challenge DNS service, or libdns for self-hosters;
  - reserved names: `ca` is removed, `_acme-challenge` is added as invalid.
- **Sign-up and `hogman-host`:**
  - provisioning makes a pen ID and a per-pen credential at the challenge DNS service;
  - the front door moves to `gate.`;
  - the provision regex no longer expects `fp=`.
- **CSRF:** unchanged. `requireSameOriginAndJSON` already rejects same-site requests, which remains correct when every pen sits under `pens.hogman.network`.

## D-19 guardrails, built in the same work

- **The front door allow-lists the Tailscale control and relay routes, and returns 404 for everything else from Headscale**, such as its HTML registration pages.
- **`Origin-Agent-Cluster: ?1`** on the home page, the front door, the sign-up page and the site. **`nosniff`** on `/join/dl/*`.
- **The FAQ and the sign-up page disclose the multi-pen risk:**
  - apps in one pen can plant cookies for, or send same-site requests to, apps in another pen you're also in;
  - a malicious pen can flood your browser with cookies until our pages stop loading for you (HTTP 431);
  - so use a separate browser profile for a pen you don't trust.
- **Bring your own domain per pen,** for full isolation: a paid option, using the self-hosted path.
- **HSTS** never uses `includeSubDomains` or preload on `hogman.network`, `pens.` or `gate.`.

## Testing

- **CI stays offline.** It uses **Pebble** (Let's Encrypt's test CA) with its `pebble-challtestsrv` as the challenge DNS, and a fake challenge DNS service.
- The e2e suites assert:
  - shares get certificates through the registrar's TXT endpoint, and **a share can't get one for another share's name**;
  - home gets its certificate through the shared folder and the reload;
  - nothing on members' machines touches a trust store;
  - the PAC and the proxy work with the new zone;
  - a share restart reuses its certificate (no new order);
  - failover to a second Pebble happens on 429 but not on a DNS error;
  - the per-pen cap is enforced.
- **Unit tests** cover:
  - the challenge DNS service's scope checks (another pen, `gate.`, a non-TXT record, an apex write: all refused);
  - EAB binding;
  - CAA output.

## Migration

The two live pens are test pens: recreate them. Then `hogman-join update`:
- removes any old Hogman root it finds on the computer (from the trust store, by fingerprint, matched against the saved config);
- moves the agent's folder to the new zone name when the pen is re-joined.

The docs say, in one sentence, that pens created before this change need to be recreated.

## Threats

| Threat | Covered by |
|---|---|
| A compromised share gets a certificate for another share's name | The registrar writes TXT only for names the device may use, and per-share keys mean no shared wildcard |
| A compromised pen issues certificates for another pen or for `hogman.network` | Per-pen credential scope at the challenge DNS service, plus NS delegation (it can't touch `hogman.network`) |
| Someone issues through another CA or method | CAA restricted to our two CAs, with `validationmethods=dns-01` and `accounturi` |
| A leaked EAB key | It never leaves the challenge DNS service, and bindings are per account |
| One pen exhausts the shared quota | The per-pen weekly cap, the LE override, the GTS fallback |
| Site names exposed in CT | Pen IDs hide ownership; site labels are disclosed; bring-your-own-domain for those who mind |
| Cross-pen cookie risk before the PSL | D-19 disclosure; PSL application; bring-your-own-domain |
| The challenge DNS service is down | Existing certificates keep working for up to about 60 days, and ARI starts renewing early. Monitor it with `hogman-watch`. |
| The pen's server reads members' traffic | Not possible: TLS ends at each share, never at the server (wildcard termination at the server was rejected) |

## Red-team resolutions (revision 2)

| Question | Answer |
|---|---|
| `gate.` for front doors | Kept. Only `_acme-challenge.gate` is delegated; addresses and CAA stay in Cloudflare. |
| acme-dns or our own | Our own small server on `miekg/dns`. |
| certmagic | Yes, with public resolvers for propagation checks and its cache kept across updates. |
| `get_certificate` | Dropped. Atomic files in a mount-isolated folder, and a reload over Caddy's admin Unix socket. |
| Weekly cap | 10, counting distinct new names, not TXT writes. |
| Pen ID length | 12 characters (60 bits). |

Also fixed:
- `accounturi` is dropped on `pens.`;
- the GTS fallback uses single-use EAB pairs minted per share;
- zones are verified, and pinned to a pattern, before they reach the PAC;
- the TXT endpoint is for server devices only, limited to 2 live records per name;
- the registrar's path to the challenge API is documented.

## Original open questions

1. `gate.hogman.network` for front doors: right separation, or does it create new trouble (one more PSL question)?
2. Should the challenge DNS service be acme-dns itself (joohoi/acme-dns, extended with pen scopes and the cap), or our own small server on `miekg/dns`, which the registrar already uses?
3. certmagic in shares: the dependency weight is acceptable, it already brings libdns and ARI, and keeps `CGO_ENABLED=0`. Better alternatives?
4. Should `get_certificate http` for the home page and front door replace a custom Caddy build?
5. Is a per-pen cap of 10 new certificates a week right for the trial?
6. Keep 8-character pen IDs, or longer?

## What the operator needs to set up (before code reaches production)

1. **Cloudflare:**
   - NS records delegating `pens.hogman.network`, and `_acme-challenge.gate.hogman.network`, to `ns1.hogman.network`, plus its A/AAAA;
   - `*.gate` A/AAAA;
   - CAA at `gate.`.

   The exact records come once the challenge DNS service runs.
2. **Let's Encrypt:** the rate-limit increase form for `hogman.network`. It takes weeks, so file it early. I'll draft the answers.
3. **Google Trust Services:** a Google Cloud project with the Public CA API enabled, and a service account limited to `roles/publicca.externalAccountKeyCreator`. Its key goes only into the challenge DNS service's config on the server.
4. **Later:** the PSL pull request for `pens.hogman.network`, once we're eligible.

## Plan, after sign-off

1. The challenge DNS service, with its scope tests.
2. The registrar's TXT endpoint and `home` issuer, plus Pebble in CI.
3. certmagic in shares.
4. Front-door wildcard, `gate.` names, and the D-19 guardrails.
5. Remove step-ca and root trust.
6. Docs, then recreate the test pens.

Each step is its own PR, reviewed by the other AI.
