# Public Certificates: Architecture and Threat Model

Every HTTPS name in a Hogman pen uses a publicly trusted certificate obtained through ACME `dns-01`. Members never install a private root certificate. Each shared site holds its own ACME account and TLS private key, so the pen server never terminates or inspects members' site traffic.

## Standards

| Area | Standard |
|---|---|
| Issuing certificates | ACME, RFC 8555 (`dns-01` challenge only, §8.4). |
| Who may issue | CAA, RFC 8659, with `validationmethods` and `accounturi` (RFC 8657). |
| Renewal | ACME Renewal Information (ARI), RFC 9773. |
| CA accounts with keys | External Account Binding (EAB), RFC 8555 §7.3.4. |
| Public logging | Certificate Transparency, RFC 6962. Every issued hostname appears in public CT logs. |

This architecture follows two established models:
- **Node-held ACME (`*.ts.net` pattern):** each share runs ACME itself and keeps its own private key, while the pen's registrar mediates DNS-01 TXT writes strictly for names that server is authorized to use.
- **Scoped challenge DNS (`acme-dns` pattern):** a dedicated authoritative DNS server answers only challenge TXT records (plus SOA, NS, and CAA), using per-pen API credentials scoped to a single pen zone.

## Names and Zone Validation

| Role | Hosted pens | Self-hosted pens |
|---|---|---|
| Pen zone (mesh only) | `<pen>.pens.hogman.network` | Operator's own subzone, e.g. `pen.example.com` |
| Shared sites | `<site>.<pen>.pens.hogman.network` | `<site>.pen.example.com` |
| Pen portal | `home.<pen>.pens.hogman.network` | `home.pen.example.com` |
| Public front door (Headscale control, join page, invite redemption) | `<pen>.gate.hogman.network` | Operator's `PUBLIC_HOST` |

- **Pen names are single-use.** A hosted pen name is 3–30 lowercase letters, digits, and hyphens starting with a letter (excluding reserved labels). Once a pen uses a name, that name is permanently retired so old links, cookies, or HSTS entries can never reach a different pen later.
- **Zone checks happen before any routing rule is trusted:**
  - Hosted pen zones must match `^[a-z][a-z0-9-]{1,28}[a-z0-9]\.pens\.hogman\.network$`, verified against the pen's network info and `https://home.<zone>` using the system's trusted roots before `hogman` writes the zone to config or the browser extension accepts it.
  - Front doors live under `gate.` rather than `pens.`, keeping the front-door wildcard certificate and public ingress separate from mesh-only pen zones.
- **No public A or AAAA records exist under pen zones.** Browsers do not resolve pen names via public DNS; the browser extension or PAC routes `*.<pen>.pens.hogman.network` to the local `hogman` proxy, which resolves names over WireGuard via the pen's registrar DNS. Public DNS answers only `_acme-challenge` TXT, CAA, NS, and SOA records.

## Split-Horizon DNS and `challenge-dns`

- **Narrow NS delegation:**
  - `pens.hogman.network` is delegated to the authoritative `challenge-dns` server (`deploy/challenge-dns`, built on `miekg/dns`). Nothing under `pens.` needs a public IP address.
  - For front doors, only `_acme-challenge.gate.hogman.network` is delegated for DNS-01 validation; public A records and `gate.` CAA live in the parent DNS zone.
  - Nothing `challenge-dns` can do modifies the apex domain (`hogman.network`).
- **What `challenge-dns` serves:**
  - `SOA` and `NS` for its delegated zones.
  - `CAA` at `pens.hogman.network`:
    - `0 issue "letsencrypt.org; validationmethods=dns-01"`
    - `0 issue "pki.goog; validationmethods=dns-01"`
    - `0 issuewild ";"`
    (No `accounturi` on `pens.` because every share registers its own ACME account.)
  - `TXT` records at `_acme-challenge.<name>`, created only through the private HTTP API and automatically expired after 10 minutes even if not explicitly deleted.
- **Front-door CAA:** `gate.hogman.network` sets `0 issue ";"` plus `0 issuewild` entries for Let's Encrypt and Google Trust Services constrained by `validationmethods=dns-01` and the host's `accounturi`.
- **Scoped credentials:**
  - Each pen receives a distinct bearer token scoped strictly to `_acme-challenge.*.<pen>.pens.hogman.network` — it cannot write TXT records for any other pen, any non-TXT record type, or anything under `gate.`.
  - A separate host credential is scoped strictly to `_acme-challenge.gate.hogman.network` for the `*.gate.hogman.network` wildcard.
  - The HTTP API listens only on a private Unix socket (never exposed to the public internet) and permits at most 2 concurrent TXT values per name.
- **Rate limits and caps:**
  - `challenge-dns` counts distinct hostnames on first TXT write over rolling 1-hour and 7-day windows (retries for the same name within 7 days do not count again):
    - **Free / Personal pens:** 5 new names/hour (`CDNS_HOURLY_CAP`), 20 per 7 days (`CDNS_WEEKLY_CAP`).
    - **Work pens:** 40 new names/hour (`CDNS_WORK_HOURLY_CAP`), 120 per 7 days (`CDNS_WORK_WEEKLY_CAP`).
    - **Global hourly ceiling:** 80/hour soft (`CDNS_GLOBAL_HOURLY_CAP`) and 120/hour hard (`CDNS_GLOBAL_HARD_HOURLY_CAP`). The 40-slot headroom between soft and hard caps is reserved exclusively for quiet or newly created pens (`< 2` new names in the past hour) so bursty pens cannot starve quiet pens or new sign-ups.
    - `429` responses include a `Retry-After` header and distinguish hourly, weekly, and global limits.
    - Optional 80% 7-day budget warning (`CDNS_LE_WEEKLY_ALLOWANCE`, `CDNS_NTFY_URL`, at most once per 24 hours persisted in state).
  - Fallback EAB mints (`POST /v1/eab`) enforce the same per-credential hourly/weekly caps plus a process-wide burst limiter (20/minute, 90/hour) and a per-credential cooldown on upstream mint errors so one failing pen cannot starve others.

## Who Gets Which Certificate

- **Shared sites (`hogman share`):**
  - Run ACME directly via `certmagic` with their own ACME account key and TLS private key.
  - Use a minimal DNS-01 provider that calls the pen's registrar over WireGuard (`POST` / `DELETE /api/acme/txt`). That endpoint accepts **server devices only**, enforces the same name-ownership check (`serverMayUse`) as claiming a name, and refuses reserved labels (`home`, `ns*`, `nodes`, `_acme-challenge`).
  - Verify TXT propagation against public resolvers (`1.1.1.1`, `8.8.8.8`), since the pen's split DNS does not serve public challenge records.
  - Persist the `certmagic` cache (account, keys, certs, ARI state) in the share's state directory across restarts and `hogman update` so renewals include ARI `replaces`.
  - Hold no DNS credentials; on CA failover, receive only a single-use EAB pair.
- **Pen portal (`home.<zone>`):**
  - `registrar` manages `home.<zone>` directly with `certmagic`, writes the certificate and key atomically into its TLS directory, and serves `https://home.<zone>` directly over its embedded `tsnet` listener with live in-memory certificate reloads.
- **Public front door (`*.gate.hogman.network`):**
  - Uses a single wildcard certificate obtained via DNS-01 with the host credential, keeping individual pen names out of Certificate Transparency logs for front-door traffic.

## Certificate Authorities, Quotas, and Failover

- **Primary CA: Let's Encrypt.**
  - ARI renewals (RFC 9773 `replaces`, sent by `certmagic`) are exempt from Let's Encrypt rate limits; non-ARI exact-identifier renewals are exempt from the new-certificates-per-registered-domain bucket.
- **Fallback CA: Google Trust Services (`pki.goog`).**
  - Supports RFC 8657 CAA parameters and ARI, and requires External Account Binding (EAB).
  - `challenge-dns` holds a least-privilege credential limited to minting single-use EAB keys (which expire after 7 days if unused). When a pen or share first needs fallback issuance, `challenge-dns` mints one fresh EAB pair and returns it; once bound to that ACME account, the pair cannot be reused, and no long-lived CA secret ever leaves `challenge-dns`.
  - Pairs are minted lazily only when failover actually occurs, keeping usage well under GCP Public CA quotas (100 `newOrder`/hour, 25 `newAccount`/min, 100 `newAccount`/hour, 120 EAB API requests/min).
- **Explicit failover policy:**
  - Fail over to the secondary CA only on `rateLimited`, HTTP `429`, or CA `5xx`/outage errors.
  - Never fail over on DNS validation errors (`unauthorized`, `dns`) — retrying a broken challenge against a second CA would burn its failed-validation limit as well.
- **Renewal and deduplication:**
  - Certificates renew via ARI or around 30 days before expiry.
  - Persistent per-share caches, exponential backoff on failures, and per-pen/global caps prevent repeated issuance loops.

## Browser and Multi-Pen Guardrails

- The front door allowlists only Tailscale control/relay routes and the join page, returning `404` for everything else.
- `Origin-Agent-Cluster: ?1` is sent on the portal and front door; `X-Content-Type-Options: nosniff` is sent on downloads and API responses.
- Portal mutations require same-origin + JSON (`requireSameOriginAndJSON`), blocking cross-site and cross-pen CSRF requests.
- HSTS never uses `includeSubDomains` or preload on `hogman.network`, `pens.`, or `gate.`.
- Until `pens.hogman.network` is on the Public Suffix List, apps in different pens under `pens.hogman.network` share a browser registrable-domain cookie scope. The browser extension enforces per-profile pen allowlists by default (nothing routes in a profile until explicitly enabled), and untrusted pens should be kept in separate browser profiles.

## Threat Model

| Threat | Mitigation |
|---|---|
| Compromised share tries to get a certificate for another share's name | Registrar writes TXT only for names that server device is authorized to use (`serverMayUse`); per-share keys mean no shared wildcard. |
| Compromised pen tries to issue certificates for another pen or `hogman.network` | Per-pen credential scope in `challenge-dns`, plus narrow NS delegation (cannot touch `hogman.network` or `gate.`). |
| Issuance via an unauthorized CA or HTTP-01/TLS-ALPN-01 | CAA restricts issuance to Let's Encrypt and Google Trust Services with `validationmethods=dns-01` (and `accounturi` on `gate.`). |
| Leaked Google Trust Services credential | Service-account key stays inside `challenge-dns`; pens and shares receive only single-use EAB pairs bound once to their own ACME account. |
| One pen exhausts shared CA quota | Per-pen hourly/weekly caps, global soft/hard hourly ceiling reserving quiet-pen headroom, Let's Encrypt rate-limit override, and GTS fallback. |
| Pen and site names visible in Certificate Transparency | Documented upfront; pen names are not publicly reachable because no public A/AAAA records exist under `pens.`. |
| Cross-pen cookie or same-site interference | Same-origin JSON CSRF enforcement on the portal, per-profile extension allowlists by default, and profile isolation guidance. |
| `challenge-dns` outage | Existing certificates remain valid for ~60 days after issuance and ARI starts renewing early. |
| Pen server reads members' site traffic | TLS terminates end-to-end at each share with its own private key, never at the pen server. |

## Offline CI Verification

CI tests the full public-certificate flow offline against Pebble (`core/test/acme-pebble.sh`) and Go unit tests:
- Shares obtain certificates through the registrar's TXT endpoint and cannot obtain certificates for another share's name.
- `home.<zone>` obtains and reloads its certificate cleanly without touching any client trust store.
- Share restarts reuse cached certificates without opening a new ACME order.
- Failover to a secondary CA triggers on `429`/outage errors and does not trigger on DNS validation failures.
- `challenge-dns` unit tests verify credential scoping (other pens, `gate.`, non-TXT, apex writes refused), CAA responses, per-pen/global caps, and EAB reservation/cooldown semantics.
