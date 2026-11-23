# challenge-dns

The DNS server that answers Let's Encrypt and Google Trust Services when they check a pen's
certificate requests (ACME DNS-01). It's authoritative for `pens.hogman.network` and
`_acme-challenge.gate.hogman.network`, which Cloudflare delegates to it, and it serves only:

- **TXT** challenge records, written through its API and gone after 10 minutes;
- **CAA** at the pens apex: only Let's Encrypt and Google, only by DNS-01, and no wildcards;
- **SOA** and **NS**.

It never serves an address. Names under its zones that have nothing are answered "no records"
(NODATA), never "doesn't exist" (NXDOMAIN, RFC 8020). Anything outside its zones is refused.

**Who may write what.** Each pen's registrar has a credential for that pen alone: it can write
`_acme-challenge.<site>.<its pen name>.pens.hogman.network` and nothing else, subject to a
two-window cap on distinct new names: by default **5 per rolling hour** (`CDNS_HOURLY_CAP`) and
**20 per rolling 7 days** (`CDNS_WEEKLY_CAP`) per pen, plus a global hourly ceiling across all
pens: **40 per rolling hour soft cap** (`CDNS_GLOBAL_HOURLY_CAP`) and **60 per rolling hour hard
cap** (`CDNS_GLOBAL_HARD_HOURLY_CAP`). Slots between the soft and hard caps are reserved
exclusively for quiet or newly created pens (pens with fewer than 2 new names in the last hour), so
bursty pens cannot starve quiet users or new pen sign-ups. `home.<pen>` uses one slot, **attempts
count rather than issued certs** (a failed-then-undone share still uses a slot for 1 hour and 7
days once its challenge TXT was written), and retries or renewals of names already in the 7-day
window are free. Lowering caps takes effect immediately on restart, and `429` responses carry a
`Retry-After` header in seconds. The host's front door has one credential, for its `*.gate`
wildcard only. Tokens are stored as SHA-256 hashes.

**What it keeps, and nothing more:** token hashes; for the hourly and weekly caps, which names each
pen wrote in the last 7 days (timestamped); recent fallback-key mints (7 days); and the names of
pens ever given a credential, so a deleted pen's name is never handed out again (`challenge-dns name
used <name>`). That last list holds only names, which are public in the certificate logs anyway.

**The fallback CA.** With `CDNS_GCP_KEY` set to a Google service-account key that holds
only `roles/publicca.externalAccountKeyCreator`, `POST /v1/eab` mints one single-use
Google account key on request, gated by the same per-pen hourly and weekly caps (`CDNS_HOURLY_CAP`,
`CDNS_WEEKLY_CAP`) within Google's project quota.
The service-account key never leaves this server. Google refuses an account without a
contact, so a key is handed out only with `CDNS_GTS_CONTACT` set (`hogman-host
fallback-contact <email>`), and the response carries that operator address for the account.
Without it the API answers 503 rather than mint a key that would be wasted.

Design and threat model: [docs/security/public-certificates.md](../../docs/security/public-certificates.md).

```bash
challenge-dns serve                      # CDNS_LISTEN=203.0.113.10:53, see `challenge-dns` for all settings
challenge-dns cred add pen <penname>     # prints the token once
challenge-dns cred add host
challenge-dns cred list
challenge-dns cred rm <id>
challenge-dns name used <penname>        # sign-up asks before raising a pen
```

| API (Unix socket `/run/hogman-acme/api.sock`, bearer token) | |
|---|---|
| `POST /v1/txt {fqdn, value}` | 201 (also on repeat) · 400 bad value · 403 out of scope · 409 two live already · 429 hourly/weekly/global cap (`Retry-After`) |
| `DELETE /v1/txt {fqdn, value}` | 204 (also when absent) · 403 out of scope |
| `POST /v1/eab` | 201 `{kid, hmac_b64url, contact}` · 429 allowance or Google quota · 503 not configured or no contact |
