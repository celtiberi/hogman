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
`_acme-challenge.<site>.<its pen name>.pens.hogman.network` and nothing else, and at most
10 new names a week. The host's front door has one credential, for its `*.gate` wildcard
only. Tokens are stored as SHA-256 hashes.

**What it keeps, and nothing more:** token hashes; for the weekly cap, which names each pen wrote
in the last 7 days; recent fallback-key mints (a day); and the names of pens ever given a
credential, so a deleted pen's name is never handed out again (`challenge-dns name used <name>`).
That last list holds only names, which are public in the certificate logs anyway.

**The fallback CA.** With `CDNS_GCP_KEY` set to a Google service-account key that holds
only `roles/publicca.externalAccountKeyCreator`, `POST /v1/eab` mints one single-use
Google account key on request, at most 5 a day per credential, within Google's quota.
The service-account key never leaves this server.

Design and threat model: [docs/security/public-certificates.md](../../docs/security/public-certificates.md).

```bash
challenge-dns serve                      # CDNS_LISTEN=159.65.78.95:53, see `challenge-dns` for all settings
challenge-dns cred add pen <penname>     # prints the token once
challenge-dns cred add host
challenge-dns cred list
challenge-dns cred rm <id>
challenge-dns name used <penname>        # sign-up asks before raising a pen
```

| API (Unix socket `/run/hogman-acme/api.sock`, bearer token) | |
|---|---|
| `POST /v1/txt {fqdn, value}` | 201 (also on repeat) · 400 bad value · 403 out of scope · 409 two live already · 429 weekly cap |
| `DELETE /v1/txt {fqdn, value}` | 204 (also when absent) · 403 out of scope |
| `POST /v1/eab` | 201 `{kid, hmac_b64url}` · 429 allowance or Google quota · 503 not configured |
