// hogman.network's DNS, as code (decision D-23). Changed only by a PR: every PR
// shows a preview of exactly what would change; merging applies it from the
// locked "infra" environment, after approval. Nobody edits records in the
// Cloudflare dashboard.
//
// This file is the whole zone: a record that isn't here gets deleted by the
// next apply. (Cloudflare's own apex NS records are managed by Cloudflare and
// never touched.)

var REG_NONE = NewRegistrar("none");
var DSP_CLOUDFLARE = NewDnsProvider("cloudflare");

D("hogman.network", REG_NONE, DnsProvider(DSP_CLOUDFLARE),
  DefaultTTL(1), // Cloudflare's "auto"

  // Imported from the live zone on 2026-11-21 (workflow "dns", action "import").
  // Records stay DNS-only except get. and get.work. (sign-up pages), which use Cloudflare
  // Proxy for edge DDoS absorption, WAF, and rate limiting.

  // The website (Fly).
  A("@", "66.241.125.85"),
  AAAA("@", "2a09:8280:1::213:c8aa:0"),
  A("www", "66.241.125.85"),
  AAAA("www", "2a09:8280:1::213:c8aa:0"),
  A("work", "66.241.125.85"),    // Hogman for Work (D-27), same site
  AAAA("work", "2a09:8280:1::213:c8aa:0"),

  // The hosting server.
  A("get", "159.65.78.95", CF_PROXY_ON), // sign-up page (proxied via Cloudflare)
  A("get.work", "159.65.78.95", CF_PROXY_ON), // Work sign-up page, same server (D-27); edge cert via ACM
  A("ns1", "159.65.78.95"),              // the challenge DNS server (D-18); IPv4 only

  // Hosted pens' sites live under pens. (D-18). The whole subzone is the
  // challenge DNS server's: it answers only SOA, NS, CAA and challenge TXT, so
  // nothing under it has a public address. Front doors are under gate. below.
  NS("pens", "ns1.hogman.network."),

  // Front doors under gate. (D-18 switch-over, Phase A). Addresses and CAA stay
  // here; only the wildcard's challenge name is handed to the challenge DNS
  // server, so it can never touch anything else in this zone.
  A("*.gate", "159.65.78.95"),                          // every hosted pen's front door; IPv4 only
  NS("_acme-challenge.gate", "ns1.hogman.network."),    // DNS-01 for the *.gate wildcard
  // Only a wildcard may be issued for gate. (issue ";" alone forbids plain
  // names: RFC 8659), only by Let's Encrypt, only by DNS-01 (RFC 8657).
  // Pinned to hogman-1's own Let's Encrypt account (RFC 8657 accounturi), so
  // even a leaked challenge credential can't get a *.gate certificate through
  // any other account. Phase E adds pki.goog with the host's GTS account.
  CAA("gate", "issue", ";"),
  CAA("gate", "issuewild", "letsencrypt.org; validationmethods=dns-01; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/4026504272"),

  // Cloudflare's Advanced Certificate Manager (edge certificate for
  // *.hogman.network and *.work.hogman.network) writes its own DNS-01 TXT
  // records here at issue and at every renewal. Leave them alone, or an apply
  // that runs mid-validation deletes them and the renewal fails.
  IGNORE("_acme-challenge", "TXT"),
  IGNORE("_acme-challenge.work", "TXT"),

  // Email from the sign-up page (Resend).
  CNAME("send", "send.forge.rmta.net."),
  CNAME("rsend", "rsend.forge.rmta.net."),
  TXT("resend._domainkey", "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMdsTLCits5O5Ahdg0HWhSfUueKGAfYbNWx1n2KqZ7PDA9krQa91FGDiafPpATUqN5RsPAJHHq8O6xWO4pcsUnsBEXpROgf4IoN11pyqU/750aPv5DCd5kKKLNZa74rf+gjAtOYJna/QPixcnafSsnkNdyu8DQxr6nFtIo9IZGPQIDAQAB"),
  TXT("_dmarc", "v=DMARC1; p=none;"),
END);
