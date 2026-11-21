// hogman.network's DNS, as code (decision D-23). Changed only by a PR: every PR
// shows a preview of exactly what would change; merging applies it from the
// locked "infra" environment, after approval. Nobody edits records in the
// Cloudflare dashboard.
//
// NO_PURGE: until the zone has been imported in full (workflow "dns", action
// "import") and this file reviewed against it, dnscontrol may add or change
// records but never deletes one it doesn't know about.

var REG_NONE = NewRegistrar("none");
var DSP_CLOUDFLARE = NewDnsProvider("cloudflare");

D("hogman.network", REG_NONE, DnsProvider(DSP_CLOUDFLARE),
  NO_PURGE,
  DefaultTTL(1), // Cloudflare's "auto"

  // Imported from the live zone on 2026-11-21 (workflow "dns", action "import").
  // Every record is DNS-only (no Cloudflare proxy).

  // The website (Fly).
  A("@", "66.241.125.85"),
  AAAA("@", "2a09:8280:1::213:c8aa:0"),
  A("www", "66.241.125.85"),
  AAAA("www", "2a09:8280:1::213:c8aa:0"),

  // The hosting server.
  A("get", "159.65.78.95"),    // sign-up page
  A("hs", "159.65.78.95"),     // the farm pen's front door
  A("*.pens", "159.65.78.95"), // hosted pens' front doors (moving to *.gate at the switch-over)
  A("ns1", "159.65.78.95"),    // the challenge DNS server (D-18); IPv4 only

  // Email from the sign-up page (Resend).
  CNAME("send", "send.forge.rmta.net."),
  CNAME("rsend", "rsend.forge.rmta.net."),
  TXT("resend._domainkey", "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMdsTLCits5O5Ahdg0HWhSfUueKGAfYbNWx1n2KqZ7PDA9krQa91FGDiafPpATUqN5RsPAJHHq8O6xWO4pcsUnsBEXpROgf4IoN11pyqU/750aPv5DCd5kKKLNZa74rf+gjAtOYJna/QPixcnafSsnkNdyu8DQxr6nFtIo9IZGPQIDAQAB"),
  TXT("_dmarc", "v=DMARC1; p=none;"),
END);
