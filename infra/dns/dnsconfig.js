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

  // Filled in from the import. Until then this file manages nothing.
END);
