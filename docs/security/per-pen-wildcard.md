# Per-pen wildcard certificates: design proposal

Status: **parked** (2026-11-22, maintainer's call after @hogman's red-team on PR #112). Nothing is built.

**Why parked:** with the hosted registrar holding each pen's wildcard key, a compromised hosted server could impersonate any site in any pen *silently*. Today a compromised server can mint certificates through DNS-01, but every one lands in CT, so it is detectable. That trades a detectable attack for an undetectable one, which is the wrong default. The mitigations are also weaker than this draft claimed:
- short-lived certificates carry no OCSP or CRL, so a kicked member keeps a working key for up to about 6 days;
- reissuing on every kick hits Let's Encrypt's 5-per-week duplicate-certificate limit, and a sharer can force it;
- the GTS fallback has no short-lived profile.

**If revisited:** only as a keeper opt-in ("private site names") where the pen key is generated on the keeper's device and passed between the pen's share hosts end-to-end encrypted, so the hosted server never holds it. Until then, the docs keep stating that site names are public in CT.

## Problem

Every publicly trusted certificate goes into the public Certificate Transparency (CT) logs, and the logs keep it forever. Today every share gets its own certificate (`docs/security/public-certificates.md`). So the logs publish every pen name and every site name, for example `therapy-notes.smith.pens.hogman.network` or `divorce-lawyer.smith.pens.hogman.network`. Anyone can search them (crt.sh). For a product whose point is a private life off the open web, the names of the things people host are a leak. Hogman doesn't police names (D-26); this is about saying less in public, for everyone.

CT itself can't be avoided while we use public certificates. Going back to a private CA, so that nothing is logged, means installing a root on every device, which is what D-18 removed. What we control is what the certificates name.

## Proposal

One certificate per pen, `*.<pen>.pens.hogman.network` (plus the bare `<pen>.pens.hogman.network` if anything needs it), in place of one certificate per site.

- **CT then shows one name per pen:** `*.smith.pens.hogman.network`. That says the pen exists and nothing about what's inside it.
- **Optional, decided separately: random public pen IDs** (the original D-20 shape, `*.k3j9x2ab.pens.hogman.network`). With these, CT shows nothing meaningful at all. The cost is unreadable addresses.
- **Fewer certificates and fewer orders.**
  - The per-pen weekly cap (`CDNS_WEEKLY_CAP`), I-1's per-member share and most of the Let's Encrypt 50-per-week pressure stop mattering: a new pen needs one order, not one per server.
  - The CAA on `pens.` must allow `issuewild` for this zone; today it says "no wildcards".

## Who holds the key

The certificate can be obtained by:
- the pen's registrar, which already does DNS-01 for `home.<pen>`;
- or the first share, which then hands it over.

Then the key has to reach every share host in the pen, and that is the cost. Every server in the pen holds one private key, and anyone with it can present a valid certificate for any name in the pen.

How the key would move:
- The registrar keeps the key and the chain.
- A share host fetches them over the mesh: `GET /api/acme/wildcard`, server devices only, the same gate as `/api/acme/eab`.
- The share host keeps them under its share folder, mode 0600.

## Why sharing the key is less dangerous here than usual

Normally a shared wildcard key means any holder can impersonate any sibling site. In Hogman, inside the pen, a holder can't get the traffic:

1. **Names resolve only through the pen's own DNS.** It's served by the pen's registrar on the mesh. `hogman-join`'s resolver dials only devices this pen's node knows (`core/join/agent.go`, `newAgent`). A member can't point `photos.smith…` at their own device; only the registrar maps names to devices, after `serverMayUse`.
2. **The proxy dials only mesh peers.** The IP must pass `WhoIs` (`isPeer`). Traffic between peers is WireGuard, so nobody on the path can redirect it.
3. **Personal devices accept no inbound connections, and shares are tagged servers.** A member can't stand up a fake `photos` and have DNS send people to it.

So while the browser is going through `hogman-join`, holding the key doesn't let a member impersonate another member's site.

## Where it is still dangerous (the reasons this needs review)

1. **Kicked members keep the key.** A share host that's kicked still has a valid key until the certificate expires. Browser revocation checking is weak: CRLSets and CRLite cover little, and OCSP is going away.
   - **Mitigation:** Let's Encrypt's short-lived (about 6-day) profile, plus re-keying and reissuing on every kick and every removed server.
   - That leaves a gap of at most about 6 days, and in practice 0 once reissue and revocation land.
   - The cost is renewals every ~3 days per pen; renewals don't count against the new-certificate limits.
2. **Browsers outside the proxy.** When the PAC isn't in effect (macOS VPN case, Safari with a VPN, a misconfigured browser), the browser resolves pen names through ordinary DNS. Today that returns NODATA, so the page fails safely.
   - On a hostile network (for example café Wi-Fi with forged DNS), someone holding a leaked pen key could answer with their own address and present a valid certificate for every site in the pen: credentials, cookies.
   - Per-site keys have the same weakness, but only for one site, and only if that one host leaks. With a wildcard, any one server leaking exposes the whole pen.
   - **Mitigations to weigh:**
     - short-lived certificates (above);
     - keep `home.<pen>` (where member sessions live) on its own non-wildcard certificate held only by the registrar;
     - the browser extension fails closed for allowed pens;
     - HSTS doesn't help, since the certificate is valid.
3. **Key at rest on members' machines.**
   - A stolen laptop that runs a share yields the pen's key, not one site's.
   - The same short-lived and rotate-on-kick answer applies, plus removing the device's server node, which already happens on kick.
4. **Blast radius of a registrar bug.** The registrar now hands out one key to many hosts. The `/api/acme/wildcard` gate must be at least as strict as the gate for names.

## Rejected alternative

**Terminate TLS centrally.** The pen's hosted server would hold the wildcard and forward to shares over the mesh. That breaks the end-to-end promise: our server would see members' traffic in the clear, against "a pen's server never sees its members' traffic in the clear".

## What changes if we do it

- **Registrar:** obtains and renews the pen wildcard on the short-lived profile, serves it to server devices over the mesh, and re-keys on kick or server removal.
- **`hogman-join share`:** no per-site ACME. It fetches the pen wildcard and reloads on rotation, with a fallback to per-site certificates during migration.
- **challenge-dns:** CAA `issuewild` for `pens.`. The per-pen credential may write `_acme-challenge.<pen>.pens.hogman.network`, which is the wildcard's challenge name.
- **Docs:** update public-certificates.md, the security page and the FAQ. The CT disclosure on the sign-up page becomes "your pen's name, not your sites'".
- **Existing names stay in CT forever.** This only helps from the switch onward, which is the argument for deciding before launch.

## Questions for review

1. Is "inside the proxy, a holder can't get the traffic" airtight? Think about mesh DNS, MagicDNS, `peerIPsForHost` and any path that bypasses the registrar's mapping.
2. Is the browser-outside-the-proxy risk acceptable with 6-day certificates plus rotate-on-kick, or does it block the plan?
3. Should `home.<pen>` stay a separate, registrar-only certificate?
4. Random public pen IDs: worth the ugly addresses?
