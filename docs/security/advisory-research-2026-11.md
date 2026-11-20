# Advisory research, 2026-11-20

Recent security advisories for every piece Hogman depends on, and for the
surfaces of the own-connection design (D-10). Web research on 2026-11-20;
sources at the end. Some third-party write-ups disagree on dates and versions;
where they did, I relied on the vendor's own advisory or release notes.

## Are we patched?

| Component | We pin | Advisories of note (2026) | Fixed in | Status |
|---|---|---|---|---|
| Tailscale client (`tsnet` in hogman-join, `core-mesh` image) | v1.104.7 | TS-2026-014 to 017 "Tailworm": SSH Unix-socket forwarding to root, tailscaled session OOM, `serve --tcp` LocalAPI takeover, HTTP/2 capability bleed. TS-2026-007: Services reached loopback-bound listeners. TS-2026-008: Serve/Funnel CPU pin. TS-2026-009: SSH username flag injection. | 1.104.4 (Oct); 1.98.9 (Jul) | ✓ |
| Headscale | 0.29.7 | Tailworm control-server findings C2 (embedded DERP memory growth) and C4 (unauthenticated Noise auth-cache eviction), DoS class, Medium-High | 0.29.7 (Oct 30) | ✓ Headscale still hard-codes SSH forwarding in SSH sessions; we grant no SSH policy |
| step-ca | 0.30.2 | CVE-2026-30836 (CVSS 10): unauthenticated issuance via SCEP UpdateReq. CVE-2026-40097: TPM device-attest-01 panic | 0.30.0 | ✓ We use only an ACME provisioner, no SCEP, no device-attest-01 |
| Caddy | 2.11.9 | CVE-2026-55458 (hop-by-hop headers through WebSocket 101), CVE-2026-45692 (admin API path auth), CVE-2026-30852 bypass (env leak), CVE-2026-27588 (host matching >100 hosts) | 2.11.5 and earlier | ✓ |
| Go toolchain | `golang:1.27-alpine` (latest 1.27.x at build), go.mod 1.27.4 | CVE-2026-111943 (x509 distrusts compromised eMudhra intermediates), CVE-2026-33810 (excluded DNS constraints vs wildcard SAN case; Go 1.26 only), CVE-2026-27145 / 32281 (x509 DoS), net/http GO-2026-6859 | 1.27.3 / 1.26.10 | ✓ Builds pick up the latest 1.27 patch; releases are rebuilt on GitHub per commit |
| gVisor netstack (via tsnet) | v0.0.0-20260915 | gVisor's record lists fixes in release 20260831.0 (a VFS use-after-free, and a TCP item whose attribution conflicts with Google's own bulletins) | 20260831.0 | ✓ Ours is newer |
| wireguard-go (via tsnet) | tailscale fork 2026-11-06 | Only Chainguard-packaged advisories (CVE-2026-27143/27144) found; no upstream advisory | n/a | ✓ as far as found |
| systemd-resolved | distro | No split-DNS CVE. DNSSEC validation issues (CVE-2026-40226, CVE-2023-7008). dnsmasq CVE-2026-93008 affects split-DNS caching | distro | Note: if a Linux fallback uses dnsmasq, require a patched one |

## What the research changes for the own-connection design

1. **The T8 class is real in the wild.** Tailscale itself shipped TS-2026-007:
   traffic meant for a Service reached processes on the host's loopback. Our T8
   (a hostile pen's DNS steering the agent onto loopback, the LAN or another
   tailnet) is the same class. It is fixed for today's agent in PR #25
   (dial only devices the pen's node knows), and the real build must keep that
   rule.

2. **Browser protections won't help with the synthetic range.** Chrome's Local
   Network Access (enforced since Chrome 142, extended to WebSockets in 147)
   classifies destinations by address. Sources describe CGNAT `100.64.0.0/10`
   and `fc00::/7` as local and VPN-sensitive; `198.18.0.0/15` is not treated as
   local by Chrome (and Firefox changed to match). So pages can reach
   synthetic addresses without a prompt. That's acceptable only because, after
   the T8 fix, a synthetic address can lead only to a device the pen knows.

3. **macOS `/etc/resolver` for non-IANA TLDs is fragile.** Several reports say
   macOS 26.1 to 26.3 sent queries for custom TLDs (`.internal`, `.test`,
   `.lan`) to mDNS instead of the `/etc/resolver` nameserver. Our test on
   macOS 26.6 worked for `.hogman`, and one report says 26.6.2 works. The real
   build needs a start-up self-test (resolve the pen's `home` name through the
   system resolver) with a clear fallback (side by side) when the OS gets it
   wrong, and testing on the oldest macOS we support.

4. **Name constraints: keep them on the intermediate too.** Some verifiers
   don't apply name constraints on a trust anchor (Grok's T7 note; RFC 5280
   leaves trust-anchor constraints optional). Our intermediate also carries
   `permittedDNSDomains` and `excludedIPRanges` (`core/templates/
   intermediate_ca.tpl`), so a leaf for another name fails in verifiers that
   skip the root's. CVE-2026-33810 concerned *excluded* DNS constraints and
   wildcard case in Go 1.26; we use *permitted* DNS constraints and are on 1.27.

5. **Tailworm is a reminder about LocalAPI and long-lived sessions.** Two of
   the four client bulletins were reaching privileged local functions
   (`serve --tcp` LocalAPI takeover, root Unix-socket forwarding). The real
   own-connection daemon will have a local control channel (T3); it must be a
   root-owned socket with peer-credential checks, and never forward to
   arbitrary local sockets.

## Upgrade policy

Pinned images and modules are current as of today. To stay that way: watch
Tailscale's security bulletins, Headscale, step-ca and Caddy GitHub advisories,
and the Go release announcements; bump within a week of a fix that touches
something we use, run the GitHub e2e suites, release, and upgrade the pens.

## Sources

Tailscale: [security bulletins](https://tailscale.com/security-bulletins) ·
[TS-2026-007](https://cve.circl.lu/vuln/ts-2026-007) ·
[TS-2026-008](https://cvepremium.circl.lu/vuln/ts-2026-008) ·
[TS-2026-009](https://db.gcve.eu/vuln/ts-2026-009) ·
[Corgea on TS-2026-014 to 017](https://corgea.com/research/ts-2026-014-015-016-017-tailscale-tailworm-ssh-unix-socket-root-escalation) ·
[Tailworm report](https://www.tailworm.com/) ·
[SecurityWeek](https://www.securityweek.com/tailscale-rushes-patches-after-uncoordinated-disclosure-of-tailworm-flaws/)

Headscale: [releases](https://github.com/juanfont/headscale/releases) ·
[Headplane CVE-2026-46484](https://www.sentinelone.com/vulnerability-database/cve-2026-46484/)

step-ca: [CVE-2026-30836 (GHSA-q4r8-xm5f-56gw)](https://github.com/advisories/GHSA-q4r8-xm5f-56gw) ·
[CVE-2026-40097](https://www.strix.ai/cve/CVE-2026-40097)

Caddy: [CVE-2026-55458](https://www.cve.org/CVERecord?id=CVE-2026-55458) ·
[CVE-2026-45692](https://advisories.gitlab.com/golang/github.com/caddyserver/caddy/v2/CVE-2026-45692/) ·
[CVE-2026-30852 bypass](https://github.com/caddyserver/caddy/security/advisories/GHSA-wwhq-w58m-w29c) ·
[CVE-2026-27588](https://advisories.gitlab.com/pkg/golang/github.com/caddyserver/caddy/v2/CVE-2026-27588/)

Go: [vulnerability list](https://pkg.go.dev/vuln/list) ·
[CVE-2026-33810 (golang/go#78332)](https://github.com/golang/go/issues/78332) ·
[OSV CVE-2026-33810](https://osv.dev/vulnerability/CVE-2026-33810) ·
[x509 intermediate distrust (golang/go#82345)](https://github.com/golang/go/issues/82345)

gVisor: [security record](https://gvisor.dev/security-track-record/) ·
[GKE security bulletins](https://docs.cloud.google.com/kubernetes-engine/security-bulletins)

wireguard-go: [Chainguard advisory](https://images.chainguard.dev/security/CGA-5mvr-2pvm-cf8q)

systemd / DNS: [USN-8402-1](https://ubuntu.com/security/notices/USN-8402-1) ·
[dnsmasq CVE-2026-93008](https://vulners.com/redhatcve/RH:CVE-2026-93008)

Browsers: [Chrome Local Network Access](https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access)

macOS resolver: [macOS 26 /etc/resolver bug report](https://gist.github.com/adamamyl/81b78eced40feae50eae7c4f3bec1f5a) ·
[macOS split DNS debugging](https://walliz.cc/en/articles/macos-split-dns-vpn-browser-timeout)
