# Red team: Hogman's own connection (option D)

Status: **superseded by decision D-11 (HTTPS only), 2026-11-20.** The own-connection
design was not built: deleting the surface fixed most of what follows. Kept as the record of
why. T8 (hostile DNS) applied to the live side-by-side agent too and was fixed there (PR #25).
Grok's independent review: `own-connection-redteam-grok.md`; advisories:
`advisory-research-2026-11.md`. Originally: draft for review, 2026-11-20. Subject: the spike on branch
`spike/own-connection` (`core/join/spike_tun.go`, `spike_os_darwin.go`,
`spike_os_linux.go` on that branch), proposed as the single way to join a computer to a pen
(decision D-10, pending D-11).

## What it is

`hogman-join` (as root) creates a TUN interface (utun on macOS, `hogman0` on
Linux), routes a synthetic range (`198.19.0.0/16` from `198.18.0.0/15`) to it,
and writes a scoped resolver for each joined pen's zone (`/etc/resolver/<zone>`
on macOS, `resolvectl ~<zone>` on Linux) pointing at a DNS stub on the TUN
(`198.19.0.53`). The stub asks the pen's own DNS (over the pen's tsnet node),
maps each answer to a synthetic address, and a userspace gVisor stack on the TUN
forwards TCP and UDP for synthetic addresses to the real mesh address through
the pen's tsnet node. One tsnet node per joined pen. A status endpoint listens on
`127.0.0.1:19819`. The spike keeps per-pen state in a directory given on the
command line (`config.json`, the tsnet state).

Today's alternatives it would replace: joining through the system Tailscale app,
and side by side (tsnet plus a local HTTP proxy and a PAC file).

## Assets

- The member's computer: root on it, and their other networks (LAN, work tailnet).
- The member's pens: their traffic, their identity in each pen, their trust in
  each pen's CA.
- Other pens the member belongs to (isolation between pens).
- Privacy: which pen names the member looks up.

## Attackers

1. Malicious software or another user on the member's computer, unprivileged.
2. A malicious or compromised pen (its keeper, registrar or DNS), which the
   member joined.
3. A malicious member of a pen the user is in (controls a server and its names).
4. A web page the member visits on the open internet.
5. Someone on the same local network (café Wi-Fi).

## Threats I see (to be confirmed, refuted or extended)

### Local privilege and integrity (attacker 1)

T1. **Root runs a user-writable binary.** Today's side-by-side agent copies
`hogman-join` into the user's config folder (`installedBinary`). If the real
version's root service runs from a user-writable path, any process running as
the user can replace it and get root at the next start. The binary, its launchd
plist / systemd unit and its state must be root-owned and not writable by the
user.

T2. **Root trusts user-writable configuration.** The spike reads `config.json`
(zone, login server, DNS server, control CA) from a user-supplied directory and
runs as root. A local process that edits it before start can point the root
daemon at an attacker's control server, or add a control CA that the process
then trusts (`installCombinedControlCAs` sets process-wide fallback roots).
`zoneRE` limits the zone to `<label>.hogman`, so `/etc/resolver` paths can't be
traversed.

T3. **Unauthenticated control channel.** The real version needs the
unprivileged CLI (join, leave, share) to drive the root daemon. If that channel
is not authenticated (peer credentials on a root-owned Unix socket, or similar),
any local process can join pens, add zones and read state.

T4. **Status endpoint leaks.** `127.0.0.1:19819/status` is unauthenticated and
returns the synthetic map (which pen hosts exist, their mesh addresses). Any
local process can read it. With DNS rebinding a web page could read it too
(no Host check).

T5. **Every local process and user reaches the pen.** Inherent to any
system-wide connection (true of a VPN too): on a shared computer, other users
get the member's pen access. Side by side had the same property through its
proxy.

T6. **State in `/tmp` as root.** The spike leaves root-owned `node/` dirs under
`/tmp/spike-*`. Root writing into user-chosen paths in a world-writable
directory invites symlink attacks. The real version should keep state in a
root-owned directory.

### A hostile pen (attacker 2)

T7. **Same zone name in two pens: full MITM.** Zones are chosen by keepers. A
malicious pen that the member joins could use the same zone name as another pen
the member is in (`farm.hogman`). Its root CA is name-constrained to that same
zone, so the member's computer trusts two CAs for the same names, and the
scoped resolver / `matchZone` sends lookups to one of them. Result: the hostile
keeper can impersonate every site of the other pen. (Also true today with two
roots installed.) The join must refuse a second pen whose zone is already
joined, and the trust store must never hold two roots for one zone.

T8. **Hostile DNS pointing outside the mesh.** The stub maps whatever the pen's
DNS returns. If it returns a LAN address, `127.0.0.1` or a public address, what
does the tsnet `Dial` do with it? If it dials through the host network, a hostile
pen gets a root-privileged SSRF into the member's LAN and loopback. Answers must
be restricted to the mesh ranges (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) of that
pen, ideally to peers the node actually knows.

T9. **Synthetic pool exhaustion.** Each distinct name the pen's DNS answers
allocates a synthetic address, never freed. A pen with a wildcard answer, plus
anything that makes the computer look up many random names (a web page with
image tags pointing at `x1.farm.hogman`, `x2.farm.hogman` and so on), fills the
pool and the map, denying the member access to all their pens and growing memory.
Needs expiry and a per-pen cap.

T10. **Control CA as process-wide fallback.** A pen's control CA (test pens
only) is installed as a process-wide fallback root, so it applies to every TLS
connection in the daemon, including other pens' control servers.

### A malicious member (attacker 3)

T11. **Reaching the member's computer.** Personal devices accept nothing under
the pen's policy. The spike's tsnet nodes don't listen. Confirm nothing in the
real version (share, status) exposes a listener on the mesh, and that the
synthetic range can't be reached from the mesh side.

### The open internet (attacker 4)

T12. **DNS rebinding and CSRF into pen sites.** A public page can't resolve pen
names directly, but it can embed `https://x.farm.hogman/...` URLs, and the
browser will resolve and fetch them with the member's access. That's the same
as today, but now every app (not just the browser through the PAC) does it, and
the stub answers any name under the zone. Pen sites need the usual CSRF
defences (the home page's API has them). Also T4 above.

T13. **Name lookups leak.** If the TUN is down but `/etc/resolver/<zone>` stays
(crash, kill -9), or the stub fails, does macOS fall back to the public resolver
and leak pen host names to the ISP? The real version should fail closed, and
clean stale resolver files at start.

### The local network (attacker 5)

T14. **Synthetic range collisions.** `198.18.0.0/15` is used by some proxy apps
(the fake-IP mode of Surge, Clash and similar) and by some labs and corporate
networks. A collision could break the member's other tools or send their
traffic into the pen. Detect existing routes and pick a free range.

T15. **Nothing listens on the LAN.** Confirm the DNS stub, the status endpoint
and the gVisor stack are reachable only from the TUN or loopback, not from the
physical interfaces.

## Out of scope here

Phones (expected to get a pen-browsing app). Windows (later). The pen's server
side, which this doesn't change.
