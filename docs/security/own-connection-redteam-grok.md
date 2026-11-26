

---

## GROK (Grok Build CLI [stable]) - 2026-11-20 19:05 UTC
*Independent model review; output appended verbatim from a sandboxed read-only workspace.*

I'll review the threat model against the spike and the side-by-side agent, and check the OS and tsnet behaviors the rulings depend on.

T8 is a root-privileged pivot to loopback and the LAN, and it is reachable from a normal browser. T10 does not add a fallback CA. With the `GODEBUG` flag the spike sets, that CA replaces the process trust store. Several other items are real design constraints. T7, the wildcard half of T9, and the LAN-listener half of T15 do not match this code.

Reviewed against `spike_tun.go`, `spike_os_darwin.go`, `spike_os_linux.go`, `agent.go`, and `alongside.go`, plus current `tsnet`/`tsdial` and Go `crypto/x509` behavior as of 2026-11-20.

## T1–T15

**T1. REAL as a production constraint. Not present in the spike.** `installedBinary` in `alongside.go` copies the binary into `stateDir(zone)` (`UserConfigDir/hogman/<zone>`) with mode `0755`. Side-by-side is not root, so this is not a root bug today. A launchd/systemd unit that execs that path, or any other user-writable path, is a root shell at the next start. The spike has no plist, unit, or copy step.

**T2. REAL.** `spikeTunCmd` calls `loadSpikePen` on each caller-supplied directory and never checks owner, mode, or that the directory is not a symlink. `loadAgentConfig` unmarshals `login_server`, `dns_server`, and `control_ca` with no allowlist. `spikeInitCmd` only rejects a second init of the same directory (`config.json` already present). It does not reject a second directory. `dns_server` is stored if it is non-empty. `zoneRE` is the only stated guard on `/etc/resolver/<zone>` and on `resolvectl` arguments, and it is not in the files under review, so path safety is not shown. `filepath.Join("/etc/resolver", z)` drops the prefix when `z` is absolute, so a zone of `/etc/passwd` would write that path as root if `zoneRE` ever lets it through.

**T3. REAL requirement, no channel yet.** The spike has no join/leave socket. The only local API is `GET /status`. Building an unauthenticated CLI socket later would make this bug. It is not a bug in this tree.

**T4. REAL for every local process. The browser half is narrower than written.** `/status` has no authentication and no `Host` check. The JSON includes every zone, the node's own mesh addresses, the error string, and `pool.snapshot()`. The snapshot is `synthetic → mesh IP (zone)`, not hostnames, so "which pen hosts exist" overstates it: it is the mesh addresses someone has already resolved, plus the node's own addresses. Default bind is `127.0.0.1:19819`. `--status-addr` is passed straight to `net.Listen`, so `0.0.0.0:19819` is a LAN exposure if that flag survives. Chrome 142 (2025-10-28) Local Network Access gates public pages that target loopback, which blunts DNS rebinding to `127.0.0.1` in current Chrome. The missing `Host` check still matters for any client that does not enforce that, and for the synthetic-address path in the missed attacks below.

**T5. REAL.** The `/16` route and `/etc/resolver` file are system-wide. Any uid, and any sandboxed app the kernel will route, uses the member's pen identity. Same property as a VPN. Side-by-side had it only for clients of `127.0.0.1:<proxy>`.

**T6. REAL for the way the spike is run. The path is not hardcoded.** State is `filepath.Join(dir, "node")` inside `newNode`. Pass `/tmp/spike-*` as root and a user who owns or can replace that directory can symlink `node` at a sensitive path before `tsnet` writes `tailscaled.state`. Cleanup-on-crash is not the issue. Following a symlink as root is.

**T7. OVERSTATED.** Simultaneous two-pen MITM is not what this process does. `spikeTunCmd` keeps `byZone` and returns `duplicate pen zone` before any TUN is created. `matchZone` never has to choose. What is real, and weaker:

- `spike-init` calls `installTrust` before any cross-directory zone check. A second directory with the same zone still installs a second root.
- The duplicate check is case-sensitive (`byZone[p.cfg.Zone]`). `matchZone` and the bridge zone list lowercase. `Farm.hogman` and `farm.hogman` both pass if `zoneRE` allows both. Lookups then use the lowercased key, so `byZone["farm.hogman"]` hits whichever entry was stored under that exact string and ignores the other node.
- Two roots in the OS trust store survive after the daemon refuses to start. That is latent trust, not a live split of `matchZone`.

Name constraints on a root used as a trust anchor are not a fix. RFC 5280 constraints apply to intermediates, and `AppendCertsFromPEM` does not attach a Go constraint function.

**T8. REAL. This is the serious one.** The forward path stores the pen's answer with no check:

```go
ordered := orderIPs(ips)
synthIP, err := b.pool.alloc(zone, ips[0])
// dialFn:
return node.Dial(dctx, network, addr) // addr is meshIP + the client's port
```

`orderIPs` keeps every parseable address and only prefers IPv4. `127.0.0.1`, `192.168.0.1`, `169.254.169.254`, and `::ffff:127.0.0.1` all win if they are the first IPv4 (or the only address).

`tsnet.Server.Dial` is `dialer.UserDial`. In current `tsnet` (main, 2026-11-20), `UseNetstackForIP` is `LocalBackend.PeerForIP`. That is true for a known peer address or an accepted subnet route, and false otherwise. `tsnet` does not call `Dialer.SetRoutes`, so `routes` stays nil. `dialOneUser` then uses a plain `net.Dialer` for anything `PeerForIP` rejects. The package comment says Dial stays on the tailnet. The code does not. A loopback or LAN address is dialed by the root process on the host stack. The TCP payload is whatever the local client sent, on whatever port the client used. `dns_server` in `config.json` has the same hole, fixed to port 53, because the resolver dial is `node.Dial(DNSServer:53)` and `spike-init` never checks that field against `100.64.0.0/10` or `fd7a:115c:a1e0::/48`.

The side-by-side agent is not a counterexample. `agent.dial` checks `inMeshRanges` only when the request host is already an IP. After `LookupHost` it still calls `dialMesh` on every answer. Same logic hole, user privileges, proxy clients only. This design makes it root and system-wide.

A mesh-range check is the minimum. `PeerForIP` of that pen's node is the right check. `Unmap()` before the check, or `::ffff:127.0.0.1` skips an `Is4()` test.

**T9. REAL, wrong mechanism, overstated effect.** The map key is `(zone, answer string)`, not the queried name. A wildcard that always returns one mesh address allocates one slot. Exhaustion needs distinct answer strings. For the default `/16`:

- `hostSpan = 1 << 16 = 65536`
- `maxIdx = 65536 - 258 = 65278` candidates, `198.19.1.1` through `198.19.255.254`
- skipped `.0` and `.255` in that span: 254 + 254 = 508
- usable = 65278 − 508 = **64770**

One name whose answer changes every cache expiry (5 seconds) takes `64770 × 5 = 323850` seconds, about 90 hours, to fill the pool. A script that resolves distinct names, each with its own answer, fills it in one pass. When it is full, new names in every pen get `SERVFAIL`. Names already mapped keep working. "Denying access to all their pens" is too strong. Memory of the pool is capped near 65k entries.

The hostname cache is the unbounded object. `spikePen.cache` is replaced on refresh and never deleted, and the 5-second expiry only stops reuse. Distinct names to one stable address grow that map without bound. A hostile page or a local loop can do that without filling the pool.

**T10. REAL, and stronger than written.** `installCombinedControlCAs` sets `GODEBUG=x509usefallbackroots=1` and then `x509.SetFallbackRoots(pool)`. Go's `godebug` cache follows `os.Setenv` of `GODEBUG`. `SetFallbackRoots` records `useFallbackRoots` when that value is `"1"`. On the first TLS verification, `initSystemRoots` then replaces the system pool with the fallback pool (`src/crypto/x509/root.go`). On macOS that also drops the platform verifier. The daemon no longer trusts public CAs. It trusts only the joined pens' control CAs, for every TLS dial in the process: other pens' control hosts, DERP, logtail. Any one test pen's CA can authenticate as any other server, once the TCP connection can be steered (hostile LAN, DNS for the control hostname). A publicly trusted control server fails closed instead, so one test pen in the process breaks production pens that use a public cert. Name constraints on the root do not save this. The side-by-side `trustControlCA` has the same pattern, scoped to one process that only speaks for one pen.

**T11. The exposure named here is absent.** The spike never calls `node.Listen`, `ListenFunnel`, `ListenService`, or `forwardPort`. `198.19.0.0/16` is a host route to the local TUN, not a route advertised into the pen. Mesh packets land in tsnet's own netstack, which has no application listener. The existing agent does listen, and only when `st.Self` carries `tag:server`, then forwards pen ports 80 and 443 to `127.0.0.1`. Personal devices in the spike do not. Residual: a stock `tsnet.Server` still runs magicsock and peerapi. `RunWebClient` and `Loopback` are off unless something calls them. The spike does not.

**T12. REAL, and the synthetic map makes it worse than a normal VPN.** Any app, not only a PAC browser, will resolve `*.<zone>` and connect. The stub has no allowlist. `matchZone` is a suffix test. Embedding `https://x.farm.hogman/` is enough for the browser to send the member's pen identity. Pen sites need their own CSRF checks. That part is right. The part the model misses is below: the browser never sees the real answer address, so its private-network checks see `198.19.x` instead.

**T13. REAL on macOS. OVERSTATED on Linux.** Darwin cleanup removes only the files this process wrote, and only on a normal return. `kill -9` skips every `defer`. The utun disappears with the process. `/etc/resolver/<zone>` does not, and startup does not sweep leftovers. A file left behind points at `198.19.0.53`, which no longer exists. Scoped-resolver timeout followed by the primary resolver is reported behavior (the Homebrew dnsmasq `/etc/resolver` report, 2026-11-19: timeout, then the router). I did not find an Apple guarantee. The test below is the decider. The file also survives a "leave" that this spike does not implement. On Linux, `resolvectl domain <if> ~zone` plus `default-route false` keeps non-matching names off this link, and `FallbackDNS` is not used while any DNS server is configured (systemd issue 33865, Lennart Poettering, 2024-07-29). `kill -9` destroys `hogman0`, and resolved drops per-link config with the interface. Linux fails closed more by accident of interface lifetime than by an explicit policy.

**T14. REAL, with a bad example.** Nothing reads the routing table before `route add` or `ip addr replace`. Default `198.19.0.0/16` is the upper half of RFC 2544 `198.18.0.0/15`. Clash/mihomo's usual fake-ip default is `198.18.0.1/16`, which does not overlap `198.19.0.0/16`. A tool or network that holds the whole `/15` does overlap, and the spike's more-specific `/16` wins, so their `198.19` traffic is stolen into the TUN and dies unless it hits a mapping. An existing more-specific route the other way steals pen traffic out of the TUN. `--subnet` accepts any IPv4 `/8` through `/22`, including RFC 1918. Exact `route add` failure is fail-closed. Overlap with a covering prefix is not.

**T15. WRONG as an exposure finding for the three things named.** The stub is not a host socket. It only sees packets the kernel writes to the TUN, and the kernel route is the synthetic prefix. Status defaults to `127.0.0.1`. The gVisor stack has no host listener. Forwarding is off by default, and the TUN address is not proxied on the physical NIC, so café Wi-Fi does not get to inject. Two holes sit next to this and are easy to miss. `--status-addr` can bind a non-loopback address. tsnet's WireGuard UDP socket listens on all host interfaces (`Port` defaults to 0, ephemeral, `0.0.0.0`). That is ordinary Tailscale, and it is on the LAN.

## What the packet path actually does

`SetPromiscuousMode`, `SetSpoofing`, and the netstack default route are not a host-wide tunnel. The host route is only the synthetic prefix (`route add -net` on macOS, the connected route from `ip addr replace local/prefix` on Linux). Promiscuous mode is what lets the forwarder see packets for `198.19.1.1` and the rest, which are not assigned to the NIC. Spoofing is what lets the reply use that address as its source. The `0.0.0.0/0` route exists only inside gVisor. Replies go back out the TUN. The host's default route is untouched.

Unmapped destinations are reset (`handleTCP` → `Complete(true)`) or dropped (`handleUDP` returns false). They are not dialed. ICMP echo is enabled (`icmp.NewProtocol4`) with no handler. In promiscuous mode gVisor answers echo requests for addresses it does not own, so ping of any address in the prefix gets a reply from the root process. That confirms the prefix is alive. It is not a pivot. Fragments are reassembled by gVisor with its own limits. A local sender can aim a fragment set at a root parser. That is residual attack surface of doing TCP in-process as root, not a bug I can point at in this code.

`handleTCP` dials upstream before `CreateEndpoint`. A SYN to a mapped address is enough to make root open the upstream connection. The in-flight cap is 1024 (`tcp.NewForwarder(s, 0, 1024, ...)`).

## Missed

**Browser pivot through the synthetic range.** The stub never returns the pen's A record. The browser connects to `198.19.x`, which it resolved itself. The WICG Local Network Access table lists `198.18.0.0/15` as loopback. Chrome's `ip_address_space_util.cc` does not, and Firefox bug 1980302 (patch discussion about 11 months before 2026-11-20) changed Firefox to stop treating it as local so it would match Chrome. A public page can load `http://evil.farm.hogman:18080/` and the browser will not treat the destination as loopback or RFC 1918. The root daemon then dials whatever the pen answered, including `127.0.0.1` and LAN addresses, and copies the client's bytes. Sandboxes that are allowed to open "public" sockets and forbidden to open localhost still get localhost. A raw Redis payload does not survive a browser. An unauthenticated HTTP API on localhost or on the LAN router does. Any unsandboxed local process sends arbitrary TCP and UDP.

**`dns_server` is an SSRF field at join.** Attacker 2 sets it in the network document. `spike-init` stores it. Every lookup dials it via `node.Dial`. Port 53 only. Still root, still the host stack if `PeerForIP` misses.

**One shared pool and one shared trust store across pens.** Data-plane isolation is better than the model fears: `dialFn` indexes `byZone[zone]` from `matchZone`, so pen A cannot make the stack dial through pen B's node. Trust, memory, and the status document are shared. One pen's control CA is a trust anchor for the other pen's control TLS. One pen's distinct answers fill the pool for every pen. `/status` lists every zone.

**Node private key and auth key are same-user readable.** `newNode` stores state under `<dir>/node`. `authkey` is mode `0600` in that directory and is removed only after `Up` succeeds. Malware running as the member reads the key before `Up`, or copies `tailscaled.state` after it, and clones the pen identity. Another unix user cannot, if the directory is `0700`. Attacker 1 includes same-user malware. T6's symlink story is the cross-user version of the same directory.

**Predictable addresses.** Pool start is `base+257` (`198.19.1.1` for the default) and `nextIdx` walks upward, skipping `.0` and `.255`. A page that can cause lookups can also probe `198.19.1.1` upward. The status map makes the probe unnecessary for any local process.

**NXDOMAIN on a live failure.** Once `penUp` is set, a timeout or a non-`IsNotFound` resolver error is still packed as `RCodeNameError`. macOS negative-caches that. A pen that stalls DNS for one name can pin a lie that the name does not exist.

**Darwin startup does not adopt or reject foreign resolver files except by the marker.** A second process whose file already has the marker overwrites it (`os.WriteFile` after the marker check). Two spike processes on the same zone, the duplicate check is per process, so the later one steals `/etc/resolver/<zone>` and points it at its own TUN. Combined with two routes for the same prefix, this is a local race, not a remote one.

**Linux DNS is installed in the wrong order.** `resolvectl dns` runs before `resolvectl domain ~zone` and `default-route false`. systemd's own VPN notes say a DNS server without a routing domain is eligible as a default resolver. There is a window at startup where public queries can hit the stub. The stub REFUSEs names outside its zones, so this is a glitch and a possible race to the real resolver, not a pen-name leak. `dnssec no` is best-effort (`_ = runPrivileged`). If it fails, resolved rejects the stub's unsigned answers and pen names fail closed.

**No update story.** The spike has none. A root service that later downloads a new binary and execs it inherits T1. The current project install line is `curl | sudo bash`. That is outside this diff and it is the integrity problem to close before this becomes the only join path.

**gVisor as root is the trust boundary.** Every local process can send IPv4 at the prefix. A bug in fragment reassembly or TCP state in the linked gVisor is local root. Pin the module and treat packet parsing as the boundary.

## Five attacks and the test that decides each

**1. Hostile pen DNS, root dials the member's LAN and loopback.**

Who: keeper of a pen the member already joined (attacker 2). No local malware.

Steps: Publish `evil.<zone>` A `127.0.0.1` and A `192.168.1.1` for `router.<zone>`. From the member's browser, load `http://evil.<zone>:18080/` and `http://router.<zone>:80/`. The OS resolver hits `198.19.0.53`. The stub allocates `198.19.1.1` and `198.19.1.2`. The browser connects there. `handleTCP` calls `node.Dial("tcp", "127.0.0.1:18080")` and `node.Dial("tcp", "192.168.1.1:80")`. `PeerForIP` misses both. The plain dialer connects on the host. Bytes from the page are written to the local service.

Result: an unauthenticated localhost or LAN HTTP service sees a request the member's browser was not allowed to send directly. A local unsandboxed process does the same with a raw payload to any port, including ports Chrome blocks.

Test, on the spike, no browser required: listen on `127.0.0.1:18080`. Point the pen DNS (or a test double of `lookupFn`) at `127.0.0.1` for `evil.<zone>`. Query the stub, connect to the returned synthetic address on port 18080, send `hello\n`. Pass condition for the attack: the listener accepts and reads `hello\n`, and `RemoteAddr` is `127.0.0.1`, not the test client. Refute condition: the stub returns `SERVFAIL` or the TCP dial never reaches the listener. Repeat with answer `192.0.2.1` (TEST-NET-1) and a packet capture on the default NIC: a SYN refutes "Dial stays on the tailnet". Repeat with answer `::ffff:127.0.0.1`. Repeat with a real peer `100.64.x`: that one must still connect over the pen, or the fix is too wide. Also set `dns_server` to `127.0.0.1` and confirm a lookup opens TCP/53 to loopback.

**2. One test pen's CA becomes the only root, then a café network steers another pen's control connection.**

Who: attacker 2 who got a test pen joined in the same process as a second pen, plus attacker 5 on the LAN (or the same person).

Steps: Pen A is joined with `--control-ca`. `installCombinedControlCAs` runs. Pen B's `login_server` is a hostname the member's OS resolves on the host network. On the café LAN, answer that hostname with the attacker's address and present a certificate signed by pen A's CA. The daemon's verifier no longer has the public roots. Pen A's CA is enough.

Result: attacker speaks the control protocol to pen B's node, which is running as root inside the member's daemon. Netmap, routes, and node identity for pen B are in play. If pen B's real certificate is publicly trusted and the attacker cannot steer TCP, pen B simply fails to connect. That availability break is the same bug.

Test: call the same `installCombinedControlCAs` path, then `x509.Verify` a leaf signed only by that CA for a name that is not the control host (`derp.example`), with no `Roots` override. Pass for the attack: verify succeeds. Second leaf, signed by a normal public CA: verify fails. That pair shows replacement rather than fallback. Full chain: run pen B's control URL at a local TLS server whose certificate is signed by pen A's CA and see whether `node.Up` reaches `Running`.

**3. Same-user malware copies the node key, or a second local user symlink-plants it.**

Who: attacker 1.

Steps, same user: between `spike-init` and `Up`, read `<dir>/authkey`. After `Up`, copy `<dir>/node/tailscaled.state`. Start another `tsnet` with that store and the pen's control URL. Steps, other user, if the daemon is root and `dir` is under `/tmp`: replace `<dir>/node` with a symlink to a root-owned path the attacker wants created or truncated, then start the daemon.

Result: a second device wears the member's pen identity, or root writes through the symlink.

Test: mode and owner assertion before `start` — refuse the directory unless it is root-owned, mode `0700` or tighter, and not a symlink (`Lstat`). Positive test: user-owned `0700` directory must fail closed when the process is root. Symlink test: `node` → a scratch directory, start, assert no file appears in the scratch directory. Auth-key test: a reader in the same uid can read `authkey` today; after the fix, the file is root-owned `0600` and the reader gets `EACCES`.

**4. One pen fills the shared pool, or the hostname cache, for every pen.**

Who: attacker 2, or attacker 4 feeding unique names if the pen DNS returns unique answers (a wildcard that echoes the query into a generated address).

Steps: answer `n<i>.<zone>` with `100.64.0.0/10` addresses, one per name, for 64771 names. Query each through the stub once.

Result: query 64771 is `SERVFAIL` for a name in a second, innocent pen. Mappings from the first 64770 still answer. Memory stays bounded. Separate run: 200000 distinct names, all answered with the same `100.64.0.5`. The pool length stays 1. `spikePen.cache` length stays 200000 after the 5-second TTL, because expiry does not delete.

Test: drive `handleSpikeDNS` in-process with a fake `lookupFn`. Assert allocation 64770 succeeds and 64771 returns `RCodeServerFailure`, and that a name resolved at the start still returns its old synthetic address. Second assertion: equal answers do not grow `len(pool.byIP)`, and `len(pen.cache)` grows with distinct qnames with no ceiling. A fix (cap per pen, delete expired cache entries, reject non-peer answers) fails this test in the other direction: the 64771st distinct peer address may fail, and a non-peer answer must fail on query 1.

**5. macOS leaves the zone file behind and the next lookup leaves the machine.**

Who: nobody remote has to be clever. Crash, `kill -9`, or a power loss. Attacker is whoever receives the member's ordinary DNS (attacker 5's resolver, or the ISP).

Steps: join so `/etc/resolver/<zone>` exists and starts with the marker. `kill -9` the process. Confirm the utun is gone and the file is still there. Resolve `secret-host.<zone>` with `dscacheutil` or an app that uses `getaddrinfo` (not `dig`, which ignores the scoped resolver). Capture UDP/53 on the physical NIC.

Result, if the fallback is real: the qname `secret-host.<zone>` is in a query to the LAN/ISP resolver. The pen name and the host label leave the machine. Linux counterpart, same kill: `resolvectl` no longer has `~<zone>` on `hogman0`, and a capture on the physical NIC shows no query, or the test fails.

Test is that capture. Pass for the threat: one query, qname visible, sent to the non-TUN resolver, file still present. Refute: `getaddrinfo` fails and the capture is empty. The startup sweep is the other half: plant a marker file for `old.<zone>` before start and assert the new process deletes it when `old.<zone>` is not in the argument list.

## What is fine

Duplicate zones in one process are rejected. The dial target's pen is the zone that matched the name, not a zone encoded in the answer. The synthetic prefix is not routed back into the mesh. Default listeners are not on the physical NIC. Linux split DNS uses `~zone` and `default-route false`, so this link is not a search domain and not the default resolver once setup finishes. The netstack default route does not move the host default route. Side-by-side's proxy allowlist (`inZone` / `errOutside`) is the right policy. This spike drops it on the way to becoming the system path.
