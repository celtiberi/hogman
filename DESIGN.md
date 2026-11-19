# Hogman: a deployable private internet

Status: build steps 1–4 (core stack, registrar, removal, join tool) are in [core/](core/) and pass their end-to-end test. Steps 5 onward are partly built: a minimal join page exists; the portal UI and phones do not. Not yet built from step 7: webhooks, the invite-tree cascade.

## 1. What this is

Hogman is a stack that one person (the **owner**) deploys to run their own private internet. They decide who gets in. Once inside, members browse sites, host sites and run services the same way they do on the public internet, using stock browsers and stock tools. Nothing inside is reachable or visible from outside.

Each deployment is one sovereign **network** with its own name, its own DNS, its own certificate authority and its own member list. Example used throughout: a network called `bobo`, whose names all end in `.bobo.hogman`.

### Goals

- One command deploys a whole network on a single small server.
- Members join in one step and then use stock software (browser, git, curl, anything).
- Any member can claim a name and host a site with automatic HTTPS.
- The owner controls admission and can remove anyone, effective within seconds.
- No dependency on a third party after setup, apart from the one public hostname in section 4.

### Non-goals (for now)

- Day-one content. The network starts empty; this is the backbone.
- Federation between networks.
- Anonymity between members or from the owner. This is a private network, not an anonymous one.
- A custom browser. A possible later convenience for phones, not part of this design.

## 2. Roles

| Role | Can do |
|---|---|
| **Owner** | Everything: deploy, set policy, mint invites, remove anyone, appoint admins. Holds the CA root key. |
| **Admin** | Mint and revoke invites, suspend and remove members. Cannot remove the owner or touch the CA. |
| **Member** | Join devices, claim names, run servers. May mint invites if the owner enables that. |

## 3. Architecture

```
                 PUBLIC INTERNET
   ┌──────────────────────────────────────────┐
   │  join.example.com   (invite page, bundle) │   one public hostname,
   │  hs.example.com     (Headscale control)   │   public cert
   └───────────────────┬──────────────────────┘
                       │
 ┌─────────────────────┴───────────────────────────────────────┐
 │  CORE NODE (one VPS, docker compose)                         │
 │                                                              │
 │  Headscale ........ mesh control plane + embedded relay      │
 │  Registrar ........ members, invites, names, kick (custom)   │
 │  CoreDNS .......... authoritative for bobo.hogman            │
 │  step-ca .......... the network's CA, speaks ACME            │
 │  Caddy ............ fronts the public hostname and the       │
 │                     in-mesh portal (home.bobo.hogman)        │
 └─────────────────────┬───────────────────────────────────────┘
                       │  WireGuard mesh (100.64.0.0/10)
        ┌──────────────┼──────────────────┐
        │              │                  │
   member laptop   member phone     member SERVER
   (no inbound)    (no inbound)     (tagged, reachable,
                                     alice.bobo.hogman)
```

### Components

| Component | Software | Job |
|---|---|---|
| Mesh control | Headscale | Device registration, key exchange, pushes DNS settings and access policy to every device. |
| Relay | Headscale's embedded DERP | Relays traffic for devices that can't connect directly. Set to serve only known devices. |
| Mesh client | Stock Tailscale client | Runs on every member device and server. |
| DNS | CoreDNS | Answers for `*.bobo.hogman` from records the registrar writes. |
| CA | step-ca | Issues certs for `*.bobo.hogman` over ACME, the same protocol Let's Encrypt uses. |
| **Registrar** | Custom (the main thing to build) | Source of truth for members, devices, invites and names. Drives Headscale, CoreDNS and step-ca. Exposes the owner's admin API and CLI. |
| **Join tool** | Custom, small | Run once per device: joins the mesh and installs the network's root cert. |
| Portal | Part of the registrar | `home.bobo.hogman`: claim names, manage devices, list what exists. |

Only the registrar and join tool are new code. Everything else is configured, not written.

## 4. The one public foothold

A device has to reach the control plane before it is on the mesh, so the control plane needs an address on the public internet with a cert that stock clients already trust. The owner therefore needs **one public hostname** (any cheap domain or a free subdomain) pointing at the core node. It serves two things only:

- Headscale's control endpoint.
- The invite page and join bundle.

This hostname is plumbing. Members never type it; it is embedded in the invite link. Everything members actually use lives under `.bobo.hogman`.

Public ports on the core node: 443/tcp, 80/tcp (public cert renewal), 3478/udp (relay discovery).

## 5. Naming

- Network zone: `bobo.hogman`. CoreDNS on the core node is authoritative for it.
- Headscale pushes a split-DNS rule to every device: queries for `bobo.hogman` go to CoreDNS over the mesh; all other queries use the device's normal DNS. The owner never sees members' ordinary browsing.
- Device names live under `nodes.bobo.hogman` (Headscale's own device directory).
- Reserved names: `home`, `ca`, `registrar`, `search`, `nodes`.
- Member names are first come, first served: `alice.bobo.hogman`, plus anything under it (`blog.alice.bobo.hogman`). A name points at one of that member's servers.
- The owner can reserve, reassign or seize any name.

There is no global `.hogman` layer. `search.bobo.hogman` belongs to the `bobo` network only.

## 6. Certificates and trust

- At deploy time the stack generates a **root CA** for the network, restricted by name constraint to `.bobo.hogman`. It cannot sign for any other name, so installing it does not let the owner intercept members' other traffic.
- The root key is taken offline by the owner after setup. An online **intermediate** does day-to-day signing.
- step-ca exposes ACME at `ca.bobo.hogman`, reachable only on the mesh. A server proves it controls a name by answering a challenge at the address DNS gives for that name. Since the registrar controls DNS, **owning a name in the registrar is what entitles you to a cert for it.**
- The zone restriction is enforced by the name constraints in the root and intermediate certificates, not by step-ca's own policy settings: step-ca's policy can only match one label under a wildcard, so it cannot allow `blog.alice.bobo.hogman`. The core test signs a `www.google.com` cert directly with the intermediate key and confirms it fails verification.
- The CA runs on its own mesh address, separate from the portal, since both serve port 443.
- Certs are short-lived (7 days, auto-renewed). Short lifetime is the revocation mechanism: a removed member's certs simply expire.
- Hosting a site is: join a server, claim a name, run Caddy pointed at `ca.bobo.hogman`. HTTPS is automatic from there.

### Trust install per platform

| Platform | Step | Result |
|---|---|---|
| macOS, Windows, Linux | Join tool adds the root; one admin prompt | Browsers, git, curl and most apps work |
| iOS | Install a profile, flip one switch in Settings | Safari and most apps work |
| Android | Install the cert in Settings | Browsers work; most third-party native apps don't |

Java, Node and Python keep their own cert bundles and need an environment variable pointing at the root. The portal documents this.

## 7. Admission ("the velvet rope")

Deciding who deserves entry is the owner's business. Hogman supplies the mechanism and a replaceable reference invite page; the owner builds whatever admission process they like in front of it (application form, vouching, credential check).

**Primitive: the invite token.** Single use, expiring, minted through the registrar API.

```
POST /invites            -> { token, url, expires }
DELETE /invites/{token}  -> revoke before use
GET  /invites            -> outstanding and redeemed, with who minted each
```

The registrar records **who invited whom**. That invite tree is what makes removal meaningful (section 9).

### Join flow (desktop)

1. Applicant passes the owner's admission process and receives an invite link. The link carries the token and the fingerprint of the network's root cert.
2. They run the join tool with the link.
3. The tool redeems the token. The registrar creates the member, creates their Headscale user and returns a bundle: control address, root cert, a single-use device key.
4. The tool checks the root cert against the fingerprint from the link, installs it in the OS trust store, installs the Tailscale client if missing and joins the mesh.
5. The device now resolves and trusts `*.bobo.hogman`. The tool opens `home.bobo.hogman`.

Adding a second device or a server: the member requests another device key from the portal. Server keys carry the server tag (section 8).

*As built (core/join): the link is `https://<host>/join#t=<token>&fp=<fingerprint>`; the page it opens gives a one-line command that downloads `hogman-join` and runs it with the link. The tool also refuses a root that is not name-constrained to the network. It adds the root before redeeming, so a failed trust step leaves the invite unused, and joins with `tailscale login` as a separate profile so other tailnets survive. On macOS the trust step needs a person at the screen: macOS will not let even root set certificate trust without on-screen approval, so it cannot be done over SSH or by a background installer (device management can push the certificate instead).*

### Join flow (phones)

Same idea using the stock Tailscale app pointed at the network's control address, plus the cert install from section 6. The exact enrolment mechanics on iOS and Android are an open question (section 13).

## 8. Access policy

Default-deny, expressed in Headscale's policy file, which the registrar owns.

| Device kind | Inbound | Outbound |
|---|---|---|
| Personal device | Nothing | Core services and all servers |
| Server (tagged) | Anything from any member | Core services and other servers |
| Core node | DNS, HTTP, HTTPS from any member | n/a |

As built: Headscale runs in database policy mode and the **registrar generates the policy** from its ledger every few seconds, listing device addresses rather than tags (Headscale grants syntax):

```jsonc
{
  "tagOwners": { "tag:infra": [], "tag:server": [] },
  "grants": [
    // every active member's device, plus the core, may reach the core's DNS/HTTP/HTTPS
    { "src": ["<active device IPs>", "tag:infra"], "dst": ["tag:infra"], "ip": ["53", "80", "443"] },
    // ... and anything on every active member's servers
    { "src": ["<active device IPs>", "tag:infra"], "dst": ["<active server IPs>"], "ip": ["*"] }
  ]
}
```

Listing addresses gives two properties tags cannot: suspending a member is just leaving their devices out (instant and reversible, devices stay registered), and a device that joined around the registrar is in no rule and gets nothing.

- A device is only a server if the member asked the registrar for a server key. Laptops are never reachable by accident.
- Subnet routes and exit nodes are off. Members cannot route the network elsewhere.
- Tagged servers are not owned by a user inside Headscale, so the **registrar keeps its own ledger of which member owns which device.** Removal depends on that ledger.

## 9. Removing people

The owner (or an admin) must be able to take someone off the network quickly and completely. Three actions, from lightest to heaviest:

| Action | Effect | Reversible |
|---|---|---|
| **Revoke device** | One device is cut off. For a lost or compromised laptop. | Member can join a new device |
| **Suspend member** | All their devices and servers are cut off. Names and account are kept. | Yes, one command |
| **Kick member** | Everything is cut off and the membership ends. | Only by a fresh invite |

### What a kick does

`hogman member kick alice` runs these steps in order, as one operation in the registrar:

1. **Mark the member removed.** From this point the registrar refuses every request from them: no new device keys, no name changes, no invites.
2. **Revoke what they could still use.** Their unused device keys and any invites they minted that have not been redeemed.
3. **Delete every device they own** from Headscale, personal and server, using the registrar's ledger. Headscale pushes the change to all other devices, which drop the removed devices as peers. The relay refuses them too. This is the step that actually cuts them off.
4. **Delete their Headscale user.**
5. **Withdraw their names from DNS.** The names go into a hold period (default 90 days) so nobody can immediately impersonate a site members were used to trusting.
6. **Stop cert issuance.** No name, no cert. Existing certs expire within 7 days and are useless without network access.
7. **Fire a `member.removed` event** to any service that subscribed, so forums, chat and the like can disable that person's account.
8. **Write an audit record:** who was removed, by whom, when, with an optional reason.

Expected time from command to cut-off is seconds for online devices. That figure must be measured during the build, not assumed.

### The invite tree

Because the registrar knows who invited whom, a kick can optionally show or include everyone the removed member brought in:

```
hogman member kick alice              # alice only
hogman member tree alice              # show everyone downstream of alice
hogman member kick alice --cascade    # alice and everyone she invited, recursively
```

### What a kick cannot do

- **Recall data.** Anything they already copied, they keep.
- **Stop a determined return.** Someone else can invite them back under a new identity. The rope is social; the invite tree shows who let them in.
- **Reach offline devices instantly.** A peer that is offline learns of the removal when it reconnects. It cannot talk to the removed device while offline, so this is harmless.
- **Remove the root cert from their device.** It stays installed until they delete it. It is harmless: it only vouches for `.bobo.hogman`, which they can no longer reach.
- **Log them out of member-run services automatically,** unless that service listens for the removal event. A network-wide login service would close this gap (section 12).

### Protecting the owner

- The owner cannot be kicked or suspended by anyone.
- Admins cannot remove other admins; only the owner can.
- Every removal is in the audit log, visible to the owner.

## 10. What the owner can see and do

Members should be told this plainly when they join. The owner:

- Can see who is a member, what devices they have, when devices are online and which names exist.
- Can see DNS queries for `*.bobo.hogman` (which private sites a device looked up), but not other DNS.
- **Cannot** read traffic between members; it is encrypted end to end between devices.
- Can add devices, change policy and reassign names, so could impersonate a site inside the network if they chose to. Joining a network means trusting its owner.

## 11. Registrar

One service, one database (SQLite), one binary that is also the `hogman` CLI. Suggested language: Go, since Headscale, step-ca, CoreDNS and Caddy are all Go and expose usable client libraries.

### Data

| Table | Holds |
|---|---|
| `members` | id, handle, role, status (active, suspended, removed), invited_by, joined_at |
| `devices` | id, member_id, headscale_node_id, kind (personal, server), mesh_ip |
| `invites` | token hash, minted_by, expires_at, redeemed_by, revoked_at |
| `names` | fqdn, member_id, device_id, held_until |
| `audit` | actor, action, target, reason, at |
| `webhooks` | url, secret, events |

### API surface

| Area | Operations |
|---|---|
| Invites | mint, list, revoke, redeem |
| Members | list, show, tree, suspend, resume, kick, set role |
| Devices | list, issue key (personal or server), revoke |
| Names | claim, release, point at device, seize (owner) |
| Events | subscribe, list deliveries |
| Network | status, policy, export backup |

The owner-facing API is reachable only from the mesh, and only by owner and admin devices. The redeem endpoint is the single operation exposed publicly.

## 12. Later, not now

- **Search AI** (`search.bobo.hogman`). Optional module. Indexes from the registrar's name list plus a crawler. Must run a local model so queries never leave the network. Off by default.
- **Network login.** One account for every service inside the network, so a kick also ends app sessions.
- **Dedicated mobile app or browser** to remove the manual cert step on phones.
- **Real-domain mode.** For owners who prefer public certs and no root install, at the cost of hostnames appearing in public logs.

## 13. Open questions to settle by testing

1. **Name constraints on a user-installed root.** Confirm each platform (macOS, Windows, iOS, Android, Firefox) actually refuses a cert outside `.bobo.hogman` signed by the network's CA. *macOS: confirmed on 14.6 and 26.6 with Apple's own trust engine (`security verify-cert`, the engine Safari uses): names inside the zone, at any depth, are accepted; `www.google.com`, a look-alike `lab.hogman.evil.com` and an IP address are rejected. OpenSSL and Go: confirmed by the end-to-end test. Windows, iOS, Android, Firefox: still to test.*
2. **Phone enrolment.** How the stock Tailscale apps join a custom control server with a single-use key, and whether that needs a web login flow on the control server instead.
3. **Kick latency.** Measure time from kick to loss of connectivity for direct and relayed connections. *Real Mac mini on a LAN, direct connection: suspend 2.0 s, resume 0.8 s, kick 2.1 s. Local test measurements: removing one device by deleting it, 6–7 seconds; suspending a member, 3–5 seconds; kicking a member, 3 seconds (the policy change lands before the device deletions). Still to measure on a real public server, over the relay, and with real NAT.*
4. **Headscale version specifics.** Policy syntax, tagged-device ownership and the user-deletion behaviour differ between releases; pin a version and verify.
5. **Whether the public hostname can be avoided,** for example with a cert issued to a bare IP address.
6. **Belonging to two networks.** *Resolved by side-by-side mode (core/join): the join tool can run its own embedded connection (tsnet) with a local proxy for pen names only, leaving the device's Tailscale alone. Proven on a Mac that stayed on another tailnet throughout. The cost: only apps that use the proxy reach the pen (browsers via a PAC file; curl, git, ssh with one line of config). The whole-device way still switches Tailscale profiles.*

## 14. Operations

- **Size:** one small VPS handles a network of hundreds of devices. Headscale is single-instance; there is no high-availability mode.
- **If the core node is down:** existing direct connections keep working for a while; new connections, joins, DNS for `.bobo.hogman` and cert renewals stop.
- **Backups:** Headscale database, registrar database, CA intermediate key and config. The root key is kept offline by the owner. Losing the root key means every member must install a new one.

## 15. Build order

1. **Core stack:** compose file with Headscale, CoreDNS, step-ca, Caddy. Manually join two devices, resolve a name, serve a site with a cert from the CA.
2. **Registrar, minimum:** members, invites, device keys, name claims, writing DNS records and policy.
3. **Removal:** revoke, suspend, kick, audit log, with the latency measurement from section 13.
4. **Join tool:** desktop first.
5. **Portal and reference invite page.**
6. **Phones,** once question 2 is answered.
7. **Events, invite tree cascade, admin role.**
