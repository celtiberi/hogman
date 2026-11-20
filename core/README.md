# Hogman core node

Build steps 1–4 from [DESIGN.md](../DESIGN.md): the backbone of one private network,
its registrar, and the join tool, deployable with one command on a small server.

| Service | Image | Where it is reachable |
|---|---|---|
| `headscale` | Headscale 0.29.7 | Behind `edge` (or shared front door); STUN on udp/3478 |
| `edge` | Caddy 2.11.9 | Standalone installs only: public `https://<PUBLIC_HOST>` (behind `hogman-host`, the shared front door serves these routes directly) |
| `core-mesh` | Tailscale 1.104.7 | Mesh identity `core` (tag:infra) |
| `portal` | Caddy 2.11.9 | `https://home.<network>.hogman`, mesh only; fronts the registrar's API |
| `registrar` | built from [registrar/](registrar/) | Owns members, invites, devices, names, policy, and authoritative DNS (`core` mesh IP, port 53) |
| `step-ca` | step-ca 0.30.2 | `https://ca.<network>.hogman:9000`, mesh only (`core` mesh IP); ACME |

Not built yet: a portal UI (the portal API exists), a way to earn an invite (that part
is yours to build), mobile enrolment, webhooks, the invite-tree cascade.

## Deploy

On a Linux server with Docker, ports 80/tcp, 443/tcp and 3478/udp open, and a DNS A
record for your public hostname pointing at it:

```bash
cp .env.example .env      # set NETWORK, PUBLIC_HOST, PUBLIC_IPV4
./hogman init             # creates the network's CA; prints its fingerprint
./hogman up
./hogman member add <you> --role owner
./hogman device key <you> personal   # open the link it prints on your laptop to join (first device only)
```

`init` leaves the root key in `data/pki/offline/`. Once the network works, move that
folder offline and delete it from the server.

## Invite people

```bash
./hogman invite create --note "alice from the department"     # single use, 7 days
./hogman invite create --role admin --ttl 48h
./hogman invite list
./hogman invite revoke <id>
```

Each invite prints a link like `https://<PUBLIC_HOST>/join#t=…&fp=…`. Send it however
you like. Opening it shows a page with one command to copy into a terminal:

```bash
curl -fsSLo hogman-join "https://<PUBLIC_HOST>/join/dl/hogman-join-$(uname -s)-$(uname -m)" \
  && chmod +x hogman-join && ./hogman-join '<the link>'
```

The join tool ([join/](join/)) then:

1. fetches the network's root certificate and checks it against the fingerprint in the
   link; refuses if they differ, or if the root is not limited to the network's names;
2. adds the root to the computer's trust store (asks for the password once);
3. redeems the invite, asking the person to choose their handle;
4. joins with the installed Tailscale client **as a separate profile**, so any other
   Tailscale network is kept (`tailscale switch --list` to go back);
5. checks `https://home.<network>.hogman` loads using only the computer's own DNS and
   trust store, exactly as a browser would, and opens it.

**Two ways in, chosen automatically.**

- *Whole device:* if Tailscale is installed and not in use, the tool joins with it, and
  every app on the device can reach the pen.
- *Side by side:* if Tailscale is missing, or already on another network, the tool
  runs its own small connection (Tailscale's embeddable library, no network interface,
  no admin rights) and a local proxy that carries **only** names in the pen. The
  computer's Tailscale and everything else are left alone, so a member can be in a pen
  and on their own tailnet at once. Browsers use it through a proxy rules file the tool
  serves; curl, git and ssh need one line of proxy config, which the tool prints.
  Force it with `--alongside`; force the whole-device way with `--switch`. On a shared
  multi-user computer, note that any local user on the machine can connect to that
  loopback proxy on `127.0.0.1`.

Trust is added before the invite is redeemed, so if that step fails the invite is still
unused. More devices: each member adds their own from the home page (`POST /api/devices`), which
prints a device link for the same tool. Nobody can make one for someone else: there is no
account recovery. `hogman-join leave '<link>'` removes
the certificate and logs out.

Built for macOS (Apple silicon, Intel), Linux (x86-64, ARM64) and Windows (x86-64).
Tested end to end on Linux (containers) and on a real Mac mini (macOS 14.6, Homebrew
Tailscale) joining a network hosted on another Mac over the LAN: invite redeemed, two
approvals on screen, joined as a second Tailscale profile, Safari and system curl trusted
the portal, ordinary browsing unaffected; then `leave` removed the certificate and the
saved profile. Side-by-side mode:
tested end to end on Linux with no Tailscale installed, and on the Mac mini while it
stayed on another tailnet: both networks worked at the same moment, and a kick cut the
pen off in 1.8 s without disturbing the tailnet. Not yet exercised on a Mac: the login
item that restarts the agent, and setting the system's automatic proxy (both were
switched off for the remote test). Windows: compiled only.

**macOS needs a person at the screen.** macOS only lets someone approve a new trusted
certificate on screen, even for an administrator, so the tool must run in Terminal on the
Mac itself. Over SSH it stops before using the invite and explains this. Managed Macs can
receive the certificate from device management instead; then run with `--no-trust`.

How people earn an invite is up to you. Build whatever page or process you like in
front of `invite create`.

## Members' API (on the mesh)

Every request to `https://home.<network>.hogman/api/` is identified by the mesh
address it comes from. No passwords: a device is its owner's identity.

| Request | What it does |
|---|---|
| `GET /api/me` | Your membership, devices, names, invites |
| `POST /api/devices {"kind":"personal"\|"server"}` | One-time key and join link for another device |
| `DELETE /api/devices/{id}` | Remove one of your devices |
| `POST /api/names {"name":"alice","device_id":3,"note":"..."}` | Claim a name (with optional note) for a server |
| `DELETE /api/names/{name}` | Release a name and everything under it |
| `GET /api/directory` | Every site on the network, its owner and note |
| `POST /api/invites` | Mint an invite (admins; members if `MEMBERS_CAN_INVITE=true`) |
| `GET /api/admin/members`, `/devices`, `/invites`, `/audit` | Admins |
| `POST /api/admin/members/{handle}/suspend\|resume\|kick\|role` | Admins |

Names: first come, first served. Owning `alice` gives you everything under it
(`blog.alice`); nobody else can claim there. Names point only at servers, since
personal devices accept no connections. Reserved: `home`, `ca`, `ns`, `nodes`,
`registrar`, `search`, `www`, `join`, `admin`.

## Remove people

```bash
./hogman device rm <id>                 # one device (lost laptop)
./hogman member suspend bob [reason]    # cut off everything, keep the account; reversible
./hogman member resume bob
./hogman member kick alice [reason]     # end the membership
./hogman audit
```

A kick, in order: marks the member removed; drops their devices from the access
policy (this is the moment they lose access); revokes their unused device keys and
open invites; deletes all their devices from the mesh; deletes their Headscale user;
takes their names out of DNS and holds them for 90 days (`NAME_HOLD`) so nobody can
impersonate their sites; writes the audit record.

Nobody can suspend or kick the owner. Only the owner can suspend or kick an admin.

## How access works

The registrar owns the Headscale access policy (Headscale runs in database policy
mode). Every few seconds it rebuilds it from the ledger:

- Devices of **active** members may reach the core (DNS, HTTP, HTTPS) and every server.
- Personal devices accept nothing.
- Devices of suspended or removed members appear in no rule, so they reach nothing.
- Devices that joined **around** the registrar (a key minted directly in Headscale)
  are not in the ledger and get no access. They are logged.

## Test locally

Needs Docker and jq. Plays out a small network's life: invites redeemed from "the
internet", devices joining, a server and its names, a device sneaking in around the
registrar, a suspension and a kick.

```bash
test/run.sh            # add --keep to leave it running
```

Also covers the join page and downloads, and the join tool on two fresh Linux machines
with only Tailscale installed: a tampered link refused before the invite is used, a full
join, a second device via a device link, and leaving.

Plus side-by-side mode on a machine with no Tailscale at all.

About six minutes. Last result: **105 passed, 0 failed** (Docker Desktop on macOS, arm64).
Suspension cut access in 3–5 seconds; resume restored it within 2 seconds; a kick cut
access in 3 seconds. On the real Mac mini (direct connection over the LAN): suspend 2.0 s,
resume 0.8 s, kick 2.1 s.

What it does not cover: real phones and desktops (the simulated devices are Linux
containers), a real public server with a Let's Encrypt cert, and real NAT.

## Layout

```
compose.yaml        services
hogman              operator tool (setup; passes member/invite/device/name/audit to the registrar)
registrar/          the registrar (Go): ledger, Headscale client, policy, zone, APIs, CLI
join/               the join tool (Go, embeds tsnet for side-by-side mode), cross-compiled at `up`
join-page/          the page an invite link opens
config/             Caddyfiles (env-substituted at runtime)
templates/          rendered into data/ by ./hogman
portal/             static portal page
test/               end-to-end test
data/               generated: keys, databases, rendered configs (never commit)
```
