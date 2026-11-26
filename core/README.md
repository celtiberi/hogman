# Hogman core node

The backbone of a Hogman pen: control plane, registrar, portal, and the `hogman` client.

> **Hosted pens (D-24):** Production pens run behind the hosted front door on `hogman.network`. The standalone compose stack here (`edge`, `./hogman`, `test/run.sh`, `test/acme-pebble.sh`) is kept as the local and CI test harness rather than a supported self-hosted deployment.

| Service | Image | Where it is reachable |
|---|---|---|
| `headscale` | Headscale 0.29.7 | Behind shared front door (or `edge` in local tests); STUN on udp/3478 |
| `edge` | Caddy 2.11.9 | Standalone test harness only: `https://<PUBLIC_HOST>` (behind `hogman-host`, the shared front door serves these routes directly) |
| `registrar` | built from [registrar/](registrar/) | Single unprivileged (`65532:65532`, `read_only`, `cap_drop: ALL`) container embedding the `core` (`tag:infra`) mesh node via `tsnet`: serves authoritative DNS (`:53` UDP/TCP), `https://home.<ZONE>:443` portal static files and `/api/*` (with direct WireGuard `WhoIs` caller identity, no `X-Forwarded-For`), `home.<ZONE>` ACME TLS, `/api/acme/{txt,eab}`, and public `/hogman/*` (`:8081`) |

## Test harness setup

Requires Docker, `jq`, and Linux (for Unix-socket challenge DNS bind mounts in `core/test/run.sh` and `core/test/acme-pebble.sh`):

```bash
cp .env.example .env      # set NETWORK, ZONE, PUBLIC_HOST
./hogman init             # prepares data folders, Headscale ACL policy, non-root IDs
# place the challenge-dns token in data/secrets/registrar/challenge_dns_token
./hogman up
./hogman member add <you> --role owner
./hogman device key <you> personal   # open the link it prints on your laptop to join (first device only)
```

## Invite people

```bash
./hogman invite create --note "alice from the department"     # single use, 7 days
./hogman invite create --role admin --ttl 48h
./hogman invite list
./hogman invite revoke <id>
```

Each invite prints a link like `https://<PUBLIC_HOST>/join#t=…`. Send it however you like.
Opening it shows a page with one command to copy into a terminal:

```bash
curl -fsSLo hogman "https://<PUBLIC_HOST>/join/dl/hogman-$(uname -s)-$(uname -m)" \
  && chmod +x hogman && ./hogman '<the link>'
```

The join tool ([join/](join/)) runs side by side as your own user (no root, no `TUN` device, no OS trust-store changes):

1. fetches `/hogman/v1/network` over standard HTTPS, validates that `zone` is a valid public subdomain matching `PUBLIC_HOST`, and rejects legacy links carrying `fp=`;
2. redeems the invite (asking you to choose a handle);
3. runs its embedded `tsnet` node and local `:443`-only loopback proxy (`WhoIs`-pinned dialing so pen DNS cannot reach `127.0.0.1`, LAN, or other tailnets), serves `/proxy.pac` for all joined pens, and checks `https://home.<ZONE>` loads over HTTPS before configuring the system proxy.

More devices: each member adds their own from the home page (`POST /api/devices`), which prints a
device link (`https://<PUBLIC_HOST>/join#k=…`, or with `&for=share` for `hogman share`). Nobody can
make one for someone else: there is no account recovery. `hogman update` defaults to
immutable GitHub Releases on `celtiberi/hogman` (working with 0, 1, or many pens; pass `--pen <zone>`
or a pen host URL to update from a pen's server instead; `HOGMAN_RELEASE_BASE` is a test-only
override), verifies downloads against SHA-256 over HTTPS, cleans up any leftover legacy private-CA
root certificates, and restarts background agents and service-managed shares. New client releases
maintain backward compatibility with at least the previous registrar release (one release back).
`hogman leave <pen>` (a join link
with or without its key, the control host, the pen zone, or its short name) stops shares on that pen, cleans up any
legacy root cert, logs the device out, and removes its local settings. It works from saved settings,
so a pen whose server is gone can still be left. `leave` with no pen does nothing and points to
`leave-all`, which lists every pen and asks `[y/N]`. `hogman uninstall` leaves every pen
(asking first) and removes Hogman's settings folders. All three refuse a pen whose person is an
owner (no account recovery) or one that can't be reached to check. `--force` overrides that only
after a warning and typing the exact pen name; `--yes` never skips the name, and there's no
override without a terminal. `uninstall` is all or nothing: if any pen is refused, nothing changes.
`hogman share list [--pen ZONE]` lists local shares with any error state, `hogman share stop NAME [--force]`
tears down a share (or removes local files when unreachable with `--force`), `hogman join` prompts to paste
a link interactively on a terminal (or reads `--link-stdin`), `--pen` / `HOGMAN_PEN` accept short pen names or open
an interactive picker when multiple pens are installed, `hogman doctor [--json]` checks pen/share/proxy/extension
health, `status --json` and `share list --json` emit machine-readable JSON on stdout, and `hogman version` /
`help` / `completion <shell>` print version, usage, or shell completions to stdout. All pen agents and background
shares run from one shared binary under `<configBase>/bin/`.

Built for macOS (Apple silicon, Intel), Linux (x86-64, ARM64) and Windows (x86-64; untested).

## Members' API (on the mesh)

Every request to `https://home.<ZONE>/api/` is identified by the mesh
address it comes from (`X-Forwarded-For` over the Unix socket shared only with `portal`). No passwords: a device is its owner's identity.

| Request | What it does |
|---|---|
| `GET /api/me` | Your membership, devices, names, invites |
| `POST /api/devices {"kind":"personal"\|"server"}` | One-time key and join link for another device |
| `DELETE /api/devices/{id}` | Remove one of your devices |
| `POST /api/names {"name":"alice","device_id":3,"note":"..."}` | Claim a name (with optional note) for a server |
| `DELETE /api/names/{name}` | Release a name and everything under it |
| `POST/DELETE /api/acme/txt` | Write/delete `_acme-challenge.*` TXT records via `challenge-dns` for names owned solely by the calling `server` device |
| `POST /api/acme/eab` | Mint a single-use fallback CA EAB credential for a `server` device that owns at least one name |
| `GET /api/directory` | Every site on the network, its owner, note, and live server `online` / `last_seen` from Headscale |
| `POST /api/invites` | Mint an invite (admins; members if `MEMBERS_CAN_INVITE=true`) |
| `GET /api/admin/members`, `/devices`, `/invites`, `/audit` | Admins (`/devices` includes live `online` / `last_seen` from Headscale without storing history) |
| `POST /api/admin/members/{handle}/suspend\|resume\|kick\|role` | Admins |

Names: first come, first served. Owning `alice` gives you everything under it
(`blog.alice`); nobody else can claim there. Names point only at servers, since
personal devices accept no connections. Reserved: `home`, `ns`, `ns[0-9]*`, `nodes`,
`registrar`, `search`, `www`, `join`, `admin`, `_acme-challenge`.

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
takes their names out of DNS and retires them permanently so nobody can
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

### Test-only `hogman` environment variables

- `HOGMAN_DISABLE_NETNS=1` — **test-only, for isolated networks with no default route** (such as Docker `--internal` bridges). Disables Tailscale's `netns` `SO_BINDTODEVICE` hook (which otherwise binds unprivileged sockets to `lo` on Linux 5.7+ when no default gateway exists). Do **not** set this on ordinary laptops or desktops: it turns off `tsnet`'s VPN bypass.
- `HOGMAN_ACME_CA_ROOT` / `HOGMAN_ACME_CA_URL` / `HOGMAN_ACME_RESOLVERS` — point `hogman` at a local Pebble test ACME CA during offline tests.

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
