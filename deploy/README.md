# The keeper's guide

Everything to raise a pen on a server of your own, from an empty server to your first
guests, plus keeping it backed up, watched and up to date.

## Before you start

- **A server**: Ubuntu 24.04, 2 GB of memory, a public IPv4 address. A $12-a-month
  DigitalOcean droplet or similar is plenty, and one server holds many pens.
- **A hostname you control** for each pen's front gate, such as `hs.example.com`. Members'
  devices connect to it.
- **A free Tailscale account** (recommended), so you manage the server over your own
  tailnet and close SSH to the internet. Hogman runs side by side with it.
- **A password manager**, for the pen's root key.

## Your first pen

1. **Point the hostname at the server** with an A record to its IPv4 address. On
   Cloudflare, leave it *DNS only* (grey cloud), not proxied. Do this first: the pen fetches
   its certificate through that name.

2. **Install.** Log in to the server and run:

   ```bash
   curl -fsSL https://hogman.network/install.sh | sudo bash
   ```

   This sets the server up (security updates, Docker, Tailscale, firewall, swap), installs
   Hogman into `/opt/hogman`, and starts the front door. The code comes from a release on
   hogman.network, checked against its published SHA-256, with the join tool and registrar
   already compiled by GitHub from a public commit. Each compiled file carries signed build
   provenance: `gh attestation verify FILE --repo celtiberi/hogman` checks it. Each pen's
   registrar and certificate authority run as user 65532, not root, even though the installer
   runs as root.

3. **Lock the server down.** Manage it over your own tailnet, and close SSH to the internet:

   ```bash
   tailscale up --hostname=hogman-1                  # open the link it prints
   bash /opt/hogman/bootstrap.sh --lock-ssh          # from now on: ssh root@hogman-1
   ```

4. **Raise the pen** and make yourself its keeper:

   ```bash
   hogman-host add mypen hs.example.com
   hogman-host pen mypen member add you --role owner
   ```

   The pen's names end in `.mypen.hogman`.

5. **Get your own laptop in.** This makes a one-time link for one of your devices:

   ```bash
   hogman-host pen mypen device key you personal
   ```

   Open the link on your laptop (macOS or Linux). It shows one command to copy into a
   terminal; that trusts the pen's certificates and joins. You then land on your pen's home
   page, where you can add your other devices yourself. Run it again for each device you
   want to add from the server.

6. **Take the root key off the server.** The pen runs without it; you need it only to
   replace the pen's intermediate certificate, years from now. Copy it to your computer,
   put the three files in your password manager, then delete both copies:

   ```bash
   scp -r root@hogman-1:/opt/hogman/pens/mypen/data/pki/offline ./mypen-root   # on your computer
   rm -rf /opt/hogman/pens/mypen/data/pki/offline/*                            # on the server
   ```

7. **Let others in.** Each invite is a link for one person. They open it, pick a name, and
   copy one command:

   ```bash
   hogman-host pen mypen invite create --note "alice"
   ```

   Then set up [backups](#backups) and [alerts](#knowing-when-it-breaks), below.

## How a shared server works

Two tools run a real server:

- **`bootstrap.sh`** sets up a fresh Ubuntu 24.04 server: automatic security updates,
  Docker, Tailscale (so you manage it over your own tailnet), a firewall that only opens the
  pens' ports, and swap.
- **`hogman-host`** runs any number of pens behind one shared **front door**. The front
  door holds ports 80 and 443 and a Let's Encrypt certificate for every pen's control
  hostname, serves `/join` and the join tool downloads, enforces edge blocks/headers, and
  hands each pen's Headscale and registrar traffic directly to that pen alone (so pens behind
  it do not need their own `edge` container).

| Shared by all pens | Each pen's own |
|---|---|
| The server, ports 80/443, the front door (TLS, `/join`, `/join/dl`) | Headscale, DNS, certificate authority, registrar, database, keys, relay port |

Each pen lives in its own folder, `/opt/hogman/pens/<name>`. Copy that folder to another
server and the pen moves with it.

The front door joins each pen's private network; pens never share a network with each
other's core. `test-host.sh` checks this: two pens on one host, a member joining each, and
neither pen able to reach the other.

## Updating

```bash
curl -fsSL https://hogman.network/install.sh | sudo bash   # new code; pens untouched
hogman-host upgrade bobo                                   # restart a pen on it (under a minute)
```

Members stay joined; their devices reconnect by themselves after the pen restarts (about 20
seconds on a small server).

## Backups

Every night at 03:30 UTC the server packs each pen (its member ledger, Headscale's database,
names, the intermediate CA, settings) and encrypts it to a key the server doesn't have. The
root key is never in a backup; it should already be off the server.

1. On your own computer, make the backup key and keep the private half in your password
   manager, not on disk:

   ```bash
   age-keygen -o backup-key.txt      # prints the public key: age1...
   ```

2. On the server:

   ```bash
   hogman-host backup-setup age1...  # installs age, the nightly timer, takes a first backup
   ```

3. Get the backups off the server. On a machine you own (an always-on Mac mini is ideal),
   make a key, then allow it on the server. That key can list and download backups, and
   nothing else: no shell, no other files, no forwarding.

   ```bash
   ssh-keygen -t ed25519 -N "" -f ~/.ssh/hogman_backup                # on that machine
   hogman-host backup-allow "$(cat hogman_backup.pub)"                # on the server
   deploy/backup-pull.sh hogman-1                                     # on that machine
   ```

   Run `backup-pull.sh` on a schedule (cron, or a LaunchDaemon on a Mac). It keeps 30 days;
   the server keeps 7.

**Restoring.** With the private key back out of your password manager:

```bash
age -d -i backup-key.txt farm-<time>.tar.gz.age | tar -xz -C restore/
```

`restore/data` is the pen's `data/` folder and `restore/.env` its settings. Put both in
`/opt/hogman/pens/<name>/` on a server with Hogman installed (on a new server, fix
`PUBLIC_IPV4` in `.env` and point the pen's hostname at it), then `hogman-host upgrade <name>`.
Members keep their names, and their devices reconnect by themselves. Delete `backup-key.txt`
afterwards.

`hogman-host backup` takes one now.

## Knowing when it breaks

Run `deploy/hogman-watch.sh` every five minutes on a machine you own (the same one that pulls
backups is ideal). It checks that Headscale and the pen answer on the control host, that the
certificate has two weeks left, and that backups keep arriving, and pushes an alert to your
phone through [ntfy](https://ntfy.sh): no account, just the app and a topic name.

```bash
echo hogman-$(openssl rand -hex 12)          # your topic: subscribe to it in the ntfy app
NTFY_TOPIC=<topic> deploy/hogman-watch.sh --test
NTFY_TOPIC=<topic> deploy/hogman-watch.sh hs.example.com ~/hogman-backups   # every 5 minutes
```

It alerts after two failures in a row, reminds you every six hours, and tells you when it's
fixed. If the watching machine is offline itself, it says nothing. To watch other pages too, such as
a sign-up page, set `WATCH_URLS` (space-separated), e.g.
`WATCH_URLS=https://get.example.com/api/status`.

## Hosting pens for other people

A sign-up page lets people get a pen of their own on your server without a shell, the way
hogman.network does at [get.hogman.network](https://get.hogman.network). They name the pen and
themselves; about a minute later it's up at `<name>.<your pens domain>` and they get a one-time
link that joins their laptop. They run it from the pen's home page: invites, the herd, the boot.

```bash
hogman-host backup-setup age1...                          # first: hosted root keys are escrowed to this key
hogman-host signup-setup pens.example.com get.example.com 8   # pens domain, sign-up page, at most 8 pens
hogman-host signup-code "for alice"                       # a single-use code, and a link that fills it in
```

Point `get.example.com` and `*.pens.example.com` at the server first (DNS only). Sign-ups are
by code, one pen per code, so you decide who gets one. `hogman-host capacity` shows how full
the server is; the page says so when it's full. Each new pen gets its own Let's Encrypt
certificate, and Let's Encrypt allows about 50 new names a week per domain.

How it's built: the page runs unprivileged and can only ask a **broker**, over a private
network the two share, to report capacity, check a name, or raise a pen with a valid code. The
broker drives Docker, so it is as powerful as root; it does only those three things, one at a
time, and a failed attempt doesn't use up the code. It has no internet access unless you turn
on push notifications (`hogman-host signup-notify`), its only outbound use. Each hosted pen's **root key never stays
on the server in the clear**: it's encrypted to your backup key
(`data/pki/root-escrow.tar.gz.age`) and the plain copy deleted. The pen runs on its
intermediate certificate for five years; you need the root only to renew that.

Who signed up, and with which code, is in `/opt/hogman/signup/raised.log`.

**The waiting list.** When the server is full, or someone has no code, the page takes their
email instead (and, optionally, the pen name they'd like and a note). It promises to keep the
email only to send them a code, and to delete it once they've signed up; the broker removes
their line when they sign up with their code.

```bash
hogman-host waitlist                 # who's waiting
hogman-host waitlist invite 3        # make their code and email it (or print the message to send)
hogman-host waitlist remove 3        # delete someone, e.g. when they ask

hogman-host signup-mail "Hogman <pens@example.com>" < resend-api-key   # email codes via Resend
hogman-host signup-mail test you@example.com
hogman-host signup-notify https://ntfy.sh/<topic>   # a push when someone joins or gets a pen
```

Mail goes out only when you invite someone, never when someone joins, so nobody can use the
page to make you email an address they typed. Pushes never include personal details. Link
people straight to the list with `https://<signup-host>/#wait`.

## Public certificates (being built)

Pens are moving to certificates that browsers already trust, so members never install
anything (decision D-18; design in
[docs/security/public-certificates.md](../docs/security/public-certificates.md)). The first
piece is the **challenge DNS server**, which answers Let's Encrypt and Google when they check
a certificate request. It runs on the host:

```bash
hogman-host challenge-dns-setup 203.0.113.10              # this server's public IPv4
hogman-host challenge-dns-setup 203.0.113.10 gcp-eab.json # with the Google fallback CA
hogman-host challenge-dns cred list
```

- **It runs as a locked-down systemd service** (`hogman-challenge-dns`): its own system user
  with no login, only allowed to bind port 53, read-only everywhere else. Its state (credential
  hashes and the pen names ever used) is in the nightly backups.
- **It answers only for `pens.hogman.network` and `_acme-challenge.gate.hogman.network`,** and
  only once Cloudflare delegates those names to `ns1.hogman.network`. Until then nobody asks it
  anything. Check it with `dig @<ip> pens.hogman.network SOA`, then again with `+tcp`.
- **The Google key** (a service account that can only create single-use account keys) is
  handed over as a systemd credential, readable only by the service. Make it fresh, straight
  onto the server, when you set this up.
- **Port 53** is opened in the server's firewall. If DigitalOcean's cloud firewall is on,
  open TCP and UDP 53 there too.

Pens keep their own certificate authority until the switch-over. At the switch-over every
pen moves to public certificates at once and the old way is removed: there's no setting to
choose between them (D-22).

## Everyday

```bash
hogman-host list                        # pens, their hostnames and relay ports
hogman-host pen <name> <hogman args>    # anything ./hogman does, for one pen
hogman-host upgrade <name>              # after running install.sh again
hogman-host remove <name>               # stop and unroute a pen (its folder stays)
```

## Testing locally

```bash
deploy/test-host.sh        # needs Docker and jq; about five minutes
```
