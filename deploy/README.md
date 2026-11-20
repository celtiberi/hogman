# Running pens on a server

Two tools for a real server:

- **`bootstrap.sh`** sets up a fresh Ubuntu 24.04 server: automatic security updates,
  Docker, Tailscale (so you manage it over your own tailnet), a firewall that only opens the
  pens' ports, and swap.
- **`hogman-host`** runs any number of pens behind one shared **front door**. The front
  door holds ports 80 and 443 and a Let's Encrypt certificate for every pen's control
  hostname, and hands each pen's traffic to that pen alone.

## What is shared, and what isn't

| Shared by all pens | Each pen's own |
|---|---|
| The server, ports 80/443, the front door | Headscale, DNS, certificate authority, registrar, database, keys, relay port |

Each pen lives in its own folder, `/opt/hogman/pens/<name>`. Copy that folder to another
server and the pen moves with it.

The front door joins each pen's private network; pens never share a network with each
other's core. `test-host.sh` checks this: two pens on one host, a member joining each, and
neither pen able to reach the other.

## Setting up a server

1. Create an Ubuntu 24.04 server with your SSH key, log in, and install:

   ```bash
   curl -fsSL https://hogman.network/install.sh | sudo bash
   ```

   This sets the server up (security updates, Docker, Tailscale, firewall, swap), installs
   Hogman into `/opt/hogman`, and starts the front door. The code comes from a release on
   hogman.network, checked against its published SHA-256, with the join tool and registrar
   already compiled.

2. Manage the server over your own tailnet, and close SSH to the internet:

   ```bash
   tailscale up --hostname=hogman-1                  # open the link it prints
   bash /opt/hogman/bootstrap.sh --lock-ssh          # from now on: ssh root@hogman-1
   ```

3. For each pen, point its control hostname at the server (an A record, not proxied, if the
   DNS is on Cloudflare), then:

   ```bash
   hogman-host add bobo hs.example.com
   hogman-host pen bobo member add alice --role owner
   hogman-host pen bobo invite create
   ```

4. **Take each pen's root key off the server.** `add` prints where it is
   (`pens/<name>/data/pki/offline/`). Keep it in your password manager. The pen runs without
   it.

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
