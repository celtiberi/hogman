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
