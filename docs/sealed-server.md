# Sealed Pen-Only Server (Docker Sidecar)

Run any Dockerized web app inside a container with **zero internet access** (`network_mode: none`), reachable only by active members of your Hogman pen over HTTPS (`:443`).

## What it guarantees (and what it does not)

- **Inside the app container:** The app shares a Linux `network_mode: none` network namespace (`lo` only). It has no `eth0`, no default route, no LAN access, no cloud metadata (`169.254.169.254` / `fd00:ec2::254`), and no external DNS. Even if the app has hidden telemetry, a compromised dependency, or a prompt-injected AI agent, direct outbound connections fail at the kernel level (`Network is unreachable`).
- **Inbound access:** Only active members of your Hogman pen can reach `https://<name>.<pen>` over mutual-WireGuard HTTPS (`:443`). Zero host ports are opened, and you do not have to modify the upstream app image.
- **What is outside the seal (honest boundaries):**
  - Anyone with root on the Docker host can change or remove container isolation; this protects a cooperative host operator's data from leaky or compromised apps, not against a hostile host admin.
  - Authorized pen members viewing a page in a normal internet-connected browser are outside the container (they can copy/screenshot data, and a compromised web app can still attempt browser-side redirects or links if opened in a normal browser).
  - Mount sensitive host folders read-only (`:ro`) into `app`; any writable host bind mount (especially synced cloud folders) is outside the network seal.
  - Real `network_mode: none` enforcement requires Linux network namespaces (Linux Docker/Podman, or Docker Desktop / OrbStack / Colima on macOS).

## Architecture (3 containers, 1 sidecar image)

1. **`hogman-sidecar`** (normal Docker egress network for Headscale/DERP/ACME, UID `65532`, `read_only`, `cap_drop: ALL`): joins the pen as `tag:server`, stores its WireGuard and ACME state privately in `hogman_state`, and mounts `hogman_ingress` **read-only** (`:ro`) to connect to `app.sock`.
2. **`hogman-bridge`** (same image, `network_mode: none`, UID `65532`, `read_only`, `cap_drop: ALL`): creates `/run/hogman-in/app.sock` (`0600`) and forwards incoming connections to `127.0.0.1:8080`.
3. **`app`** (your unmodified image — Jupyter, Open WebUI, Wiki.js, Flask, Node, etc.): runs with `network_mode: service:hogman-bridge` (`lo` only) and mounts **no** socket volumes.

## Quick Start

### 1. Build the sidecar image

```sh
docker build -f core/join/Dockerfile.sidecar -t hogman-sidecar core/join
```

### 2. Create `docker-compose.yml`

```yaml
services:
  hogman-sidecar:
    image: hogman-sidecar
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 192m
    pids_limit: 128
    tmpfs:
      - /tmp:size=16m,noexec,nosuid,nodev
    volumes:
      - hogman_state:/var/lib/hogman
      - hogman_ingress:/run/hogman-in:ro
    command:
      - share
      - lab-notes
      - unix:///run/hogman-in/app.sock
      - --state-dir=/var/lib/hogman
      # Optional: override Host header sent to strict dev servers (default: <name>.<zone>)
      # - --upstream-host=localhost:8080
      # Optional: pass verified X-Hogman-* caller identity headers to a local upstream app (off by default)
      # - --identity-headers
    depends_on:
      hogman-bridge:
        condition: service_healthy
    restart: unless-stopped

  hogman-bridge:
    image: hogman-sidecar
    network_mode: none
    hostname: lab-notes
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 64m
    pids_limit: 64
    tmpfs:
      - /tmp:size=4m,noexec,nosuid,nodev
    volumes:
      - hogman_ingress:/run/hogman-in
    command:
      - bridge
      - --listen-unix=/run/hogman-in/app.sock
      - --forward-tcp=127.0.0.1:8080
    healthcheck:
      test: ["CMD", "/hogman", "bridge", "--check", "/run/hogman-in/app.sock"]
      interval: 5s
      timeout: 3s
      retries: 10
    restart: unless-stopped

  app:
    image: my-app:latest
    network_mode: service:hogman-bridge
    depends_on:
      hogman-bridge:
        condition: service_healthy
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 1g
    pids_limit: 256
    tmpfs:
      - /tmp:size=64m,noexec,nosuid,nodev
    volumes:
      - ./data:/data:ro
    restart: unless-stopped

volumes:
  hogman_state:
  hogman_ingress:
```

### 3. Enroll once via stdin (no secret file left on disk)

Get a one-time **Share link** from your pen's home page, then run:

```sh
docker compose run --rm -i hogman-sidecar \
  share lab-notes unix:///run/hogman-in/app.sock \
  --state-dir=/var/lib/hogman --enroll-only --link-stdin
```

Paste the share link and press `Ctrl-D`. Hogman enrolls the server node, claims the name, obtains its HTTPS certificate, deletes the one-time key, and exits `0`.

### 4. Start the stack

```sh
docker compose up -d
```

## Caller Identity Headers (`--identity-headers`)

Apps behind `hogman share` (or `hogman-sidecar`) can identify who in the pen is calling without building passwords or session cookies.

- **Off by default:** pass `--identity-headers` on `hogman share` to enable. Only allowed for local upstream targets (`unix://` socket, `localhost`, `127.0.0.1`, or `::1` — refused for static folders and LAN targets).
- **Always stripped on ingress:** `hogman share` strips every inbound `X-Hogman-*` header (regardless of casing, suffix, or hyphen/underscore spelling such as `X_Hogman_Handle`) before forwarding, **whether or not `--identity-headers` is enabled**, so a caller in the pen can never forge identity headers — including in CGI, PHP, WSGI, and Rack apps that fold `-` and `_` together.
- **Headers set on the local hop** (resolved from the authenticated WireGuard peer via `tsnet` `WhoIs`):
  - `X-Hogman-Handle` — the member's Hogman handle (personal devices only; omitted for tagged server nodes).
  - `X-Hogman-Node` — the peer's device name (display/audit only — **never** use `X-Hogman-Node` for access decisions).
  - `X-Hogman-IP` — the peer's mesh IP address.
  - `X-Hogman-Tags` — comma-separated ACL tags (e.g. `tag:server`), omitted for personal devices.
- **Fail closed in your app:** only accept traffic on the local socket or loopback interface reachable by the sidecar, read caller identity **only** from `X-Hogman-Handle`, and return `403 Forbidden` whenever `X-Hogman-Handle` is missing or not on your allowlist (and reject requests with `X-Hogman-Tags` if only personal devices should have access).

## Operational Notes

- **Firewalled networks blocking `1.1.1.1:53` / `8.8.8.8:53`:** If your lab firewall blocks direct public DNS from containers, set `HOGMAN_ACME_RESOLVERS` on `hogman-sidecar` to your local recursive resolver (e.g., `10.0.0.53:53`) so DNS-01 propagation checks succeed on first enrollment.
- **Restarting `hogman-bridge`:** Because `app` shares `hogman-bridge`'s network namespace (`network_mode: service:hogman-bridge`), if `hogman-bridge` is recreated, recreate `app` as well (`docker compose up -d --force-recreate hogman-bridge app`). `hogman-sidecar` reconnects automatically to the new Unix socket on the next request.
- **macOS Docker Desktop / Podman:** Always use Docker **named volumes** (`hogman_ingress:`) rather than host bind mounts (`./sock:/run/hogman-in`); Unix sockets live cleanly inside the Linux VM on named volumes, whereas VirtioFS host bind mounts do not support Unix sockets.
