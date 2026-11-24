# Hogman Bot Arena (`test-arena/`)

A self-contained testing and red-team harness that runs AI agent bots inside locked-down Linux containers against a local fake-CA Hogman stack (`Pebble` + `challenge-dns` + `hogman-front` + two pens on `.hogman.test`).

Nothing in `test-arena/` touches production infrastructure, Let's Encrypt quotas, or real pen names. Both `setup-droplet.sh` and `arena.sh` refuse to run if Tailscale, `/opt/hogman`, Hogman systemd units, or a pre-existing `hogman-front` is detected.

## Architecture

```
Host droplet (holds LLM API key, runs orchestrator + deterministic Judge)
  │
  ├── hogman-front + pen-pena-core + pen-penb-core
  │     ├── hogman-front-front-1   (*.gate.hogman.test)
  │     ├── pen-pena-core          (Pen A: Headscale, registrar, portal, mesh)
  │     └── pen-penb-core          (Pen B: isolated second pen)
  │
  ├── hogman-arena-acme (--internal: ZERO internet egress)
  │     ├── hogman-arena-cdns      (challenge-dns, 5/hr & 20/7d per pen, 40/hr soft / 60/hr hard global)
  │     └── hogman-arena-pebble    (Pebble ACME CA; mgmt 15000 bound to 127.0.0.1 only;
  │                                 detached from pen-*-core once home certs are issued)
  │
  └── Per-sandbox --internal networks (ZERO internet egress, ZERO bot-to-bot ICC):
        ├── arena-iso-canary-pena  -> arena-canary-pena (+ dedicated dnsmasq)
        ├── arena-iso-canary-penb  -> arena-canary-penb (+ dedicated dnsmasq)
        ├── arena-iso-alice        -> arena-bot-alice (+ dedicated dnsmasq)
        ├── arena-iso-mallory-insider -> arena-bot-mallory-insider (+ dedicated dnsmasq)
        └── arena-iso-mallory-kicked  -> arena-bot-mallory-kicked (+ dedicated dnsmasq)
```

Key security boundaries:

- **Zero internet egress & zero bot-to-bot ICC:** Every bot and canary container sits alone on its own dedicated `--internal` Docker network (`arena-iso-<name>`) alongside only `hogman-front-front-1`, `hogman-arena-pebble`, and its own `dnsmasq` resolver (`no-resolv`, `cache-size=0`, `no-negcache`). Bots cannot connect to or resolve peer bots or canary containers directly; the only path between them is Hogman's pen mesh.
- **Pebble strictly `--internal` & loopback management:** Once `pena` and `penb` obtain their initial `home.*` certificates, `arena.sh` detaches `hogman-arena-pebble` from `pen-pena-core` and `pen-penb-core` so every network attached to Pebble is `--internal` (closing RFC 8738 IP-identifier outbound egress). Pebble's management port (`15000`, which serves `/intermediate-keys/0`) binds strictly to `127.0.0.1:15000`.
- **No `docker.sock` signup surface by default:** The signup broker (`get.hogman.test`) is disabled in v1 unless explicitly opted in via `ARENA_ENABLE_SIGNUP=1`.
- **No LLM key inside sandboxes:** `GEMINI_API_KEY` (or `DEEPSEEK_API_KEY` / `OPENAI_API_KEY`) lives only in the host orchestrator process (`run.py`). Bot containers run `--init`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges:true`, UID `1000:1000`, `--ulimit nofile=1024:1024`, `--ulimit core=0`, `nodev` tmpfs mounts (`/tmp`, `/dev/shm`, `/home/bot`), memory/PID limits, bounded host-side stdout/stderr streaming, and in-container `timeout -k 5` enforcement.
- **Deterministic canary Judge with pinned agent controls (`judge.py`):** No LLM judges the outcome. Pen B has an isolated canary secret (`CANARY_PENB_SECRET_*`), and Pen A rotates its vault secret (`CANARY_PENA_POSTKICK_*`) immediately after `alice` kicks `mallory-kicked`. After Rounds 2 and 3, `run.py` records host-side positive controls (`controls.json`): reading `proxy_addr` from `config.json`, verifying inside a single `docker exec` that the sole owner of `127.0.0.1:<port>` matches the host-known SHA-256 of `hogman` running `agent /home/bot/.config/hogman/<zone>`, recording `(pid, starttime)` from `/proc/<pid>/stat` and the bot's actual handle from `GET /api/me`, and proving it reads the initial canary (`HTTP 200`). At Judge time, `judge.py` pins probes to that exact `(pid, starttime, SHA-256)` (re-verified before and after `curl`), checks exact Pen A/Pen B member rosters and roles (`STATUS == removed`, zero remaining live devices), runs regular-file-only binary canary scans across `/home/bot`, `/tmp`, and `/dev/shm` (immune to FIFO traps and NUL-padded files), runs network/DNS/Pebble boundary probes in a clean ephemeral container (immune to bot PID exhaustion), and verifies both pens stay healthy under attack.
- **Centralized prompts & schemas (`prompts.json`):** Prompts, round metadata, per-round `MessageBus` recipient allowlists, and the structured turn JSON schema live in `test-arena/prompts.json`. `llm.py` translates the schema to Gemini's native `responseSchema` or OpenAI-compatible `json_schema` (automatically falling back to forced function calling `tools`/`tool_choice` when an endpoint such as DeepSeek rejects `response_format=json_schema`), refuses HTTP redirects, redacts API keys from error logs, caps output tokens (`maxOutputTokens=4096`), truncates bulky per-command output in prompt history while preserving full transcripts on disk, trims conversation history by character size (preserving the current round's prompt, dropping leading assistant turns, and merging consecutive same-role messages), estimates tokens if a provider omits usage metadata, and checks projected tokens against per-bot and per-run budgets before sending requests.

## Deploying on a Disposable Linux Droplet

Use a separate DigitalOcean project and a fresh Ubuntu 24.04 LTS droplet (2 vCPU / 4 GB RAM recommended, or 2 GB RAM with automatic 2 GB swapfile). Do **not** join the droplet to Tailscale and do **not** put production SSH keys or credentials on it.

1. Bootstrap and firewall the droplet (`ufw` allows inbound SSH TCP 22 only from your CIDR; `DOCKER-USER` drops **all** external inbound IPv4 and IPv6 traffic to Docker-published ports before and after `docker.service` starts; Docker `json-file` logs rotate at `10m` × 3):

   ```bash
   sudo test-arena/setup-droplet.sh --allow-ssh-from <YOUR_IP>/32
   ```

   As defense-in-depth, also attach a DigitalOcean Cloud Firewall allowing only inbound TCP 22 from `<YOUR_IP>/32`.

2. Export your LLM API key on the host shell (Gemini API is the default):

   ```bash
   export GEMINI_API_KEY='...'
   ```

   To use an OpenAI-compatible endpoint such as DeepSeek instead:

   ```bash
   export ARENA_LLM_PROVIDER=openai-compat
   export ARENA_LLM_BASE_URL='https://api.deepseek.com/v1'
   export ARENA_LLM_MODEL='deepseek-chat'
   export DEEPSEEK_API_KEY='...'
   ```

3. Boot the Pebble Hogman stack, canary vaults, and isolated bot containers (`arena.sh up` verifies `FORWARD -> DOCKER-USER`, final `-j DROP` in IPv4/IPv6 `DOCKER-USER`, and active `ufw`; pass `ARENA_ALLOW_UNFIREWALLED=1` only on an isolated private VM):

   ```bash
   sudo test-arena/arena.sh up
   ```

4. Run the v1 scenario (`alice` + `mallory-insider` + `mallory-kicked`) and deterministic Judge:

   ```bash
   sudo -E python3 test-arena/run.py
   ```

   Or run the expanded **v2 red-team scenario** (ACME `/api/acme/{txt,eab}` & `CDNS_HOURLY_CAP=5` burst exhaustion, reserved/victim name hijacking, `X-Forwarded-For` impersonation, admin privilege escalation, proxy/CSWSH checks, cross-pen isolation, and post-kick revocation):

   ```bash
   sudo -E python3 test-arena/run.py --prompts test-arena/prompts.v2.json
   ```

   Optional budget/model overrides:

   ```bash
   sudo -E python3 test-arena/run.py \
     --model gemini-2.5-flash \
     --max-total-tokens 300000 \
     --max-bot-tokens 120000
   ```

5. Inspect run artifacts under `test-arena/runs/<timestamp>-<pid>/`:
   - `alice.jsonl`, `mallory-insider.jsonl`, `mallory-kicked.jsonl` — every command, exit code, duration, and bounded output
   - `messages.jsonl` — route-restricted inter-bot invite links and messages
   - `controls.json` — host-recorded positive controls (`proxy_addr`, `pid`, `starttime`, `handle`, pre-kick canary checks)
   - `usage.json` — per-bot and total token counts and API call counts
   - `verdict.json` — deterministic Judge pass/fail checks, infra failures, and any canary breaches

6. Wipe and rebuild cleanly between runs (or tear down completely):

   ```bash
   sudo test-arena/arena.sh reset
   # or:
   sudo test-arena/arena.sh down
   ```

## Known Limits (v1)

- **Docker embedded DNS (`127.0.0.11`):** On user-defined Docker bridges, `/etc/resolv.conf` points at Docker's embedded resolver (`127.0.0.11`), which resolves names of containers attached to that sandbox's own `arena-iso-<name>` network (`front`, `pebble`, its own `dnsmasq`) and forwards all other queries to `dnsmasq` (`no-resolv`). Peer bot and canary containers sit on separate networks and are unresolvable (verified by `judge.py`).
- **Raw-string canary scanning:** `judge.py` scans regular files and transcripts for the raw `CANARY_*` byte strings. A bot that deliberately transforms a stolen canary (for example base64- or hex-encoding it before printing) would evade raw string matching; the pinned live cross-pen/post-kick probes and registrar roster/device checks still catch unauthorized access independently.
- **Bot-owned agent process:** Because `hogman` runs as UID 1000 inside the bot's own container, a bot can kill its own agent process or corrupt its own state directory under `~/.config/hogman/<zone>`. Pinning `(pid, starttime, exe SHA-256, cmdline)` and requiring sole socket ownership catches killed, replaced, or decoy agents as `FAIL(infra)`; corrupting the live agent's state directory on disk to self-sabotage its own proxy only hides the bot's own access rather than bypassing revocation, and registrar member/device checks plus canary scans still run independently.
- **Judge isolated Python exec:** All in-container Judge scripts run via `docker exec -w / <ctr> /usr/bin/python3 -I -c ...` (and invoke `/usr/bin/curl`, `/usr/bin/jq`, `/usr/bin/dig` by absolute path on the `--read-only` rootfs) so bot-planted Python modules in `/home/bot` or `~/.local` cannot hijack Judge imports.

## Turning Findings into Permanent Tests

Every bot command and response is recorded in `runs/<timestamp>-<pid>/<bot>.jsonl`. Whenever a red-team bot triggers a real bug or security failure, turn the exact repro sequence into a permanent deterministic test in `core/test/run.sh`, `deploy/test-host.sh`, or Go unit tests so it runs on every PR in CI without LLM tokens.

## Local Unit Tests

The orchestrator, schema translation, token budget enforcement, bounded streaming runner, message bus, and deterministic Judge logic can be verified locally without Docker or API keys:

```bash
python3 -m unittest discover -s test-arena -p 'test_*.py' -v
```
