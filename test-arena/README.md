# Hogman Bot Arena (`test-arena/`)

A self-contained testing and red-team harness that runs AI agent bots inside locked-down Linux containers against a local fake-CA Hogman stack (`Pebble` + `challenge-dns` + `hogman-front` + two pens on `.hogman.test`).

Nothing in `test-arena/` touches production infrastructure, Let's Encrypt quotas, or real pen names. Both `setup-droplet.sh` and `arena.sh` refuse to run if Tailscale, `/opt/hogman`, or a pre-existing `hogman-front` is detected.

## Architecture

```
Host droplet (holds LLM API key, runs orchestrator + deterministic Judge)
  │
  ├── hogman-front network
  │     ├── hogman-front-front-1   (*.gate.hogman.test, get.hogman.test)
  │     ├── hogman-arena-cdns      (challenge-dns, CDNS_WEEKLY_CAP=5)
  │     ├── hogman-arena-pebble    (Pebble ACME CA; mgmt 15000 bound to 127.0.0.1 only)
  │     ├── hogman-arena-dns       (dnsmasq: *.hogman.test only, no upstream)
  │     ├── pen-pena-core          (Pen A: Headscale, registrar, portal, mesh)
  │     └── pen-penb-core          (Pen B: isolated second pen)
  │
  └── hogman-arena-bots (--internal: ZERO internet egress)
        ├── arena-canary-pena      (serves rotatable secret at https://vault.pena.pens.hogman.test)
        ├── arena-canary-penb      (serves isolated secret at https://vault.penb.pens.hogman.test)
        ├── arena-bot-alice        (keeper of Pen A)
        ├── arena-bot-mallory-insider (member of Pen A probing Pen B & admin APIs)
        └── arena-bot-mallory-kicked  (member of Pen A kicked mid-run)
```

Key security boundaries:

- **Zero internet egress in bot sandboxes:** Every bot container sits exclusively on `hogman-arena-bots` (`docker network create --internal`) with DNS forwarded to `hogman-arena-dns` (`dnsmasq` with `no-resolv`, `cache-size=0`, `no-negcache`).
- **No Pebble CA key exposure:** Pebble's management port (`15000`, which serves `/intermediate-keys/0`) is bound strictly to `127.0.0.1:15000` inside Pebble's own network namespace. `arena.sh` fetches the issuing root via a one-shot `--network container:hogman-arena-pebble` curl, and `judge.py` verifies port `15000` is unreachable from bot sandboxes.
- **No LLM key inside sandboxes:** `GEMINI_API_KEY` (or `DEEPSEEK_API_KEY` / `OPENAI_API_KEY`) lives only in the host orchestrator process (`run.py`). Bot containers run `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges:true`, UID `1000:1000`, memory/PID limits, in-container `timeout -k 5` enforcement, and no Docker socket.
- **Deterministic canary Judge with positive controls (`judge.py`):** No LLM judges the outcome. Pen B has an isolated canary secret (`CANARY_PENB_SECRET_*`), and Pen A rotates its vault secret (`CANARY_PENA_POSTKICK_*`) immediately after `alice` kicks `mallory-kicked`. After Rounds 2 and 3, `run.py` records host-side positive controls (`controls.json`) by reading `proxy_addr` from the container's `config.json`, checking `/proc` inside the container to verify that `127.0.0.1:<port>` is owned by the read-only `/usr/local/bin/hogman-join` `agent` binary, and proving the bot reached `vault.pena` (`HTTP 200` + initial canary). At Judge time, `judge.py` probes those host-recorded addresses, re-verifies via `/proc` that the listener is still `/usr/local/bin/hogman-join` `agent` (so a bot cannot swap in a fake 403 stub), treats broken proxies or failed joins as `FAIL(infra)` rather than "blocked", checks registrar `STATUS == removed`, scans transcripts and container filesystems for canary leaks, and verifies both pens remain healthy under attack.
- **Centralized prompts & schemas (`prompts.json`):** Prompts, round metadata, and the structured turn JSON schema live in `test-arena/prompts.json`. `llm.py` translates the schema to Gemini's native `responseSchema` (or OpenAI-compatible `json_schema`), caps output tokens (`maxOutputTokens=2048`), trims conversation history by character size (keeping the current round's prompt and merging consecutive same-role messages), estimates tokens if a provider omits usage metadata, and checks projected per-call tokens against per-bot and per-run budgets before sending requests.

## Deploying on a Disposable Linux Droplet

Use a separate DigitalOcean project and a fresh Ubuntu 24.04 LTS droplet (2 vCPU / 4 GB RAM recommended, or 2 GB RAM with automatic 2 GB swapfile). Do **not** join the droplet to Tailscale and do **not** put production SSH keys or credentials on it.

1. Bootstrap and firewall the droplet (restricting both SSH via `ufw` and Docker-published ports `80`/`443`/STUN via a persistent `DOCKER-USER` iptables/ip6tables service to your IP only):

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

3. Boot the Pebble Hogman stack, canary vaults, and bot containers (`arena.sh up` verifies that the `DOCKER-USER` DROP rule is active before starting; pass `ARENA_ALLOW_UNFIREWALLED=1` only on an isolated private VM):

   ```bash
   sudo test-arena/arena.sh up
   ```

4. Run the v1 scenario (`alice` + `mallory-insider` + `mallory-kicked`) and deterministic Judge:

   ```bash
   sudo -E python3 test-arena/run.py
   ```

   Optional budget/model overrides:

   ```bash
   sudo -E python3 test-arena/run.py \
     --model gemini-2.5-flash \
     --max-total-tokens 150000 \
     --max-bot-tokens 60000
   ```

5. Inspect run artifacts under `test-arena/runs/<timestamp>/`:
   - `alice.jsonl`, `mallory-insider.jsonl`, `mallory-kicked.jsonl` — every command, exit code, duration, and output
   - `messages.jsonl` — inter-bot invite links and messages
   - `controls.json` — host-recorded positive controls (`proxy_addr` and pre-kick canary checks)
   - `usage.json` — per-bot and total token counts and API call counts
   - `verdict.json` — deterministic Judge pass/fail checks, infra failures, and any canary breaches

6. Wipe and rebuild cleanly between runs (or tear down completely):

   ```bash
   sudo test-arena/arena.sh reset
   # or:
   sudo test-arena/arena.sh down
   ```

## Known Limits (v1)

- **Docker embedded DNS (`127.0.0.11`):** On user-defined Docker bridges, `/etc/resolv.conf` points at Docker's embedded resolver (`127.0.0.11`), which resolves names of containers attached to `hogman-arena-bots` locally and forwards all other queries to our pinned `hogman-arena-dns` (`dnsmasq` with `no-resolv`). External domains never resolve (verified by `judge.py`), and canary/proxy services bind strictly to `127.0.0.1` inside their own containers.
- **Raw-string canary scanning:** `judge.py` greps transcripts and bot container filesystems for the raw `CANARY_*` tokens. A bot that deliberately transforms a stolen canary (for example base64- or hex-encoding it before printing) would evade raw string matching; the live cross-pen and post-kick probes and registrar state checks still catch unauthorized access independently.

## Turning Findings into Permanent Tests

Every bot command and response is recorded in `runs/<timestamp>/<bot>.jsonl`. Whenever a red-team bot triggers a real bug or security failure, turn the exact repro sequence into a permanent deterministic test in `core/test/run.sh`, `deploy/test-host.sh`, or Go unit tests so it runs on every PR in CI without LLM tokens.

## Local Unit Tests

The orchestrator, schema translation, token budget enforcement, message bus, and deterministic Judge logic can be verified locally without Docker or API keys:

```bash
python3 -m unittest discover -s test-arena -p 'test_*.py' -v
```
