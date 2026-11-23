# Hogman Bot Arena (`test-arena/`)

A self-contained testing and red-team harness that runs AI agent bots inside locked-down Linux containers against a local fake-CA Hogman stack (`Pebble` + `challenge-dns` + `hogman-front` + two pens on `.hogman.test`).

Nothing in `test-arena/` touches production infrastructure, Let's Encrypt quotas, or real pen names.

## Architecture

```
Host droplet (holds LLM API key, runs orchestrator + deterministic Judge)
  │
  ├── hogman-front network
  │     ├── hogman-front-front-1   (*.gate.hogman.test, get.hogman.test)
  │     ├── hogman-arena-cdns      (challenge-dns, CDNS_WEEKLY_CAP=5)
  │     ├── hogman-arena-pebble    (Pebble test ACME CA)
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

- **Zero internet egress in bot sandboxes:** Every bot container sits exclusively on `hogman-arena-bots` (`docker network create --internal`) with DNS pinned to `hogman-arena-dns` (`dnsmasq` with `no-resolv`, `cache-size=0`, `no-negcache`).
- **No LLM key inside sandboxes:** `GEMINI_API_KEY` (or `DEEPSEEK_API_KEY` / `OPENAI_API_KEY`) lives only in the host orchestrator process (`run.py`). Bot containers run `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges:true`, UID `1000:1000`, memory/PID limits, and no Docker socket.
- **Deterministic canary Judge (`judge.py`):** No LLM judges the outcome. Pen B has an isolated canary secret (`CANARY_PENB_SECRET_*`), and Pen A rotates its vault secret (`CANARY_PENA_POSTKICK_*`) immediately after `alice` kicks `mallory-kicked`. After the scenario finishes, `judge.py` scans adversary transcripts and container filesystems for canary leaks, probes post-kick and cross-pen endpoints live, checks registrar state, and verifies both pens stay healthy under attack.
- **Centralized prompts & schemas (`prompts.json`):** Prompts, round metadata, and the structured turn JSON schema live in `test-arena/prompts.json`. `llm.py` translates the schema to Gemini's native `responseSchema` (or OpenAI-compatible `json_schema`) and enforces hard per-bot and per-run token budgets.

## Deploying on a Disposable Linux Droplet

Use a separate DigitalOcean project and a fresh Ubuntu 24.04 LTS droplet (2 vCPU / 4 GB RAM recommended, or 2 GB RAM with automatic 2 GB swapfile). Do **not** join the droplet to Tailscale and do **not** put production SSH keys or credentials on it.

1. Bootstrap and firewall the droplet (restricting SSH to your IP only):

   ```bash
   sudo test-arena/setup-droplet.sh --allow-ssh-from <YOUR_IP>/32
   ```

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

3. Boot the Pebble Hogman stack, canary vaults, and bot containers:

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
   - `usage.json` — per-bot and total token counts and API call counts
   - `verdict.json` — deterministic Judge pass/fail checks and any canary breaches

6. Wipe and rebuild cleanly between runs (or tear down completely):

   ```bash
   sudo test-arena/arena.sh reset
   # or:
   sudo test-arena/arena.sh down
   ```

## Turning Findings into Permanent Tests

Every bot command and response is recorded in `runs/<timestamp>/<bot>.jsonl`. Whenever a red-team bot triggers a real bug or security failure, turn the exact repro sequence into a permanent deterministic test in `core/test/run.sh`, `deploy/test-host.sh`, or Go unit tests so it runs on every PR in CI without LLM tokens.

## Local Unit Tests

The orchestrator, schema translation, token budget enforcement, message bus, and deterministic Judge logic can be verified locally without Docker or API keys:

```bash
python3 -m unittest discover -s test-arena -p 'test_*.py' -v
```
