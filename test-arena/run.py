#!/usr/bin/env python3
"""Hogman Bot Arena v1 orchestrator.

Loads arena-state.json and prompts.json, drives alice, mallory-insider, and
mallory-kicked through the v1 scenario rounds with strict per-turn timeouts,
bounded conversation history, and token budgets, records host-side positive
controls, rotates Pen A's vault canary after kick, writes JSONL transcripts and
token accounting to runs/<timestamp>/, and finishes with the deterministic
canary Judge.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from judge import format_verdict, record_positive_control, run_judge
from llm import BudgetExceededError, LLMClient, LLMError, TokenLedger
from sandbox import MessageBus, exec_in_container, utc_now


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_MAX_HISTORY_CHARS = 24_000


def load_prompts(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_message_roles(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    """Merge consecutive messages with the same role so APIs never see user->user runs."""
    out: list[dict[str, str]] = []
    for msg in messages:
        role = msg["role"]
        content = msg["content"]
        if out and out[-1]["role"] == role:
            out[-1] = {"role": role, "content": out[-1]["content"] + "\n\n" + content}
        else:
            out.append({"role": role, "content": content})
    return out


def trim_history(
    history: list[dict[str, str]],
    round_start_idx: int = 0,
    max_chars: int = DEFAULT_MAX_HISTORY_CHARS,
) -> list[dict[str, str]]:
    """Trim conversation history by character size while always preserving the current round's prompt.

    Keeps the message at `round_start_idx` (the current round's assignment), plus
    as many of the most recent messages after it as fit within `max_chars`, and
    merges any consecutive same-role messages (e.g. if a previous round ended at
    max_turns).
    """
    if not history:
        return []
    anchor_idx = max(0, min(round_start_idx, len(history) - 1))
    anchor = history[anchor_idx]
    recent: list[dict[str, str]] = []
    used = len(anchor["content"])

    # Walk backward from newest turn back to anchor_idx + 1, keeping what fits.
    for msg in reversed(history[anchor_idx + 1 :]):
        msg_len = len(msg["content"])
        if recent and used + msg_len > max_chars:
            break
        recent.append(msg)
        used += msg_len
    recent.reverse()

    # If the newest message alone blew past max_chars, truncate it defensively so
    # a single call cannot exceed the per-call budget window.
    if recent and used > max_chars:
        budget_for_last = max(256, max_chars - len(anchor["content"]))
        last = recent[-1]
        if len(last["content"]) > budget_for_last:
            recent[-1] = {
                "role": last["role"],
                "content": last["content"][:budget_for_last] + "\n...[trimmed for history budget]",
            }

    # Include compact pre-anchor context only if headroom remains.
    prefix: list[dict[str, str]] = []
    if anchor_idx > 0 and used < max_chars:
        for msg in reversed(history[:anchor_idx]):
            msg_len = len(msg["content"])
            if used + msg_len > max_chars:
                break
            prefix.append(msg)
            used += msg_len
        prefix.reverse()

    return normalize_message_roles(prefix + [anchor] + recent)


def rotate_pen_canary(arena_home: Path, pen: str, phase: str = "POSTKICK") -> str:
    env = dict(os.environ)
    env["ARENA_HOME"] = str(arena_home)
    proc = subprocess.run(
        [str(SCRIPT_DIR / "arena.sh"), "rotate-canary", pen, phase],
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
        check=True,
    )
    token = proc.stdout.strip().splitlines()[-1].strip()
    if not token.startswith("CANARY_"):
        raise RuntimeError(f"unexpected canary token output: {token!r}")
    return token


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def run_bot_round(
    *,
    bot: str,
    container: str,
    round_cfg: dict[str, Any],
    round_prompt: str,
    system_prompt: str,
    response_schema: dict[str, Any],
    history: list[dict[str, str]],
    client: LLMClient,
    bus: MessageBus,
    transcript_path: Path,
    cmd_timeout_s: int,
    max_history_chars: int = DEFAULT_MAX_HISTORY_CHARS,
) -> dict[str, Any]:
    round_id = round_cfg["id"]
    max_turns = int(round_cfg.get("max_turns", 10))

    inbox = bus.drain_inbox(bot)
    initial_user_msg = round_prompt
    if inbox:
        formatted = "\n".join(f"- From {m['from']}: {m['message']}" for m in inbox)
        initial_user_msg = f"{round_prompt}\n\nInbox messages received before this round:\n{formatted}"
    round_start_idx = len(history)
    history.append({"role": "user", "content": initial_user_msg})

    summary = ""
    status = "max_turns_reached"

    for turn in range(1, max_turns + 1):
        window = trim_history(history, round_start_idx=round_start_idx, max_chars=max_history_chars)
        try:
            decision = client.next_turn(bot, system_prompt, window, response_schema)
        except BudgetExceededError as exc:
            status = "budget_exceeded"
            summary = str(exc)
            append_jsonl(
                transcript_path,
                {"ts": utc_now(), "round": round_id, "turn": turn, "bot": bot, "event": "budget_exceeded", "error": str(exc)},
            )
            print(f"[{round_id}] {bot} halted: {exc}")
            break
        except LLMError as exc:
            status = "llm_error"
            summary = str(exc)
            append_jsonl(
                transcript_path,
                {"ts": utc_now(), "round": round_id, "turn": turn, "bot": bot, "event": "llm_error", "error": str(exc)},
            )
            print(f"[{round_id}] {bot} LLM error: {exc}", file=sys.stderr)
            break

        history.append({"role": "assistant", "content": json.dumps(decision)})
        action = decision["action"]

        if action == "done":
            status = "done"
            summary = decision.get("summary", "")
            append_jsonl(
                transcript_path,
                {"ts": utc_now(), "round": round_id, "turn": turn, "bot": bot, "action": "done", "decision": decision},
            )
            print(f"[{round_id}] {bot} done (turn {turn}/{max_turns}): {summary[:160]}")
            break

        if action == "message":
            recipient = decision.get("to", "").strip()
            msg_body = decision.get("message", "")
            try:
                bus.send(bot, recipient, msg_body, round_id=round_id)
                feedback = f"Message delivered to {recipient}."
                err_str = ""
            except ValueError as exc:
                feedback = f"Message rejected: {exc}"
                err_str = str(exc)
            append_jsonl(
                transcript_path,
                {
                    "ts": utc_now(),
                    "round": round_id,
                    "turn": turn,
                    "bot": bot,
                    "action": "message",
                    "to": recipient,
                    "message": msg_body,
                    "error": err_str,
                },
            )
            print(f"[{round_id}] {bot} -> {recipient} (turn {turn}/{max_turns})")
            history.append({"role": "user", "content": feedback})
            continue

        if action == "exec":
            cmd = decision.get("command", "").strip()
            if not cmd:
                history.append({"role": "user", "content": "Empty command; provide a shell command or choose action=done."})
                continue
            res = exec_in_container(container, cmd, timeout_s=cmd_timeout_s)
            append_jsonl(
                transcript_path,
                {
                    "ts": utc_now(),
                    "round": round_id,
                    "turn": turn,
                    "bot": bot,
                    "action": "exec",
                    "thought": decision.get("thought", ""),
                    "command": cmd,
                    "exit_code": res.exit_code,
                    "timed_out": res.timed_out,
                    "duration_ms": res.duration_ms,
                    "truncated": res.truncated,
                    "stdout": res.stdout,
                    "stderr": res.stderr,
                },
            )
            print(f"[{round_id}] {bot} exec (turn {turn}/{max_turns}, rc={res.exit_code}, {res.duration_ms}ms): {cmd[:90]}")

            new_inbox = bus.drain_inbox(bot)
            inbox_note = ""
            if new_inbox:
                inbox_note = "\nNew inbox messages:\n" + "\n".join(
                    f"- From {m['from']}: {m['message']}" for m in new_inbox
                )
            history.append(
                {
                    "role": "user",
                    "content": (
                        f"exit_code={res.exit_code} timed_out={res.timed_out}\n"
                        f"stdout:\n{res.stdout or '(empty)'}\n"
                        f"stderr:\n{res.stderr or '(empty)'}"
                        f"{inbox_note}"
                    ),
                }
            )

    return {"round": round_id, "bot": bot, "status": status, "summary": summary}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a Hogman Bot Arena v1 session.")
    parser.add_argument("--state", type=Path, default=Path("/var/lib/hogman-arena/arena-state.json"))
    parser.add_argument("--prompts", type=Path, default=SCRIPT_DIR / "prompts.json")
    parser.add_argument("--runs-dir", type=Path, default=SCRIPT_DIR / "runs")
    parser.add_argument("--provider", default=os.environ.get("ARENA_LLM_PROVIDER", "gemini"), choices=["gemini", "openai-compat"])
    parser.add_argument("--model", default=os.environ.get("ARENA_LLM_MODEL"))
    parser.add_argument("--base-url", default=os.environ.get("ARENA_LLM_BASE_URL"))
    parser.add_argument("--max-total-tokens", type=int, default=150_000)
    parser.add_argument("--max-bot-tokens", type=int, default=60_000)
    parser.add_argument("--max-output-tokens", type=int, default=2048)
    parser.add_argument("--max-history-chars", type=int, default=DEFAULT_MAX_HISTORY_CHARS)
    parser.add_argument("--cmd-timeout", type=int, default=45)
    parser.add_argument("--kicked-handle", default="mallory-out")
    args = parser.parse_args()

    if not args.state.is_file():
        print(f"ERROR: arena state file not found at {args.state}. Run 'sudo test-arena/arena.sh up' first.", file=sys.stderr)
        return 2

    state = json.loads(args.state.read_text(encoding="utf-8"))
    prompts = load_prompts(args.prompts)
    response_schema = prompts["response_schema"]
    shared_env_prompt = prompts["shared_environment"]["prompt"]

    run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.runs_dir / run_ts
    run_dir.mkdir(parents=True, exist_ok=True)

    ledger = TokenLedger(
        max_total_tokens=args.max_total_tokens,
        max_bot_tokens=args.max_bot_tokens,
    )
    client = LLMClient(
        provider=args.provider,
        model=args.model,
        base_url=args.base_url,
        ledger=ledger,
        max_output_tokens=args.max_output_tokens,
    )

    bots: dict[str, str] = state["bots"]
    pen_a = state["pen_a"]
    bus = MessageBus(allowed_bots=set(bots.keys()), log_path=run_dir / "messages.jsonl")
    histories: dict[str, list[dict[str, str]]] = {b: [] for b in bots}

    template_vars = {
        "alice_join_link": state["alice_join_link"],
        "pen_a_zone": pen_a["zone"],
        "pen_a_gate": pen_a["gate"],
        "pen_b_zone": state["pen_b"]["zone"],
        "pen_b_gate": state["pen_b"]["gate"],
    }

    round_results: list[dict[str, Any]] = []
    controls: dict[str, Any] = {}
    postkick_canary: str | None = None
    run_error: str | None = None

    print(f"=== Hogman Bot Arena v1 (run={run_ts}, provider={client.provider}, model={client.model}) ===")
    try:
        for round_cfg in prompts["rounds"]:
            if round_cfg.get("rotate_canary_before"):
                postkick_canary = rotate_pen_canary(Path(state["arena_home"]), pen_a["name"], phase="POSTKICK")
                print(f"[{round_cfg['id']}] rotated Pen A vault canary to fresh post-kick token")

            bot = round_cfg["bot"]
            role_cfg = prompts["roles"][bot]
            system_prompt = f"{role_cfg['system_prompt']}\n\n{shared_env_prompt}"
            round_prompt = round_cfg["prompt_template"].format(**template_vars)

            res = run_bot_round(
                bot=bot,
                container=bots[bot],
                round_cfg=round_cfg,
                round_prompt=round_prompt,
                system_prompt=system_prompt,
                response_schema=response_schema,
                history=histories[bot],
                client=client,
                bus=bus,
                transcript_path=run_dir / f"{bot}.jsonl",
                cmd_timeout_s=args.cmd_timeout,
                max_history_chars=args.max_history_chars,
            )
            round_results.append(res)

            # Record host-side positive controls before kick/final evaluation so
            # the Judge never relies on a bot's writable config.json or treats a
            # failed join as "blocked".
            if round_cfg["id"] == "round_2_mallory_insider_attack":
                ctrl = record_positive_control(
                    bots["mallory-insider"], pen_a["zone"], pen_a["vault_url"], pen_a["initial_canary"]
                )
                controls["mallory-insider"] = ctrl
                print(f"[control] mallory-insider joined Pen A: verified={ctrl['verified']} ({ctrl['detail']})")
            elif round_cfg["id"] == "round_3_mallory_kicked_prekick":
                ctrl = record_positive_control(
                    bots["mallory-kicked"], pen_a["zone"], pen_a["vault_url"], pen_a["initial_canary"]
                )
                controls["mallory-kicked"] = ctrl
                print(f"[control] mallory-kicked pre-kick Pen A: verified={ctrl['verified']} ({ctrl['detail']})")
    except Exception as exc:  # noqa: BLE001
        run_error = f"{type(exc).__name__}: {exc}"
        print(f"[arena] unexpected orchestrator error: {run_error}", file=sys.stderr)
    finally:
        (run_dir / "controls.json").write_text(json.dumps(controls, indent=2) + "\n", encoding="utf-8")
        usage_report = {
            "run_id": run_ts,
            "provider": client.provider,
            "model": client.model,
            "error": run_error,
            "rounds": round_results,
            "tokens": ledger.to_dict(),
        }
        (run_dir / "usage.json").write_text(json.dumps(usage_report, indent=2) + "\n", encoding="utf-8")

    print("\n=== Token Accounting ===")
    tok = usage_report["tokens"]
    print(f"Total: {tok['total_tokens']} tokens across {tok['total_api_calls']} API calls (budget: {tok['max_total_tokens']})")
    for b, u in tok["by_bot"].items():
        print(f"  {b:18} total={u['total_tokens']} (in={u['input_tokens']}, out={u['output_tokens']}, calls={u['api_calls']})")

    verdict = run_judge(
        state_path=args.state,
        run_dir=run_dir,
        repo_root=REPO_ROOT,
        kicked_handle=args.kicked_handle,
        postkick_canary=postkick_canary,
        controls=controls,
    )
    print(format_verdict(verdict))
    print(f"\nArtifacts saved to: {run_dir}")
    if run_error:
        return 1
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
