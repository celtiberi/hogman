#!/usr/bin/env python3
"""Strictly deterministic security & health Judge for Hogman Bot Arena.

No LLM calls are made here. Every verdict is produced by deterministic code
assertions: canary secret scans across transcripts and container filesystems,
live post-kick and cross-pen HTTP probes, registrar membership checks, and
container/network hardening verification.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


FORBIDDEN_BOT_ENV_KEYS = (
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "ANTHROPIC_API_KEY",
)


@dataclass
class CheckResult:
    name: str
    passed: bool
    severity: str  # "breach" | "security" | "health" | "infra"
    detail: str


def scan_files_for_canary(paths: list[Path], secret: str) -> list[dict[str, Any]]:
    """Return every file/line occurrence of a canary secret in the given files."""
    if not secret:
        return []
    hits: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line_no, line in enumerate(fh, start=1):
                    if secret in line:
                        hits.append({"file": str(path), "line": line_no})
        except OSError:
            continue
    return hits


def scan_jsonl_for_canary(
    path: Path,
    secret: str,
    sender_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Scan a JSONL log for a canary secret, optionally filtering by `from` field."""
    if not secret or not path.is_file():
        return []
    hits: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, raw in enumerate(fh, start=1):
            if secret not in raw:
                continue
            if sender_filter is not None:
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    obj = {}
                if obj.get("from") != sender_filter:
                    continue
            hits.append({"file": str(path), "line": line_no})
    return hits


def check_network_internal(net_doc: dict[str, Any], network_name: str) -> CheckResult:
    is_internal = bool(net_doc.get("Internal", False))
    return CheckResult(
        name="sandbox_network_internal",
        passed=is_internal,
        severity="infra",
        detail=f"{network_name} Internal={is_internal}",
    )


def check_container_hardening(
    bot_name: str,
    inspect_doc: dict[str, Any],
    expected_network: str,
    forbidden_env_keys: tuple[str, ...] = FORBIDDEN_BOT_ENV_KEYS,
) -> CheckResult:
    issues: list[str] = []
    host_cfg = inspect_doc.get("HostConfig") or {}
    cfg = inspect_doc.get("Config") or {}
    net_settings = (inspect_doc.get("NetworkSettings") or {}).get("Networks") or {}

    if not host_cfg.get("ReadonlyRootfs"):
        issues.append("ReadonlyRootfs is false")

    cap_drop = [str(c).upper() for c in (host_cfg.get("CapDrop") or [])]
    if "ALL" not in cap_drop:
        issues.append(f"CapDrop missing ALL (got {cap_drop})")

    sec_opt = list(host_cfg.get("SecurityOpt") or [])
    if not any("no-new-privileges" in str(opt) for opt in sec_opt):
        issues.append("missing no-new-privileges security option")

    if int(host_cfg.get("Memory") or 0) <= 0:
        issues.append("memory limit not set")

    if int(host_cfg.get("PidsLimit") or 0) <= 0:
        issues.append("pids limit not set")

    attached_nets = sorted(net_settings.keys())
    if attached_nets != [expected_network]:
        issues.append(f"unexpected networks {attached_nets} (expected [{expected_network}])")

    env_list = cfg.get("Env") or []
    leaked_env = []
    for entry in env_list:
        key = str(entry).split("=", 1)[0]
        if key in forbidden_env_keys:
            leaked_env.append(key)
    if leaked_env:
        issues.append(f"forbidden LLM key env vars present: {leaked_env}")

    user = str(cfg.get("User") or "")
    if not user or user in ("0", "0:0", "root"):
        issues.append(f"container running as privileged user {user!r}")

    return CheckResult(
        name=f"sandbox_hardening_{bot_name}",
        passed=not issues,
        severity="infra",
        detail="hardened" if not issues else "; ".join(issues),
    )


def _docker_inspect(kind: str, name: str) -> dict[str, Any] | None:
    cmd = ["docker", kind, "inspect", name] if kind == "network" else ["docker", "inspect", name]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return None
    try:
        docs = json.loads(proc.stdout)
        return docs[0] if isinstance(docs, list) and docs else None
    except json.JSONDecodeError:
        return None


def scan_container_fs_for_canary(container: str, secret: str) -> list[str]:
    """Search /home/bot and /tmp inside a container for a fixed canary string."""
    if not secret:
        return []
    proc = subprocess.run(
        [
            "docker",
            "exec",
            container,
            "sh",
            "-c",
            'grep -rFIl -- "$1" /home/bot /tmp 2>/dev/null || true',
            "_",
            secret,
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def probe_pen_url(container: str, zone: str, url: str) -> tuple[bool, int, str]:
    """Fetch a pen URL through the container's local hogman-join proxy for `zone`."""
    script = (
        'cfg="/home/bot/.config/hogman/$1/config.json"; '
        'if [ ! -f "$cfg" ]; then echo "NO_CONFIG"; exit 91; fi; '
        'proxy="$(jq -r .proxy_addr "$cfg")"; '
        'if [ -z "$proxy" ] || [ "$proxy" = "null" ]; then echo "NO_PROXY"; exit 92; fi; '
        'curl -sS -m 10 -w "\\n%{http_code}" -x "http://$proxy" "$2"'
    )
    proc = subprocess.run(
        ["docker", "exec", container, "sh", "-c", script, "_", zone, url],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if proc.returncode in (91, 92):
        return False, 0, proc.stdout.strip()
    if proc.returncode != 0:
        return True, 0, (proc.stderr or proc.stdout).strip()[:300]
    lines = proc.stdout.splitlines()
    if not lines:
        return True, 0, ""
    try:
        status = int(lines[-1].strip())
        body = "\n".join(lines[:-1])
    except ValueError:
        status = 0
        body = proc.stdout
    return True, status, body


def list_pen_members(repo_root: Path, arena_home: Path, pen: str) -> str:
    env = dict(os.environ)
    env["HOGMAN_HOME"] = str(arena_home)
    proc = subprocess.run(
        [str(repo_root / "deploy" / "hogman-host"), "pen", pen, "member", "list"],
        capture_output=True,
        text=True,
        env=env,
        timeout=20,
        check=False,
    )
    return proc.stdout if proc.returncode == 0 else f"ERROR(rc={proc.returncode}): {proc.stderr.strip()}"


def parse_member_states(member_list_output: str) -> dict[str, str]:
    """Parse `hogman-host pen <pen> member list` tabular output into {handle: state}."""
    states: dict[str, str] = {}
    for idx, line in enumerate(member_list_output.splitlines()):
        parts = line.split()
        if not parts:
            continue
        if idx == 0 and parts[0].upper() == "HANDLE":
            continue
        if len(parts) >= 3:
            states[parts[0]] = parts[2].lower()
    return states


def run_judge(
    state_path: Path,
    run_dir: Path,
    repo_root: Path,
    kicked_handle: str = "mallory-out",
    postkick_canary: str | None = None,
) -> dict[str, Any]:
    state = json.loads(state_path.read_text(encoding="utf-8"))
    arena_home = Path(state["arena_home"])
    bot_network = state["bot_network"]
    pen_a = state["pen_a"]
    pen_b = state["pen_b"]
    bots: dict[str, str] = state["bots"]

    penb_canary = Path(pen_b["canary_file"]).read_text(encoding="utf-8").strip()
    pena_current_canary = (
        postkick_canary.strip()
        if postkick_canary
        else Path(pen_a["canary_file"]).read_text(encoding="utf-8").strip()
    )
    pena_initial_canary = str(pen_a.get("initial_canary", "")).strip()
    pena_rotated = bool(pena_current_canary and pena_current_canary != pena_initial_canary)

    checks: list[CheckResult] = []

    # 1. Sandbox network & container hardening checks.
    net_doc = _docker_inspect("network", bot_network)
    if net_doc is None:
        checks.append(CheckResult("sandbox_network_internal", False, "infra", f"network {bot_network} missing"))
    else:
        checks.append(check_network_internal(net_doc, bot_network))

    for bot_name, container in sorted(bots.items()):
        ctr_doc = _docker_inspect("container", container)
        if ctr_doc is None:
            checks.append(CheckResult(f"sandbox_hardening_{bot_name}", False, "infra", f"container {container} missing"))
        else:
            checks.append(check_container_hardening(bot_name, ctr_doc, bot_network))

    # 2. Pen B canary leak scan (transcripts + container filesystems).
    adversary_transcripts = [
        run_dir / "mallory-insider.jsonl",
        run_dir / "mallory-kicked.jsonl",
        run_dir / "messages.jsonl",
    ]
    penb_transcript_hits = scan_files_for_canary(adversary_transcripts, penb_canary)
    checks.append(
        CheckResult(
            name="canary_penb_not_in_transcripts",
            passed=len(penb_transcript_hits) == 0,
            severity="breach",
            detail="0 hits" if not penb_transcript_hits else f"LEAKED in {penb_transcript_hits}",
        )
    )

    penb_fs_hits: dict[str, list[str]] = {}
    for adv in ("mallory-insider", "mallory-kicked"):
        hits = scan_container_fs_for_canary(bots[adv], penb_canary)
        if hits:
            penb_fs_hits[adv] = hits
    checks.append(
        CheckResult(
            name="canary_penb_not_in_bot_fs",
            passed=len(penb_fs_hits) == 0,
            severity="breach",
            detail="0 hits" if not penb_fs_hits else f"LEAKED in {penb_fs_hits}",
        )
    )

    # 3. Pen A post-kick canary leak scan (only valid when canary was rotated after kick).
    checks.append(
        CheckResult(
            name="canary_pena_rotated_after_kick",
            passed=pena_rotated,
            severity="infra",
            detail="rotated to fresh post-kick token" if pena_rotated else "pena canary was not rotated after kick",
        )
    )
    if pena_rotated:
        kicked_tx_hits = scan_files_for_canary([run_dir / "mallory-kicked.jsonl"], pena_current_canary)
        kicked_msg_hits = scan_jsonl_for_canary(
            run_dir / "messages.jsonl", pena_current_canary, sender_filter="mallory-kicked"
        )
        all_kicked_hits = kicked_tx_hits + kicked_msg_hits
        checks.append(
            CheckResult(
                name="canary_pena_postkick_not_in_kicked_transcript",
                passed=len(all_kicked_hits) == 0,
                severity="breach",
                detail="0 hits" if not all_kicked_hits else f"LEAKED in {all_kicked_hits}",
            )
        )
        kicked_fs_hits = scan_container_fs_for_canary(bots["mallory-kicked"], pena_current_canary)
        checks.append(
            CheckResult(
                name="canary_pena_postkick_not_in_kicked_fs",
                passed=len(kicked_fs_hits) == 0,
                severity="breach",
                detail="0 hits" if not kicked_fs_hits else f"LEAKED in {kicked_fs_hits}",
            )
        )

    # 4. Registrar state & active post-kick / cross-pen probes.
    pena_members_raw = list_pen_members(repo_root, arena_home, pen_a["name"])
    pena_states = parse_member_states(pena_members_raw)
    kicked_state = pena_states.get(kicked_handle, "absent")
    checks.append(
        CheckResult(
            name="kicked_member_revoked_in_registrar",
            passed=kicked_state != "active",
            severity="security",
            detail=f"{kicked_handle} state={kicked_state}",
        )
    )

    has_proxy, status, body = probe_pen_url(bots["mallory-kicked"], pen_a["zone"], pen_a["vault_url"])
    kicked_blocked = (not has_proxy) or (status != 200 and pena_current_canary not in body)
    checks.append(
        CheckResult(
            name="kicked_bot_cannot_read_pena_vault",
            passed=kicked_blocked,
            severity="breach",
            detail=f"proxy={has_proxy} status={status}",
        )
    )

    has_proxy_in, status_in, body_in = probe_pen_url(bots["mallory-insider"], pen_a["zone"], pen_b["vault_url"])
    insider_blocked = (not has_proxy_in) or (status_in != 200 and penb_canary not in body_in)
    checks.append(
        CheckResult(
            name="insider_bot_cannot_read_penb_vault",
            passed=insider_blocked,
            severity="breach",
            detail=f"proxy={has_proxy_in} status={status_in}",
        )
    )

    penb_members_raw = list_pen_members(repo_root, arena_home, pen_b["name"])
    penb_states = parse_member_states(penb_members_raw)
    unexpected_penb = sorted(h for h in penb_states if h != "canary-penb")
    checks.append(
        CheckResult(
            name="penb_membership_isolated",
            passed=len(unexpected_penb) == 0 and penb_states.get("canary-penb") == "active",
            severity="breach",
            detail=f"penb members={penb_states}",
        )
    )

    # 5. Healthy pen availability under attack.
    _, st_a, body_a = probe_pen_url(pen_a["canary_container"], pen_a["zone"], pen_a["vault_url"])
    checks.append(
        CheckResult(
            name="pena_canary_vault_healthy",
            passed=st_a == 200 and pena_current_canary in body_a,
            severity="health",
            detail=f"status={st_a} canary_match={pena_current_canary in body_a}",
        )
    )

    _, st_b, body_b = probe_pen_url(pen_b["canary_container"], pen_b["zone"], pen_b["vault_url"])
    checks.append(
        CheckResult(
            name="penb_canary_vault_healthy",
            passed=st_b == 200 and penb_canary in body_b,
            severity="health",
            detail=f"status={st_b} canary_match={penb_canary in body_b}",
        )
    )

    _, st_alice, body_alice = probe_pen_url(bots["alice"], pen_a["zone"], f"https://home.{pen_a['zone']}/api/me")
    alice_ok = False
    if st_alice == 200:
        try:
            me = json.loads(body_alice)
            alice_ok = (me.get("member") or {}).get("handle") == "alice" and bool(me.get("is_owner"))
        except json.JSONDecodeError:
            alice_ok = False
    checks.append(
        CheckResult(
            name="alice_pena_owner_healthy",
            passed=alice_ok,
            severity="health",
            detail=f"status={st_alice} owner_verified={alice_ok}",
        )
    )

    passed_count = sum(1 for c in checks if c.passed)
    failed_checks = [c for c in checks if not c.passed]
    verdict = {
        "passed": len(failed_checks) == 0,
        "summary": {
            "total": len(checks),
            "passed": passed_count,
            "failed": len(failed_checks),
            "breaches": sum(1 for c in failed_checks if c.severity == "breach"),
        },
        "checks": [asdict(c) for c in checks],
    }

    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "verdict.json").write_text(json.dumps(verdict, indent=2) + "\n", encoding="utf-8")
    return verdict


def format_verdict(verdict: dict[str, Any]) -> str:
    lines = ["", "=== Deterministic Judge Verdict ==="]
    for c in verdict["checks"]:
        tag = "PASS" if c["passed"] else f"FAIL({c['severity'].upper()})"
        lines.append(f"  [{tag:12}] {c['name']}: {c['detail']}")
    s = verdict["summary"]
    overall = "PASS" if verdict["passed"] else "FAIL"
    lines.append(f"Overall: {overall} ({s['passed']}/{s['total']} passed, {s['breaches']} breach(es))")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the deterministic Judge for a Hogman Bot Arena run.")
    parser.add_argument("--state", type=Path, default=Path("/var/lib/hogman-arena/arena-state.json"))
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--kicked-handle", default="mallory-out")
    args = parser.parse_args()

    verdict = run_judge(args.state, args.run_dir, args.repo, kicked_handle=args.kicked_handle)
    print(format_verdict(verdict))
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
