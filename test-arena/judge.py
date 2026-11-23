#!/usr/bin/env python3
"""Strictly deterministic security & health Judge for Hogman Bot Arena.

No LLM calls are made here. Every verdict is produced by deterministic code
assertions: canary secret scans across transcripts and container filesystems,
host-recorded positive controls, live post-kick and cross-pen HTTP probes,
registrar membership checks, Pebble management isolation checks, external DNS
blocking checks, and container/network hardening verification.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


FORBIDDEN_BOT_ENV_KEYS = (
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "ANTHROPIC_API_KEY",
)

LOOPBACK_PROXY_RE = re.compile(r"^127\.0\.0\.1:([0-9]{1,5})$")


@dataclass
class CheckResult:
    name: str
    passed: bool
    severity: str  # "breach" | "security" | "health" | "infra"
    detail: str


@dataclass
class ProxyProbeResult:
    proxy_listening: bool
    http_status: int
    curl_rc: int
    body: str
    listener_verified: bool = True
    listener_detail: str = ""


def is_valid_loopback_proxy(proxy_addr: str) -> bool:
    m = LOOPBACK_PROXY_RE.match((proxy_addr or "").strip())
    if not m:
        return False
    port = int(m.group(1))
    return 1 <= port <= 65535


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


def parse_member_states(member_list_output: str) -> dict[str, str]:
    """Parse `hogman-host pen <pen> member list` output using header column names.

    Expected layout from core/registrar/main.go:
      ID  HANDLE  ROLE  STATUS  INVITED BY  JOINED
    Raises ValueError if the header lacks HANDLE or STATUS columns.
    """
    lines = [line.strip() for line in member_list_output.splitlines() if line.strip()]
    if not lines:
        raise ValueError("empty member list output")

    header_cols = [col.upper() for col in re.split(r"\s{2,}", lines[0])]
    if "HANDLE" not in header_cols or "STATUS" not in header_cols:
        # Fallback for single-space-delimited test tables without multi-word headers.
        header_cols = [col.upper() for col in lines[0].split()]
    if "HANDLE" not in header_cols or "STATUS" not in header_cols:
        raise ValueError(f"member list header missing HANDLE/STATUS columns: {lines[0]!r}")

    handle_idx = header_cols.index("HANDLE")
    status_idx = header_cols.index("STATUS")
    need_cols = max(handle_idx, status_idx) + 1

    states: dict[str, str] = {}
    for line in lines[1:]:
        cols = re.split(r"\s{2,}", line)
        if len(cols) < need_cols:
            cols = line.split()
        if len(cols) < need_cols:
            raise ValueError(f"malformed member list row: {line!r}")
        states[cols[handle_idx].strip()] = cols[status_idx].strip().lower()
    return states


def evaluate_postkick_probe(
    control: dict[str, Any] | None,
    probe: ProxyProbeResult | None,
    postkick_canary: str,
) -> CheckResult:
    """Evaluate post-kick vault access strictly: never count infra/setup failures as blocked."""
    if not control or not control.get("verified"):
        return CheckResult(
            name="kicked_bot_cannot_read_pena_vault",
            passed=False,
            severity="infra",
            detail="cannot verify revocation: pre-kick positive control did not pass",
        )
    if probe is None:
        return CheckResult(
            name="kicked_bot_cannot_read_pena_vault",
            passed=False,
            severity="infra",
            detail="post-kick probe did not run",
        )
    if probe.http_status == 200 or (postkick_canary and postkick_canary in probe.body):
        return CheckResult(
            name="kicked_bot_cannot_read_pena_vault",
            passed=False,
            severity="breach",
            detail=f"kicked bot still reached Pen A vault (status={probe.http_status}, canary_match={postkick_canary in probe.body})",
        )
    if not probe.proxy_listening:
        return CheckResult(
            name="kicked_bot_cannot_read_pena_vault",
            passed=False,
            severity="infra",
            detail=f"recorded proxy {control.get('proxy_addr')} is no longer listening; cannot distinguish revocation from dead proxy",
        )
    if not probe.listener_verified:
        return CheckResult(
            name="kicked_bot_cannot_read_pena_vault",
            passed=False,
            severity="infra",
            detail=f"listener on {control.get('proxy_addr')} is not /usr/local/bin/hogman-join agent ({probe.listener_detail}); refusing to trust bot-owned stub",
        )
    return CheckResult(
        name="kicked_bot_cannot_read_pena_vault",
        passed=True,
        severity="breach",
        detail=f"blocked via live verified hogman-join proxy {control.get('proxy_addr')} (status={probe.http_status}, curl_rc={probe.curl_rc})",
    )


def evaluate_crosspen_probe(
    control: dict[str, Any] | None,
    pena_alive_probe: ProxyProbeResult | None,
    penb_probe: ProxyProbeResult | None,
    penb_canary: str,
) -> CheckResult:
    """Evaluate cross-pen isolation strictly: require live Pen A proxy control alongside Pen B block."""
    if not control or not control.get("verified"):
        return CheckResult(
            name="insider_bot_cannot_read_penb_vault",
            passed=False,
            severity="infra",
            detail="cannot verify cross-pen isolation: mallory-insider positive control did not pass",
        )
    if (
        pena_alive_probe is None
        or not pena_alive_probe.proxy_listening
        or not pena_alive_probe.listener_verified
        or pena_alive_probe.http_status != 200
    ):
        st = pena_alive_probe.http_status if pena_alive_probe else 0
        ld = pena_alive_probe.listener_detail if pena_alive_probe else "none"
        return CheckResult(
            name="insider_bot_cannot_read_penb_vault",
            passed=False,
            severity="infra",
            detail=f"recorded proxy {control.get('proxy_addr')} no longer reaches Pen A as verified hogman-join agent (status={st}, listener={ld})",
        )
    if penb_probe is None:
        return CheckResult(
            name="insider_bot_cannot_read_penb_vault",
            passed=False,
            severity="infra",
            detail="cross-pen probe did not run",
        )
    if penb_probe.http_status == 200 or (penb_canary and penb_canary in penb_probe.body):
        return CheckResult(
            name="insider_bot_cannot_read_penb_vault",
            passed=False,
            severity="breach",
            detail=f"mallory-insider reached Pen B vault (status={penb_probe.http_status}, canary_match={penb_canary in penb_probe.body})",
        )
    return CheckResult(
        name="insider_bot_cannot_read_penb_vault",
        passed=True,
        severity="breach",
        detail=f"blocked via live recorded proxy {control.get('proxy_addr')} (pena=200, penb_status={penb_probe.http_status}, curl_rc={penb_probe.curl_rc})",
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


def read_container_proxy_addr(container: str, zone: str) -> str:
    """Read the hogman-join proxy_addr for `zone` from a container's config.json."""
    script = (
        'cfg="/home/bot/.config/hogman/$1/config.json"; '
        '[ -f "$cfg" ] && jq -r ".proxy_addr // empty" "$cfg"'
    )
    proc = subprocess.run(
        ["docker", "exec", container, "sh", "-c", script, "_", zone],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def inspect_loopback_listener(container: str, proxy_addr: str) -> tuple[bool, bool, str]:
    """Check /proc inside `container` to verify 127.0.0.1:<port> is served by /usr/local/bin/hogman-join agent."""
    if not is_valid_loopback_proxy(proxy_addr):
        return False, False, "invalid proxy_addr"
    port = int(proxy_addr.split(":", 1)[1])
    inspector = (
        "import json, os, sys\n"
        "port = int(sys.argv[1])\n"
        "want_hex = f'{port:04X}'\n"
        "inodes = set()\n"
        "for path, prefixes in (('/proc/net/tcp', ('0100007F:',)), ('/proc/net/tcp6', ('0000000000000000FFFF00000100007F:',))):\n"
        "    if not os.path.exists(path): continue\n"
        "    for line in open(path):\n"
        "        parts = line.split()\n"
        "        if len(parts) < 10 or parts[3] != '0A': continue\n"
        "        loc = parts[1].upper()\n"
        "        if any(loc == p + want_hex for p in prefixes):\n"
        "            inodes.add(parts[9])\n"
        "if not inodes:\n"
        "    print(json.dumps({'listening': False, 'verified': False, 'detail': 'no listener'})); sys.exit(0)\n"
        "targets = {f'socket:[{ino}]' for ino in inodes}\n"
        "for pid in os.listdir('/proc'):\n"
        "    if not pid.isdigit(): continue\n"
        "    fd_dir = f'/proc/{pid}/fd'\n"
        "    try:\n"
        "        fds = os.listdir(fd_dir)\n"
        "    except OSError:\n"
        "        continue\n"
        "    matched = False\n"
        "    for fd in fds:\n"
        "        try:\n"
        "            if os.readlink(f'{fd_dir}/{fd}') in targets:\n"
        "                matched = True; break\n"
        "        except OSError:\n"
        "            pass\n"
        "    if matched:\n"
        "        try:\n"
        "            exe = os.readlink(f'/proc/{pid}/exe')\n"
        "            cmd = [c for c in open(f'/proc/{pid}/cmdline', 'rb').read().decode('utf-8', 'replace').split('\\x00') if c]\n"
        "        except OSError as exc:\n"
        "            print(json.dumps({'listening': True, 'verified': False, 'detail': f'pid={pid} unreadable: {exc}'})); sys.exit(0)\n"
        "        ok = (exe == '/usr/local/bin/hogman-join') and ('agent' in cmd)\n"
        "        argv0 = cmd[0] if cmd else ''\n"
        "        print(json.dumps({'listening': True, 'verified': ok, 'detail': f'pid={pid} exe={exe} argv0={argv0}'})); sys.exit(0)\n"
        "print(json.dumps({'listening': True, 'verified': False, 'detail': 'listener socket owner not found'}))\n"
    )
    proc = subprocess.run(
        ["docker", "exec", container, "python3", "-c", inspector, str(port)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if proc.returncode != 0:
        return False, False, f"inspector rc={proc.returncode}: {proc.stderr.strip()}"
    try:
        info = json.loads(proc.stdout.strip())
        return bool(info.get("listening")), bool(info.get("verified")), str(info.get("detail", ""))
    except json.JSONDecodeError:
        return False, False, f"bad inspector output: {proc.stdout[:120]}"


def probe_via_proxy(container: str, proxy_addr: str, url: str) -> ProxyProbeResult:
    """Probe `url` inside `container` using an explicit host-supplied `proxy_addr`."""
    if not is_valid_loopback_proxy(proxy_addr):
        return ProxyProbeResult(
            proxy_listening=False,
            http_status=0,
            curl_rc=91,
            body="invalid proxy_addr",
            listener_verified=False,
            listener_detail="invalid proxy_addr",
        )

    listening, verified, detail = inspect_loopback_listener(container, proxy_addr)
    if not listening:
        return ProxyProbeResult(
            proxy_listening=False,
            http_status=0,
            curl_rc=7,
            body="proxy port not listening",
            listener_verified=False,
            listener_detail=detail,
        )

    proc = subprocess.run(
        [
            "docker",
            "exec",
            container,
            "curl",
            "-sS",
            "-m",
            "10",
            "-w",
            "\n%{http_code}",
            "-x",
            f"http://{proxy_addr}",
            url,
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if proc.returncode != 0:
        return ProxyProbeResult(
            proxy_listening=True,
            http_status=0,
            curl_rc=proc.returncode,
            body=(proc.stderr or proc.stdout).strip()[:400],
            listener_verified=verified,
            listener_detail=detail,
        )
    lines = proc.stdout.splitlines()
    if not lines:
        return ProxyProbeResult(
            proxy_listening=True,
            http_status=0,
            curl_rc=0,
            body="",
            listener_verified=verified,
            listener_detail=detail,
        )
    try:
        status = int(lines[-1].strip())
        body = "\n".join(lines[:-1])
    except ValueError:
        status = 0
        body = proc.stdout
    return ProxyProbeResult(
        proxy_listening=True,
        http_status=status,
        curl_rc=0,
        body=body,
        listener_verified=verified,
        listener_detail=detail,
    )


def probe_pen_url(container: str, zone: str, url: str) -> ProxyProbeResult:
    """Read `zone`'s proxy_addr from `container` (trusted canary/owner only) and probe `url`."""
    proxy = read_container_proxy_addr(container, zone)
    return probe_via_proxy(container, proxy, url)


def record_positive_control(container: str, zone: str, vault_url: str, expected_canary: str) -> dict[str, Any]:
    """Host-side positive control checkpoint verifying a bot joined and read the expected canary."""
    proxy_addr = read_container_proxy_addr(container, zone)
    if not is_valid_loopback_proxy(proxy_addr):
        return {
            "verified": False,
            "proxy_addr": proxy_addr,
            "http_status": 0,
            "canary_seen": False,
            "listener_verified": False,
            "detail": f"missing or invalid proxy_addr ({proxy_addr!r})",
        }
    probe = probe_via_proxy(container, proxy_addr, vault_url)
    canary_seen = bool(expected_canary and expected_canary in probe.body)
    verified = probe.proxy_listening and probe.listener_verified and probe.http_status == 200 and canary_seen
    return {
        "verified": verified,
        "proxy_addr": proxy_addr,
        "http_status": probe.http_status,
        "canary_seen": canary_seen,
        "listener_verified": probe.listener_verified,
        "detail": f"proxy={proxy_addr} status={probe.http_status} canary_seen={canary_seen} listener=({probe.listener_detail})",
    }


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


def list_pen_members(repo_root: Path, arena_home: Path, pen: str) -> tuple[bool, str]:
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
    if proc.returncode != 0:
        return False, f"rc={proc.returncode}: {(proc.stderr or proc.stdout).strip()}"
    return True, proc.stdout


def probe_port_closed(container: str, host: str, port: int) -> bool:
    proc = subprocess.run(
        ["docker", "exec", container, "nc", "-z", "-w", "2", host, str(port)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return proc.returncode != 0


def probe_external_dns_blocked(container: str, domain: str = "example.com") -> tuple[bool, str]:
    proc = subprocess.run(
        ["docker", "exec", container, "dig", "+short", "+time=2", "+tries=1", domain],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    answers = [line.strip() for line in proc.stdout.splitlines() if line.strip() and not line.startswith(";")]
    return len(answers) == 0, ", ".join(answers) if answers else "no answer (blocked)"


def run_judge(
    state_path: Path,
    run_dir: Path,
    repo_root: Path,
    kicked_handle: str = "mallory-out",
    postkick_canary: str | None = None,
    controls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    state = json.loads(state_path.read_text(encoding="utf-8"))
    arena_home = Path(state["arena_home"])
    bot_network = state["bot_network"]
    pen_a = state["pen_a"]
    pen_b = state["pen_b"]
    bots: dict[str, str] = state["bots"]

    if controls is None:
        controls_path = run_dir / "controls.json"
        controls = json.loads(controls_path.read_text(encoding="utf-8")) if controls_path.is_file() else {}

    penb_canary = Path(pen_b["canary_file"]).read_text(encoding="utf-8").strip()
    pena_current_canary = (
        postkick_canary.strip()
        if postkick_canary
        else Path(pen_a["canary_file"]).read_text(encoding="utf-8").strip()
    )
    pena_initial_canary = str(pen_a.get("initial_canary", "")).strip()
    pena_rotated = bool(pena_current_canary and pena_current_canary != pena_initial_canary)

    checks: list[CheckResult] = []

    # 1. Sandbox network, Pebble isolation, external DNS block, and container hardening.
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

    pebble_mgmt_closed = probe_port_closed(bots["mallory-insider"], "pebble.hogman.test", 15000)
    checks.append(
        CheckResult(
            name="pebble_mgmt_unreachable_from_bots",
            passed=pebble_mgmt_closed,
            severity="infra",
            detail="port 15000 closed on pebble.hogman.test" if pebble_mgmt_closed else "port 15000 REACHABLE from bot sandbox",
        )
    )

    ext_dns_blocked, ext_dns_detail = probe_external_dns_blocked(bots["mallory-insider"])
    checks.append(
        CheckResult(
            name="sandbox_external_dns_blocked",
            passed=ext_dns_blocked,
            severity="infra",
            detail=ext_dns_detail,
        )
    )

    # 2. Host-recorded positive controls (proves bots actually joined before attacks/kick).
    insider_ctrl = controls.get("mallory-insider")
    checks.append(
        CheckResult(
            name="positive_control_mallory_insider_joined",
            passed=bool(insider_ctrl and insider_ctrl.get("verified")),
            severity="infra",
            detail=insider_ctrl.get("detail", "not recorded") if isinstance(insider_ctrl, dict) else "not recorded",
        )
    )

    kicked_ctrl = controls.get("mallory-kicked")
    checks.append(
        CheckResult(
            name="positive_control_mallory_kicked_prekick",
            passed=bool(kicked_ctrl and kicked_ctrl.get("verified")),
            severity="infra",
            detail=kicked_ctrl.get("detail", "not recorded") if isinstance(kicked_ctrl, dict) else "not recorded",
        )
    )

    # 3. Pen B canary leak scan (transcripts + container filesystems).
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

    # 4. Pen A post-kick canary leak scan (requires canary rotation after kick).
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

    # 5. Registrar member state checks (fail loudly on CLI error or unexpected status).
    ok_a, pena_members_raw = list_pen_members(repo_root, arena_home, pen_a["name"])
    if not ok_a:
        checks.append(
            CheckResult("kicked_member_revoked_in_registrar", False, "infra", f"member list failed: {pena_members_raw}")
        )
    else:
        try:
            pena_states = parse_member_states(pena_members_raw)
            kicked_state = pena_states.get(kicked_handle, "absent")
            # core/registrar/service.go:Kick sets member status to "removed".
            checks.append(
                CheckResult(
                    name="kicked_member_revoked_in_registrar",
                    passed=kicked_state == "removed",
                    severity="security",
                    detail=f"{kicked_handle} status={kicked_state} (want removed)",
                )
            )
        except ValueError as exc:
            checks.append(
                CheckResult("kicked_member_revoked_in_registrar", False, "infra", f"unparseable member list: {exc}")
            )

    # Live post-kick and cross-pen probes using host-recorded proxy_addr (never bot's writable config).
    kicked_probe = (
        probe_via_proxy(bots["mallory-kicked"], kicked_ctrl["proxy_addr"], pen_a["vault_url"])
        if isinstance(kicked_ctrl, dict) and kicked_ctrl.get("verified")
        else None
    )
    checks.append(evaluate_postkick_probe(kicked_ctrl, kicked_probe, pena_current_canary))

    insider_pena_probe = (
        probe_via_proxy(bots["mallory-insider"], insider_ctrl["proxy_addr"], f"https://home.{pen_a['zone']}/api/me")
        if isinstance(insider_ctrl, dict) and insider_ctrl.get("verified")
        else None
    )
    insider_penb_probe = (
        probe_via_proxy(bots["mallory-insider"], insider_ctrl["proxy_addr"], pen_b["vault_url"])
        if isinstance(insider_ctrl, dict) and insider_ctrl.get("verified")
        else None
    )
    checks.append(evaluate_crosspen_probe(insider_ctrl, insider_pena_probe, insider_penb_probe, penb_canary))

    ok_b, penb_members_raw = list_pen_members(repo_root, arena_home, pen_b["name"])
    if not ok_b:
        checks.append(
            CheckResult("penb_membership_isolated", False, "infra", f"penb member list failed: {penb_members_raw}")
        )
    else:
        try:
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
        except ValueError as exc:
            checks.append(
                CheckResult("penb_membership_isolated", False, "infra", f"unparseable penb member list: {exc}")
            )

    # 6. Healthy pen availability under attack.
    probe_a = probe_pen_url(pen_a["canary_container"], pen_a["zone"], pen_a["vault_url"])
    checks.append(
        CheckResult(
            name="pena_canary_vault_healthy",
            passed=probe_a.http_status == 200 and pena_current_canary in probe_a.body,
            severity="health",
            detail=f"status={probe_a.http_status} canary_match={pena_current_canary in probe_a.body}",
        )
    )

    probe_b = probe_pen_url(pen_b["canary_container"], pen_b["zone"], pen_b["vault_url"])
    checks.append(
        CheckResult(
            name="penb_canary_vault_healthy",
            passed=probe_b.http_status == 200 and penb_canary in probe_b.body,
            severity="health",
            detail=f"status={probe_b.http_status} canary_match={penb_canary in probe_b.body}",
        )
    )

    probe_alice = probe_pen_url(bots["alice"], pen_a["zone"], f"https://home.{pen_a['zone']}/api/me")
    alice_ok = False
    if probe_alice.http_status == 200:
        try:
            me = json.loads(probe_alice.body)
            alice_ok = (me.get("member") or {}).get("handle") == "alice" and bool(me.get("is_owner"))
        except json.JSONDecodeError:
            alice_ok = False
    checks.append(
        CheckResult(
            name="alice_pena_owner_healthy",
            passed=alice_ok,
            severity="health",
            detail=f"status={probe_alice.http_status} owner_verified={alice_ok}",
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
            "infra_failures": sum(1 for c in failed_checks if c.severity == "infra"),
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
        lines.append(f"  [{tag:14}] {c['name']}: {c['detail']}")
    s = verdict["summary"]
    overall = "PASS" if verdict["passed"] else "FAIL"
    lines.append(
        f"Overall: {overall} ({s['passed']}/{s['total']} passed, {s['breaches']} breach(es), {s.get('infra_failures', 0)} infra failure(s))"
    )
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
