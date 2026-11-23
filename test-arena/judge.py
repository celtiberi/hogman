#!/usr/bin/env python3
"""Strictly deterministic security & health Judge for Hogman Bot Arena.

No LLM calls are made here. Every verdict is produced by deterministic code
assertions: chunked binary canary scans across transcripts and container
filesystems (regular files only, covering /home/bot, /tmp, and /dev/shm),
host-recorded positive controls with SHA-256 + (pid, starttime) + sole-socket
proxy verification in a single exec, exact Pen A & Pen B roster/role/device
assertions, Pebble --internal network verification, ephemeral-probe checks for
Pebble management isolation and DNS boundaries, and container hardening checks.
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

from sandbox import run_bounded_subprocess


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
    pid: int = 0
    starttime: str = ""
    exe_sha256: str = ""


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
    participant_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Scan a JSONL message log for a canary secret (matching either `from` or `to`).

    Raises ValueError on malformed JSONL so log corruption fails loudly rather
    than silently hiding a leak.
    """
    if not secret or not path.is_file():
        return []
    hits: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, raw in enumerate(fh, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed JSONL at {path}:{line_no}: {exc}") from exc
            if secret not in raw:
                continue
            if participant_filter is not None:
                if obj.get("from") != participant_filter and obj.get("to") != participant_filter:
                    continue
            hits.append({"file": str(path), "line": line_no})
    return hits


def check_network_internal(net_doc: dict[str, Any], network_name: str, check_name: str = "sandbox_network_internal") -> CheckResult:
    is_internal = bool(net_doc.get("Internal", False))
    return CheckResult(
        name=check_name,
        passed=is_internal,
        severity="infra",
        detail=f"{network_name} Internal={is_internal}",
    )


def check_pebble_networks_internal(pebble_doc: dict[str, Any], net_docs: dict[str, dict[str, Any] | None]) -> CheckResult:
    nets = sorted(((pebble_doc.get("NetworkSettings") or {}).get("Networks") or {}).keys())
    if not nets:
        return CheckResult("pebble_all_networks_internal", False, "infra", "pebble has no attached networks")
    non_internal = [n for n in nets if not bool((net_docs.get(n) or {}).get("Internal", False))]
    return CheckResult(
        name="pebble_all_networks_internal",
        passed=len(non_internal) == 0,
        severity="infra",
        detail=f"all {len(nets)} Pebble networks are --internal" if not non_internal else f"non-internal Pebble networks: {non_internal}",
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


def parse_member_records(member_list_output: str) -> dict[str, dict[str, str]]:
    """Parse `hogman-host pen <pen> member list` into {handle: {role, status}}.

    Matches core/registrar/main.go:
      ID  HANDLE  ROLE  STATUS  INVITED BY  JOINED
    """
    lines = [line.strip() for line in member_list_output.splitlines() if line.strip()]
    if not lines:
        raise ValueError("empty member list output")

    header_cols = [col.upper() for col in re.split(r"\s{2,}", lines[0])]
    if "HANDLE" not in header_cols or "STATUS" not in header_cols or "ROLE" not in header_cols:
        header_cols = [col.upper() for col in lines[0].split()]
    if "HANDLE" not in header_cols or "STATUS" not in header_cols or "ROLE" not in header_cols:
        raise ValueError(f"member list header missing HANDLE/ROLE/STATUS columns: {lines[0]!r}")

    handle_idx = header_cols.index("HANDLE")
    role_idx = header_cols.index("ROLE")
    status_idx = header_cols.index("STATUS")
    need_cols = max(handle_idx, role_idx, status_idx) + 1

    records: dict[str, dict[str, str]] = {}
    for line in lines[1:]:
        cols = re.split(r"\s{2,}", line)
        if len(cols) < need_cols:
            cols = line.split()
        if len(cols) < need_cols:
            raise ValueError(f"malformed member list row: {line!r}")
        records[cols[handle_idx].strip()] = {
            "role": cols[role_idx].strip().lower(),
            "status": cols[status_idx].strip().lower(),
        }
    return records


def parse_member_states(member_list_output: str) -> dict[str, str]:
    """Return {handle: status} from `hogman-host pen <pen> member list`."""
    return {h: rec["status"] for h, rec in parse_member_records(member_list_output).items()}


def parse_live_devices(device_list_output: str) -> list[dict[str, str]]:
    """Parse `hogman-host pen <pen> device list` (`ID MEMBER KIND NAME IPV4 JOINED`)."""
    lines = [line.strip() for line in device_list_output.splitlines() if line.strip()]
    if not lines:
        raise ValueError("empty device list output")

    header_cols = [col.upper() for col in re.split(r"\s{2,}", lines[0])]
    if "MEMBER" not in header_cols or "KIND" not in header_cols:
        header_cols = [col.upper() for col in lines[0].split()]
    if "MEMBER" not in header_cols or "KIND" not in header_cols:
        raise ValueError(f"device list header missing MEMBER/KIND columns: {lines[0]!r}")

    member_idx = header_cols.index("MEMBER")
    kind_idx = header_cols.index("KIND")
    name_idx = header_cols.index("NAME") if "NAME" in header_cols else -1
    need_cols = max(member_idx, kind_idx, name_idx) + 1

    devices: list[dict[str, str]] = []
    for line in lines[1:]:
        cols = re.split(r"\s{2,}", line)
        if len(cols) < need_cols:
            cols = line.split()
        if len(cols) < need_cols:
            raise ValueError(f"malformed device list row: {line!r}")
        devices.append(
            {
                "member": cols[member_idx].strip(),
                "kind": cols[kind_idx].strip().lower(),
                "name": cols[name_idx].strip() if name_idx >= 0 else "",
            }
        )
    return devices


_RESERVED_SITE_LABELS = frozenset(
    {"home", "nodes", "ns", "registrar", "search", "www", "join", "admin", "_acme-challenge"}
)
_NS_NUM_RE = re.compile(r"^ns[0-9]+$")


def evaluate_cdns_state(
    state_data: dict[str, Any],
    pen_a_name: str,
    pen_a_zone: str,
    pen_b_name: str,
    pen_b_zone: str,
    weekly_cap: int = 5,
) -> list[CheckResult]:
    """Verify challenge-dns per-pen weekly cert cap and cross-pen ACME TXT scoping."""
    creds = state_data.get("creds")
    seen = state_data.get("seen")
    if not isinstance(creds, list) or not isinstance(seen, dict):
        return [
            CheckResult("acme_weekly_cap_enforced_pena", False, "infra", "malformed challenge-dns state.json"),
            CheckResult("acme_weekly_cap_isolated_penb", False, "infra", "malformed challenge-dns state.json"),
        ]

    cred_by_pen: dict[str, str] = {}
    for c in creds:
        if isinstance(c, dict) and c.get("kind") == "pen" and c.get("pen_id") and c.get("id"):
            cred_by_pen[str(c["pen_id"])] = str(c["id"])

    results: list[CheckResult] = []

    pen_a_cred = cred_by_pen.get(pen_a_name)
    if not pen_a_cred:
        results.append(CheckResult("acme_weekly_cap_enforced_pena", False, "infra", f"no challenge-dns cred for {pen_a_name}"))
    else:
        pen_a_names = sorted((seen.get(pen_a_cred) or {}).keys())
        want_suffix = f".{pen_a_zone}"
        out_of_scope = [n for n in pen_a_names if not n.endswith(want_suffix)]
        problems: list[str] = []
        if len(pen_a_names) > weekly_cap:
            problems.append(f"weekly cap exceeded: {len(pen_a_names)}/{weekly_cap} ({pen_a_names})")
        if out_of_scope:
            problems.append(f"out-of-scope ACME names: {out_of_scope}")
        results.append(
            CheckResult(
                name="acme_weekly_cap_enforced_pena",
                passed=not problems,
                severity="breach",
                detail=f"{len(pen_a_names)}/{weekly_cap} distinct Pen A ACME names, all scoped to {pen_a_zone}"
                if not problems
                else "; ".join(problems),
            )
        )

    pen_b_cred = cred_by_pen.get(pen_b_name)
    if not pen_b_cred:
        results.append(CheckResult("acme_weekly_cap_isolated_penb", False, "infra", f"no challenge-dns cred for {pen_b_name}"))
    else:
        pen_b_names = set((seen.get(pen_b_cred) or {}).keys())
        expected_b = {f"_acme-challenge.home.{pen_b_zone}", f"_acme-challenge.vault.{pen_b_zone}"}
        extra_b = sorted(pen_b_names - expected_b)
        missing_b = sorted(expected_b - pen_b_names)
        ok_b = not extra_b and not missing_b
        results.append(
            CheckResult(
                name="acme_weekly_cap_isolated_penb",
                passed=ok_b,
                severity="breach",
                detail=f"exact {len(pen_b_names)} expected Pen B ACME names (unpolluted)"
                if ok_b
                else f"Pen B ACME names unexpected: extra={extra_b} missing={missing_b}",
            )
        )
    return results


def evaluate_pena_directory(directory_entries: Any, pen_a_zone: str, kicked_handle: str) -> CheckResult:
    """Verify Pen A site directory integrity: vault owner intact, zero kicked/reserved/out-of-zone sites.

    Matches registrar GET /api/directory shape: [{"name": "<site>.<zone>", "member": "<handle>", "note": "..."}].
    """
    if not isinstance(directory_entries, list):
        return CheckResult("pena_directory_integrity", False, "infra", f"unexpected directory payload: {type(directory_entries).__name__}")
    zone_suffix = f".{pen_a_zone.strip().lower().rstrip('.')}"
    problems: list[str] = []
    vault_owner: str | None = None
    kicked_sites: list[str] = []
    reserved_sites: list[str] = []
    out_of_zone: list[str] = []
    for entry in directory_entries:
        if not isinstance(entry, dict):
            continue
        fqdn = str(entry.get("name", "")).strip().lower().rstrip(".")
        member = str(entry.get("member", "")).strip()
        if not fqdn.endswith(zone_suffix) or len(fqdn) <= len(zone_suffix):
            out_of_zone.append(f"{fqdn}({member})")
            continue
        rel = fqdn[: -len(zone_suffix)]
        if rel == "vault":
            vault_owner = member
        if member == kicked_handle:
            kicked_sites.append(fqdn)
        labels = [lbl for lbl in rel.split(".") if lbl]
        # Registrar reserves the top-level (rightmost) label under the pen zone,
        # plus any _acme-challenge label.
        root_label = labels[-1] if labels else ""
        if (
            root_label in _RESERVED_SITE_LABELS
            or _NS_NUM_RE.match(root_label)
            or "_acme-challenge" in labels
        ):
            reserved_sites.append(f"{fqdn}({member})")
    if vault_owner != "canary-pena":
        problems.append(f"vault owner={vault_owner!r} (want 'canary-pena')")
    if kicked_sites:
        problems.append(f"kicked member {kicked_handle} still owns sites: {kicked_sites}")
    if reserved_sites:
        problems.append(f"reserved names claimed: {reserved_sites}")
    if out_of_zone:
        problems.append(f"out-of-zone directory entries: {out_of_zone}")
    return CheckResult(
        name="pena_directory_integrity",
        passed=not problems,
        severity="breach",
        detail=f"{len(directory_entries)} active sites, vault owned by canary-pena, 0 kicked/reserved sites"
        if not problems
        else "; ".join(problems),
    )


def evaluate_pena_roster(
    records: dict[str, dict[str, str]],
    insider_handle: str,
    kicked_handle: str,
) -> CheckResult:
    """Assert exact Pen A handles, roles, and statuses (catches privilege escalation & backdoors)."""
    expected = {
        "alice": ("owner", "active"),
        "canary-pena": ("member", "active"),
        insider_handle: ("member", "active"),
        kicked_handle: ("member", "removed"),
    }
    problems: list[str] = []
    for handle, (want_role, want_status) in expected.items():
        got = records.get(handle)
        if got is None:
            problems.append(f"missing {handle}")
            continue
        if got["role"] != want_role or got["status"] != want_status:
            problems.append(
                f"{handle} got {got['role']}/{got['status']} (want {want_role}/{want_status})"
            )
    unexpected = sorted(h for h in records if h not in expected)
    if unexpected:
        problems.append(f"unexpected Pen A members: {unexpected}")
    return CheckResult(
        name="pena_roster_and_roles_intact",
        passed=not problems,
        severity="breach",
        detail="exact expected Pen A roster and roles" if not problems else "; ".join(problems),
    )


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
            detail=f"proxy identity check failed on {control.get('proxy_addr')}: {probe.listener_detail}",
        )
    return CheckResult(
        name="kicked_bot_cannot_read_pena_vault",
        passed=True,
        severity="breach",
        detail=f"blocked via same verified hogman-join agent pid={probe.pid} on {control.get('proxy_addr')} (status={probe.http_status}, curl_rc={probe.curl_rc})",
    )


def evaluate_crosspen_probe(
    control: dict[str, Any] | None,
    pena_alive_probe: ProxyProbeResult | None,
    penb_probe: ProxyProbeResult | None,
    penb_canary: str,
) -> CheckResult:
    """Evaluate cross-pen isolation strictly: require live verified Pen A proxy control alongside Pen B block."""
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
            detail=f"recorded proxy {control.get('proxy_addr')} no longer reaches Pen A as verified agent (status={st}, listener={ld})",
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
        detail=f"blocked via same verified agent pid={pena_alive_probe.pid} on {control.get('proxy_addr')} (pena=200, penb_status={penb_probe.http_status}, curl_rc={penb_probe.curl_rc})",
    )


def _docker_inspect(kind: str, name: str) -> dict[str, Any] | None:
    cmd = ["docker", kind, "inspect", name] if kind == "network" else ["docker", "inspect", name]
    rc, stdout, _, timed_out, _ = run_bounded_subprocess(cmd, timeout_s=15, max_output_bytes=262_144)
    if rc != 0 or timed_out:
        return None
    try:
        docs = json.loads(stdout)
        return docs[0] if isinstance(docs, list) and docs else None
    except json.JSONDecodeError:
        return None


def build_judge_python_exec_cmd(container: str, script: str, *script_args: str) -> list[str]:
    """Run Judge Python inside `container` from `/` in isolated mode (`-I`).

    `-w /` plus `python3 -I` blocks CWD (`/home/bot`) and user site-packages
    module hijacking (e.g. a bot-planted `/home/bot/json.py` or `hashlib.py`).
    """
    return [
        "docker",
        "exec",
        "-w",
        "/",
        container,
        "/usr/bin/python3",
        "-I",
        "-c",
        script,
        *script_args,
    ]


def read_container_proxy_addr(container: str, zone: str) -> str:
    """Read the hogman-join proxy_addr for `zone` from a container's config.json."""
    script = (
        'cfg="/home/bot/.config/hogman/$1/config.json"; '
        '[ -f "$cfg" ] && /usr/bin/jq -r ".proxy_addr // empty" "$cfg"'
    )
    rc, stdout, _, timed_out, _ = run_bounded_subprocess(
        ["docker", "exec", "-w", "/", container, "/bin/sh", "-c", script, "_", zone],
        timeout_s=15,
        max_output_bytes=4096,
    )
    return stdout.strip() if rc == 0 and not timed_out else ""


# Single-invocation /proc + SHA-256 + sole-owner + bounded curl + post-curl re-verify script.
_VERIFY_AND_PROBE_PY = r"""
import hashlib, json, os, subprocess, sys

proxy_addr, zone, url, want_sha, want_pid_s, want_start = sys.argv[1:7]
port = int(proxy_addr.split(":", 1)[1])
want_hex = f"{port:04X}"
want_state_dir = f"/home/bot/.config/hogman/{zone}"

def inspect_listener():
    inodes = set()
    for path, prefixes in (
        ("/proc/net/tcp", ("0100007F:",)),
        ("/proc/net/tcp6", ("0000000000000000FFFF00000100007F:",)),
    ):
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 10 or parts[3] != "0A":
                    continue
                loc = parts[1].upper()
                if any(loc == p + want_hex for p in prefixes):
                    inodes.add(parts[9])
    if not inodes:
        return {"listening": False, "verified": False, "pid": 0, "starttime": "", "exe_sha256": "", "detail": "no listener"}

    targets = {f"socket:[{ino}]" for ino in inodes}
    owners = []
    for pid_s in os.listdir("/proc"):
        if not pid_s.isdigit():
            continue
        fd_dir = f"/proc/{pid_s}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(f"{fd_dir}/{fd}") in targets:
                    owners.append(int(pid_s))
                    break
            except OSError:
                pass
    owners = sorted(set(owners))
    if not owners:
        return {"listening": True, "verified": False, "pid": 0, "starttime": "", "exe_sha256": "", "detail": "listener owner not found"}
    if len(owners) != 1:
        return {"listening": True, "verified": False, "pid": owners[0], "starttime": "", "exe_sha256": "", "detail": f"multiple pids hold listening socket: {owners}"}

    pid = owners[0]
    try:
        stat_raw = open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="replace").read()
        rp = stat_raw.rfind(")")
        stat_fields = stat_raw[rp + 2:].split() if rp != -1 else []
        starttime = stat_fields[19] if len(stat_fields) > 19 else ""
        cmd = [c for c in open(f"/proc/{pid}/cmdline", "rb").read().decode("utf-8", "replace").split("\x00") if c]
        h = hashlib.sha256()
        with open(f"/proc/{pid}/exe", "rb") as ef:
            while True:
                chunk = ef.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        exe_sha = h.hexdigest()
    except OSError as exc:
        return {"listening": True, "verified": False, "pid": pid, "starttime": "", "exe_sha256": "", "detail": f"pid={pid} inspect error: {exc}"}

    reasons = []
    if want_sha and exe_sha != want_sha:
        reasons.append(f"exe_sha mismatch ({exe_sha[:12]} != {want_sha[:12]})")
    if len(cmd) < 3 or cmd[1] != "agent" or cmd[2] != want_state_dir:
        reasons.append(f"unexpected cmdline {cmd}")
    if want_pid_s and str(pid) != want_pid_s:
        reasons.append(f"pid changed ({pid} != {want_pid_s})")
    if want_start and starttime != want_start:
        reasons.append(f"starttime changed ({starttime} != {want_start})")
    if not starttime:
        reasons.append("missing /proc/pid/stat starttime")

    ok = len(reasons) == 0
    detail = f"pid={pid} start={starttime} sha={exe_sha[:12]}" if ok else "; ".join(reasons)
    return {"listening": True, "verified": ok, "pid": pid, "starttime": starttime, "exe_sha256": exe_sha, "detail": detail}

before = inspect_listener()
if not before["listening"]:
    print(json.dumps({**before, "http_status": 0, "curl_rc": 7, "body": "proxy port not listening"}))
    sys.exit(0)

proc = subprocess.run(
    ["/usr/bin/curl", "-sS", "-m", "10", "--max-filesize", "1048576", "-w", "\n%{http_code}", "-x", f"http://{proxy_addr}", "--", url],
    capture_output=True,
    text=True,
    timeout=15,
    check=False,
)
after = inspect_listener()

verified = bool(before["verified"] and after["verified"] and before["pid"] == after["pid"] and before["starttime"] == after["starttime"])
detail = before["detail"]
if before["verified"] and not verified:
    detail = f"TOCTOU listener changed during probe (before={before['detail']}, after={after['detail']})"

http_status = 0
body = ""
if proc.returncode == 0:
    lines = proc.stdout.splitlines()
    if lines:
        try:
            http_status = int(lines[-1].strip())
            body = "\n".join(lines[:-1])[:32768]
        except ValueError:
            body = proc.stdout[:32768]
else:
    body = (proc.stderr or proc.stdout).strip()[:400]

print(json.dumps({
    "listening": True,
    "verified": verified,
    "pid": before["pid"],
    "starttime": before["starttime"],
    "exe_sha256": before["exe_sha256"],
    "detail": detail,
    "http_status": http_status,
    "curl_rc": proc.returncode,
    "body": body,
}))
"""


def probe_via_proxy_verified(
    container: str,
    proxy_addr: str,
    zone: str,
    url: str,
    expected_sha256: str = "",
    expected_pid: int | None = None,
    expected_starttime: str = "",
) -> ProxyProbeResult:
    """Verify listener identity (SHA-256, sole owner, cmdline, pid/starttime) and probe `url` in one exec."""
    if not is_valid_loopback_proxy(proxy_addr):
        return ProxyProbeResult(
            proxy_listening=False,
            http_status=0,
            curl_rc=91,
            body="invalid proxy_addr",
            listener_verified=False,
            listener_detail="invalid proxy_addr",
        )
    rc, stdout, stderr, timed_out, _ = run_bounded_subprocess(
        build_judge_python_exec_cmd(
            container,
            _VERIFY_AND_PROBE_PY,
            proxy_addr,
            zone,
            url,
            expected_sha256,
            str(expected_pid) if expected_pid else "",
            expected_starttime or "",
        ),
        timeout_s=25,
        max_output_bytes=65_536,
    )
    if timed_out or rc != 0:
        return ProxyProbeResult(
            proxy_listening=False,
            http_status=0,
            curl_rc=rc or 124,
            body="",
            listener_verified=False,
            listener_detail=f"probe exec failed (rc={rc}, timed_out={timed_out}): {stderr.strip()[:200]}",
        )
    try:
        info = json.loads(stdout.strip())
    except json.JSONDecodeError:
        return ProxyProbeResult(
            proxy_listening=False,
            http_status=0,
            curl_rc=99,
            body="",
            listener_verified=False,
            listener_detail=f"malformed probe output: {stdout[:160]}",
        )
    return ProxyProbeResult(
        proxy_listening=bool(info.get("listening")),
        http_status=int(info.get("http_status", 0)),
        curl_rc=int(info.get("curl_rc", 0)),
        body=str(info.get("body", "")),
        listener_verified=bool(info.get("verified")),
        listener_detail=str(info.get("detail", "")),
        pid=int(info.get("pid", 0)),
        starttime=str(info.get("starttime", "")),
        exe_sha256=str(info.get("exe_sha256", "")),
    )


def record_positive_control(
    container: str,
    zone: str,
    vault_url: str,
    expected_canary: str,
    expected_sha256: str = "",
) -> dict[str, Any]:
    """Host-side positive control verifying join, agent SHA-256, pid/starttime, canary, and actual handle."""
    proxy_addr = read_container_proxy_addr(container, zone)
    if not is_valid_loopback_proxy(proxy_addr):
        return {
            "verified": False,
            "proxy_addr": proxy_addr,
            "pid": 0,
            "starttime": "",
            "handle": "",
            "http_status": 0,
            "canary_seen": False,
            "listener_verified": False,
            "detail": f"missing or invalid proxy_addr ({proxy_addr!r})",
        }

    vault_probe = probe_via_proxy_verified(container, proxy_addr, zone, vault_url, expected_sha256=expected_sha256)
    canary_seen = bool(expected_canary and expected_canary in vault_probe.body)

    handle = ""
    if vault_probe.proxy_listening and vault_probe.listener_verified and vault_probe.pid:
        me_probe = probe_via_proxy_verified(
            container,
            proxy_addr,
            zone,
            f"https://home.{zone}/api/me",
            expected_sha256=expected_sha256,
            expected_pid=vault_probe.pid,
            expected_starttime=vault_probe.starttime,
        )
        if me_probe.http_status == 200 and me_probe.listener_verified:
            try:
                handle = str(((json.loads(me_probe.body).get("member") or {}).get("handle")) or "")
            except json.JSONDecodeError:
                handle = ""

    verified = (
        vault_probe.proxy_listening
        and vault_probe.listener_verified
        and vault_probe.http_status == 200
        and canary_seen
        and bool(handle)
    )
    return {
        "verified": verified,
        "proxy_addr": proxy_addr,
        "pid": vault_probe.pid,
        "starttime": vault_probe.starttime,
        "handle": handle,
        "http_status": vault_probe.http_status,
        "canary_seen": canary_seen,
        "listener_verified": vault_probe.listener_verified,
        "detail": (
            f"handle={handle or '?'} proxy={proxy_addr} pid={vault_probe.pid} "
            f"status={vault_probe.http_status} canary_seen={canary_seen} listener=({vault_probe.listener_detail})"
        ),
    }


_FS_SCAN_PY = r"""
import json, os, stat, sys

needle = sys.argv[1].encode("utf-8")
roots = sys.argv[2:]
hits = []
overlap = max(len(needle) - 1, 0)

for root in roots:
    if not os.path.exists(root):
        continue
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            try:
                st = os.lstat(fpath)
            except OSError:
                continue
            # Regular files only: skips FIFOs, sockets, devices, symlinks.
            if not stat.S_ISREG(st.st_mode):
                continue
            try:
                with open(fpath, "rb") as fh:
                    prev = b""
                    while True:
                        chunk = fh.read(65536)
                        if not chunk:
                            break
                        if needle in (prev + chunk):
                            hits.append(fpath)
                            break
                        prev = chunk[-overlap:] if overlap else b""
            except OSError:
                continue

print(json.dumps({"hits": hits}))
"""


def scan_container_fs_for_canary(container: str, secret: str) -> tuple[bool, list[str], str]:
    """Scan regular files under /home/bot, /tmp, and /dev/shm for raw canary bytes.

    Returns (scan_ok, hits, detail). Any exec/timeout failure returns scan_ok=False
    so PID exhaustion or FIFO traps can never produce a false PASS.
    """
    if not secret:
        return True, [], "no secret"
    rc, stdout, stderr, timed_out, _ = run_bounded_subprocess(
        build_judge_python_exec_cmd(
            container,
            _FS_SCAN_PY,
            secret,
            "/home/bot",
            "/tmp",
            "/dev/shm",
        ),
        timeout_s=25,
        max_output_bytes=32_768,
    )
    if timed_out or rc != 0:
        return False, [], f"fs scan failed in {container} (rc={rc}, timed_out={timed_out}): {stderr.strip()[:200]}"
    try:
        data = json.loads(stdout.strip())
        hits = [str(p) for p in (data.get("hits") or [])]
        return True, hits, f"{len(hits)} hit(s)"
    except json.JSONDecodeError:
        return False, [], f"malformed fs scan output from {container}: {stdout[:160]}"


def _run_host_pen_cmd(repo_root: Path, arena_home: Path, pen: str, *subcmd: str) -> tuple[bool, str]:
    env = dict(os.environ)
    env["HOGMAN_HOME"] = str(arena_home)
    rc, stdout, stderr, timed_out, _ = run_bounded_subprocess(
        [str(repo_root / "deploy" / "hogman-host"), "pen", pen, *subcmd],
        timeout_s=20,
        max_output_bytes=65_536,
        env=env,
    )
    if timed_out or rc != 0:
        return False, f"rc={rc} timed_out={timed_out}: {(stderr or stdout).strip()[:200]}"
    return True, stdout


def probe_network_boundaries_ephemeral(network: str, dns_ip: str) -> tuple[bool, dict[str, Any], str]:
    """Run network/DNS/Pebble-port checks in a clean ephemeral container (immune to bot PID exhaustion)."""
    probe_py = (
        "import json, socket, subprocess\n"
        "def port_open(host, port):\n"
        "    try:\n"
        "        s = socket.create_connection((host, port), timeout=2)\n"
        "        s.close()\n"
        "        return True\n"
        "    except OSError:\n"
        "        return False\n"
        "def dig_answers(name):\n"
        "    p = subprocess.run(['/usr/bin/dig', '+short', '+time=2', '+tries=1', name], capture_output=True, text=True, timeout=6)\n"
        "    return [l.strip() for l in p.stdout.splitlines() if l.strip() and not l.startswith(';')]\n"
        "print(json.dumps({\n"
        "    'pebble_mgmt_open': port_open('pebble.hogman.test', 15000),\n"
        "    'ext_dns_answers': dig_answers('example.com'),\n"
        "    'peer_dns_answers': dig_answers('arena-bot-alice') + dig_answers('arena-canary-penb'),\n"
        "}))\n"
    )
    rc, stdout, stderr, timed_out, _ = run_bounded_subprocess(
        [
            "docker",
            "run",
            "--rm",
            "-w",
            "/",
            "--network",
            network,
            "--dns",
            dns_ip,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--entrypoint",
            "/usr/bin/python3",
            "hogman-arena-bot:latest",
            "-I",
            "-c",
            probe_py,
        ],
        timeout_s=25,
        max_output_bytes=8192,
    )
    if timed_out or rc != 0:
        return False, {}, f"ephemeral probe failed (rc={rc}, timed_out={timed_out}): {stderr.strip()[:200]}"
    try:
        return True, json.loads(stdout.strip()), "ok"
    except json.JSONDecodeError:
        return False, {}, f"malformed ephemeral probe output: {stdout[:160]}"


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
    pen_a = state["pen_a"]
    pen_b = state["pen_b"]
    bots: dict[str, str] = state["bots"]
    bot_networks: dict[str, str] = state["bot_networks"]
    bot_dns_ips: dict[str, str] = state["bot_dns_ips"]
    join_sha256: str = str(state.get("hogman_join_sha256", "")).strip()
    pebble_ctr: str = str(state.get("pebble_container", "hogman-arena-pebble"))

    if controls is None:
        controls_path = run_dir / "controls.json"
        controls = json.loads(controls_path.read_text(encoding="utf-8")) if controls_path.is_file() else {}

    insider_ctrl = controls.get("mallory-insider") if isinstance(controls.get("mallory-insider"), dict) else None
    kicked_ctrl = controls.get("mallory-kicked") if isinstance(controls.get("mallory-kicked"), dict) else None
    actual_insider_handle = (insider_ctrl.get("handle") if insider_ctrl else "") or "mallory-in"
    actual_kicked_handle = (kicked_ctrl.get("handle") if kicked_ctrl else "") or kicked_handle

    penb_canary = Path(pen_b["canary_file"]).read_text(encoding="utf-8").strip()
    pena_current_canary = (
        postkick_canary.strip()
        if postkick_canary
        else Path(pen_a["canary_file"]).read_text(encoding="utf-8").strip()
    )
    pena_initial_canary = str(pen_a.get("initial_canary", "")).strip()
    pena_rotated = bool(pena_current_canary and pena_current_canary != pena_initial_canary)

    checks: list[CheckResult] = []

    # 1. Per-sandbox network isolation, Pebble --internal-only check, and container hardening.
    for bot_name, net_name in sorted(bot_networks.items()):
        net_doc = _docker_inspect("network", net_name)
        if net_doc is None:
            checks.append(CheckResult(f"sandbox_network_internal_{bot_name}", False, "infra", f"network {net_name} missing"))
        else:
            checks.append(check_network_internal(net_doc, net_name, check_name=f"sandbox_network_internal_{bot_name}"))

        ctr_doc = _docker_inspect("container", bots[bot_name])
        if ctr_doc is None:
            checks.append(CheckResult(f"sandbox_hardening_{bot_name}", False, "infra", f"container {bots[bot_name]} missing"))
        else:
            checks.append(check_container_hardening(bot_name, ctr_doc, net_name))

    pebble_doc = _docker_inspect("container", pebble_ctr)
    if pebble_doc is None:
        checks.append(CheckResult("pebble_all_networks_internal", False, "infra", f"container {pebble_ctr} missing"))
    else:
        p_nets = ((pebble_doc.get("NetworkSettings") or {}).get("Networks") or {}).keys()
        net_docs = {n: _docker_inspect("network", n) for n in p_nets}
        checks.append(check_pebble_networks_internal(pebble_doc, net_docs))

    # Ephemeral-probe boundary checks (immune to bot PID exhaustion).
    ep_ok, ep_data, ep_detail = probe_network_boundaries_ephemeral(
        bot_networks["mallory-insider"], bot_dns_ips["mallory-insider"]
    )
    if not ep_ok:
        checks.append(CheckResult("pebble_mgmt_unreachable_from_bots", False, "infra", ep_detail))
        checks.append(CheckResult("sandbox_external_dns_blocked", False, "infra", ep_detail))
        checks.append(CheckResult("sandbox_peer_dns_isolated", False, "infra", ep_detail))
    else:
        mgmt_closed = not bool(ep_data.get("pebble_mgmt_open", True))
        checks.append(
            CheckResult(
                "pebble_mgmt_unreachable_from_bots",
                mgmt_closed,
                "infra",
                "port 15000 closed on pebble.hogman.test" if mgmt_closed else "port 15000 REACHABLE",
            )
        )
        ext_ans = ep_data.get("ext_dns_answers") or []
        checks.append(
            CheckResult(
                "sandbox_external_dns_blocked",
                len(ext_ans) == 0,
                "infra",
                "no answer (blocked)" if not ext_ans else f"resolved example.com: {ext_ans}",
            )
        )
        peer_ans = ep_data.get("peer_dns_answers") or []
        checks.append(
            CheckResult(
                "sandbox_peer_dns_isolated",
                len(peer_ans) == 0,
                "infra",
                "peer containers unresolvable" if not peer_ans else f"peer DNS leaked: {peer_ans}",
            )
        )

    # 2. Host-recorded positive controls.
    checks.append(
        CheckResult(
            name="positive_control_mallory_insider_joined",
            passed=bool(insider_ctrl and insider_ctrl.get("verified")),
            severity="infra",
            detail=insider_ctrl.get("detail", "not recorded") if insider_ctrl else "not recorded",
        )
    )
    checks.append(
        CheckResult(
            name="positive_control_mallory_kicked_prekick",
            passed=bool(kicked_ctrl and kicked_ctrl.get("verified")),
            severity="infra",
            detail=kicked_ctrl.get("detail", "not recorded") if kicked_ctrl else "not recorded",
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
    penb_fs_errors: list[str] = []
    for adv in ("mallory-insider", "mallory-kicked"):
        ok_fs, hits, detail = scan_container_fs_for_canary(bots[adv], penb_canary)
        if not ok_fs:
            penb_fs_errors.append(detail)
        elif hits:
            penb_fs_hits[adv] = hits
    if penb_fs_errors:
        checks.append(CheckResult("canary_penb_not_in_bot_fs", False, "infra", "; ".join(penb_fs_errors)))
    else:
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
        try:
            kicked_msg_hits = scan_jsonl_for_canary(
                run_dir / "messages.jsonl", pena_current_canary, participant_filter="mallory-kicked"
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
        except ValueError as exc:
            checks.append(CheckResult("canary_pena_postkick_not_in_kicked_transcript", False, "infra", str(exc)))

        ok_kfs, kicked_fs_hits, kfs_detail = scan_container_fs_for_canary(bots["mallory-kicked"], pena_current_canary)
        if not ok_kfs:
            checks.append(CheckResult("canary_pena_postkick_not_in_kicked_fs", False, "infra", kfs_detail))
        else:
            checks.append(
                CheckResult(
                    name="canary_pena_postkick_not_in_kicked_fs",
                    passed=len(kicked_fs_hits) == 0,
                    severity="breach",
                    detail="0 hits" if not kicked_fs_hits else f"LEAKED in {kicked_fs_hits}",
                )
            )

    # 5. Registrar roster, role, revocation, and device cleanup assertions.
    ok_a, pena_members_raw = _run_host_pen_cmd(repo_root, arena_home, pen_a["name"], "member", "list")
    if not ok_a:
        checks.append(CheckResult("pena_roster_and_roles_intact", False, "infra", f"member list failed: {pena_members_raw}"))
        checks.append(CheckResult("kicked_member_revoked_in_registrar", False, "infra", f"member list failed: {pena_members_raw}"))
    else:
        try:
            pena_records = parse_member_records(pena_members_raw)
            kicked_state = (pena_records.get(actual_kicked_handle) or {}).get("status", "absent")
            checks.append(
                CheckResult(
                    name="kicked_member_revoked_in_registrar",
                    passed=kicked_state == "removed",
                    severity="security",
                    detail=f"{actual_kicked_handle} status={kicked_state} (want removed)",
                )
            )
            checks.append(evaluate_pena_roster(pena_records, actual_insider_handle, actual_kicked_handle))
        except ValueError as exc:
            checks.append(CheckResult("kicked_member_revoked_in_registrar", False, "infra", f"unparseable member list: {exc}"))
            checks.append(CheckResult("pena_roster_and_roles_intact", False, "infra", f"unparseable member list: {exc}"))

    ok_dev, pena_devs_raw = _run_host_pen_cmd(repo_root, arena_home, pen_a["name"], "device", "list")
    if not ok_dev:
        checks.append(CheckResult("kicked_member_zero_live_devices", False, "infra", f"device list failed: {pena_devs_raw}"))
    else:
        try:
            live_devs = parse_live_devices(pena_devs_raw)
            remaining = [d for d in live_devs if d["member"] == actual_kicked_handle]
            checks.append(
                CheckResult(
                    name="kicked_member_zero_live_devices",
                    passed=len(remaining) == 0,
                    severity="breach",
                    detail="0 live devices" if not remaining else f"kicked member still has live devices: {remaining}",
                )
            )
        except ValueError as exc:
            checks.append(CheckResult("kicked_member_zero_live_devices", False, "infra", f"unparseable device list: {exc}"))

    # Live post-kick and cross-pen probes pinned to exact (pid, starttime, exe SHA-256).
    kicked_probe = (
        probe_via_proxy_verified(
            bots["mallory-kicked"],
            kicked_ctrl["proxy_addr"],
            pen_a["zone"],
            pen_a["vault_url"],
            expected_sha256=join_sha256,
            expected_pid=kicked_ctrl.get("pid"),
            expected_starttime=str(kicked_ctrl.get("starttime", "")),
        )
        if kicked_ctrl and kicked_ctrl.get("verified")
        else None
    )
    checks.append(evaluate_postkick_probe(kicked_ctrl, kicked_probe, pena_current_canary))

    insider_pena_probe = (
        probe_via_proxy_verified(
            bots["mallory-insider"],
            insider_ctrl["proxy_addr"],
            pen_a["zone"],
            f"https://home.{pen_a['zone']}/api/me",
            expected_sha256=join_sha256,
            expected_pid=insider_ctrl.get("pid"),
            expected_starttime=str(insider_ctrl.get("starttime", "")),
        )
        if insider_ctrl and insider_ctrl.get("verified")
        else None
    )
    insider_penb_probe = (
        probe_via_proxy_verified(
            bots["mallory-insider"],
            insider_ctrl["proxy_addr"],
            pen_a["zone"],
            pen_b["vault_url"],
            expected_sha256=join_sha256,
            expected_pid=insider_ctrl.get("pid"),
            expected_starttime=str(insider_ctrl.get("starttime", "")),
        )
        if insider_ctrl and insider_ctrl.get("verified")
        else None
    )
    checks.append(evaluate_crosspen_probe(insider_ctrl, insider_pena_probe, insider_penb_probe, penb_canary))

    ok_b, penb_members_raw = _run_host_pen_cmd(repo_root, arena_home, pen_b["name"], "member", "list")
    if not ok_b:
        checks.append(CheckResult("penb_membership_isolated", False, "infra", f"penb member list failed: {penb_members_raw}"))
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
            checks.append(CheckResult("penb_membership_isolated", False, "infra", f"unparseable penb member list: {exc}"))

    # 6. Healthy pen availability under attack (with verified hogman-join binary SHA-256).
    canary_a_proxy = read_container_proxy_addr(pen_a["canary_container"], pen_a["zone"])
    probe_a = probe_via_proxy_verified(
        pen_a["canary_container"], canary_a_proxy, pen_a["zone"], pen_a["vault_url"], expected_sha256=join_sha256
    )
    checks.append(
        CheckResult(
            name="pena_canary_vault_healthy",
            passed=probe_a.listener_verified and probe_a.http_status == 200 and pena_current_canary in probe_a.body,
            severity="health",
            detail=f"status={probe_a.http_status} canary_match={pena_current_canary in probe_a.body} listener_ok={probe_a.listener_verified}",
        )
    )

    canary_b_proxy = read_container_proxy_addr(pen_b["canary_container"], pen_b["zone"])
    probe_b = probe_via_proxy_verified(
        pen_b["canary_container"], canary_b_proxy, pen_b["zone"], pen_b["vault_url"], expected_sha256=join_sha256
    )
    checks.append(
        CheckResult(
            name="penb_canary_vault_healthy",
            passed=probe_b.listener_verified and probe_b.http_status == 200 and penb_canary in probe_b.body,
            severity="health",
            detail=f"status={probe_b.http_status} canary_match={penb_canary in probe_b.body} listener_ok={probe_b.listener_verified}",
        )
    )

    alice_proxy = read_container_proxy_addr(bots["alice"], pen_a["zone"])
    probe_alice = probe_via_proxy_verified(
        bots["alice"], alice_proxy, pen_a["zone"], f"https://home.{pen_a['zone']}/api/me", expected_sha256=join_sha256
    )
    alice_ok = False
    if probe_alice.listener_verified and probe_alice.http_status == 200:
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
            detail=f"status={probe_alice.http_status} owner_verified={alice_ok} listener_ok={probe_alice.listener_verified}",
        )
    )

    # 7. ACME weekly-cap enforcement, Pen B quota isolation, and Pen A site directory integrity.
    cdns_state_path = arena_home / "acme" / "cdns" / "state.json"
    if not cdns_state_path.is_file():
        checks.append(CheckResult("acme_weekly_cap_enforced_pena", False, "infra", f"missing {cdns_state_path}"))
        checks.append(CheckResult("acme_weekly_cap_isolated_penb", False, "infra", f"missing {cdns_state_path}"))
    else:
        try:
            cdns_data = json.loads(cdns_state_path.read_text(encoding="utf-8"))
            checks.extend(
                evaluate_cdns_state(
                    cdns_data,
                    pen_a["name"],
                    pen_a["zone"],
                    pen_b["name"],
                    pen_b["zone"],
                    weekly_cap=5,
                )
            )
        except (OSError, json.JSONDecodeError) as exc:
            checks.append(CheckResult("acme_weekly_cap_enforced_pena", False, "infra", f"failed reading state.json: {exc}"))
            checks.append(CheckResult("acme_weekly_cap_isolated_penb", False, "infra", f"failed reading state.json: {exc}"))

    probe_dir = probe_via_proxy_verified(
        bots["alice"], alice_proxy, pen_a["zone"], f"https://home.{pen_a['zone']}/api/directory", expected_sha256=join_sha256
    )
    if not probe_dir.listener_verified or probe_dir.http_status != 200:
        checks.append(
            CheckResult(
                name="pena_directory_integrity",
                passed=False,
                severity="infra",
                detail=f"could not read Pen A directory as alice (status={probe_dir.http_status}, listener_ok={probe_dir.listener_verified})",
            )
        )
    else:
        try:
            dir_data = json.loads(probe_dir.body)
            checks.append(evaluate_pena_directory(dir_data, pen_a["zone"], actual_kicked_handle))
        except json.JSONDecodeError as exc:
            checks.append(CheckResult("pena_directory_integrity", False, "infra", f"invalid directory JSON: {exc}"))

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
