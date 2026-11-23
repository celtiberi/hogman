"""Docker sandbox command runner and inter-bot message bus for Hogman Bot Arena."""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MAX_OUTPUT_BYTES = 12_000


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class ExecResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int
    truncated: bool


def truncate_output(text: str, limit: int = MAX_OUTPUT_BYTES) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text, False
    head = encoded[:limit].decode("utf-8", errors="ignore")
    return f"{head}\n...[truncated {len(encoded) - limit} bytes]", True


def exec_in_container(
    container: str,
    command: str,
    timeout_s: int = 45,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
) -> ExecResult:
    """Execute a shell command inside an already-running bot sandbox container."""
    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(
            ["docker", "exec", container, "bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        rc = proc.returncode
        raw_out = proc.stdout or ""
        raw_err = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        rc = 124
        raw_out = (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        raw_err = (exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        raw_err = (raw_err + f"\ncommand timed out after {timeout_s}s").strip()

    duration_ms = int((time.monotonic() - started) * 1000)
    stdout, trunc_out = truncate_output(raw_out, max_output_bytes)
    stderr, trunc_err = truncate_output(raw_err, max_output_bytes)
    return ExecResult(
        command=command,
        exit_code=rc,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        duration_ms=duration_ms,
        truncated=trunc_out or trunc_err,
    )


class MessageBus:
    """Simple in-memory + JSONL-logged message bus so bots can pass invite links."""

    def __init__(self, allowed_bots: set[str], log_path: Path | None = None) -> None:
        self.allowed_bots = set(allowed_bots)
        self.log_path = log_path
        self._inboxes: dict[str, list[dict[str, Any]]] = {b: [] for b in self.allowed_bots}
        self._history: list[dict[str, Any]] = []

    def send(self, sender: str, recipient: str, body: str, round_id: str = "") -> dict[str, Any]:
        if recipient not in self.allowed_bots:
            raise ValueError(f"unknown recipient {recipient!r}; allowed: {sorted(self.allowed_bots)}")
        if sender == recipient:
            raise ValueError("cannot send a message to yourself")
        event = {
            "ts": utc_now(),
            "round": round_id,
            "from": sender,
            "to": recipient,
            "message": body,
        }
        self._inboxes[recipient].append(event)
        self._history.append(event)
        if self.log_path is not None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event) + "\n")
        return event

    def drain_inbox(self, bot: str) -> list[dict[str, Any]]:
        msgs = list(self._inboxes.get(bot, []))
        self._inboxes[bot] = []
        return msgs

    @property
    def history(self) -> list[dict[str, Any]]:
        return list(self._history)
