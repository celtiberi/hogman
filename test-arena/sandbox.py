"""Docker sandbox command runner and inter-bot message bus for Hogman Bot Arena."""

from __future__ import annotations

import json
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, IO


MAX_OUTPUT_BYTES = 12_000
MAX_MESSAGE_CHARS = 512
MAX_MESSAGES_PER_ROUND = 4


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


def build_docker_exec_cmd(container: str, command: str, timeout_s: int) -> list[str]:
    """Run commands under in-container GNU `timeout -k 5` so timed-out processes die cleanly."""
    return [
        "docker",
        "exec",
        container,
        "timeout",
        "-k",
        "5",
        str(int(timeout_s)),
        "bash",
        "-c",
        command,
    ]


def _drain_pipe_bounded(pipe: IO[bytes] | None, limit: int, out_slot: list[Any]) -> None:
    """Read from `pipe` incrementally, retaining at most `limit` bytes in host memory."""
    if pipe is None:
        out_slot.extend([b"", 0])
        return
    kept = bytearray()
    total_bytes = 0
    try:
        while True:
            chunk = pipe.read(4096)
            if not chunk:
                break
            total_bytes += len(chunk)
            remaining = limit - len(kept)
            if remaining > 0:
                kept.extend(chunk[:remaining])
    except OSError:
        pass
    finally:
        try:
            pipe.close()
        except OSError:
            pass
    out_slot.extend([bytes(kept), total_bytes])


def run_bounded_subprocess(
    cmd: list[str],
    timeout_s: int,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str, bool, bool]:
    """Run `cmd` with bounded incremental stdout/stderr buffering to prevent host OOM."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    out_slot: list[Any] = []
    err_slot: list[Any] = []
    t_out = threading.Thread(target=_drain_pipe_bounded, args=(proc.stdout, max_output_bytes, out_slot), daemon=True)
    t_err = threading.Thread(target=_drain_pipe_bounded, args=(proc.stderr, max_output_bytes, err_slot), daemon=True)
    t_out.start()
    t_err.start()

    timed_out = False
    try:
        rc = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        rc = 124
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    t_out.join(timeout=2)
    t_err.join(timeout=2)

    raw_out = out_slot[0] if len(out_slot) >= 1 else b""
    tot_out = out_slot[1] if len(out_slot) >= 2 else len(raw_out)
    raw_err = err_slot[0] if len(err_slot) >= 1 else b""
    tot_err = err_slot[1] if len(err_slot) >= 2 else len(raw_err)

    stdout = raw_out.decode("utf-8", errors="replace")
    stderr = raw_err.decode("utf-8", errors="replace")
    trunc_out = tot_out > max_output_bytes
    trunc_err = tot_err > max_output_bytes
    if trunc_out:
        stdout = f"{stdout}\n...[truncated {tot_out - max_output_bytes} bytes]"
    if trunc_err:
        stderr = f"{stderr}\n...[truncated {tot_err - max_output_bytes} bytes]"
    return rc, stdout, stderr, timed_out, (trunc_out or trunc_err)


def exec_in_container(
    container: str,
    command: str,
    timeout_s: int = 45,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
) -> ExecResult:
    """Execute a shell command inside an already-running bot sandbox container."""
    started = time.monotonic()
    exec_cmd = build_docker_exec_cmd(container, command, timeout_s)
    rc, stdout, stderr, outer_timed_out, truncated = run_bounded_subprocess(
        exec_cmd,
        timeout_s=timeout_s + 10,
        max_output_bytes=max_output_bytes,
    )
    elapsed = time.monotonic() - started
    timed_out = outer_timed_out or rc == 124 or (rc == 137 and elapsed >= max(1, timeout_s - 1))
    if timed_out and "timed out" not in stderr:
        stderr = (stderr + f"\ncommand timed out after {timeout_s}s and was terminated").strip()

    duration_ms = int(elapsed * 1000)
    return ExecResult(
        command=command,
        exit_code=rc,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        duration_ms=duration_ms,
        truncated=truncated,
    )


class MessageBus:
    """Bounded, route-restricted in-memory + JSONL-logged message bus."""

    def __init__(
        self,
        allowed_bots: set[str],
        log_path: Path | None = None,
        max_message_chars: int = MAX_MESSAGE_CHARS,
        max_messages_per_round: int = MAX_MESSAGES_PER_ROUND,
    ) -> None:
        self.allowed_bots = set(allowed_bots)
        self.log_path = log_path
        self.max_message_chars = max_message_chars
        self.max_messages_per_round = max_messages_per_round
        self._inboxes: dict[str, list[dict[str, Any]]] = {b: [] for b in self.allowed_bots}
        self._history: list[dict[str, Any]] = []
        self._round_counts: dict[tuple[str, str], int] = {}

    def send(
        self,
        sender: str,
        recipient: str,
        body: str,
        round_id: str = "",
        allowed_recipients: set[str] | None = None,
    ) -> dict[str, Any]:
        if recipient not in self.allowed_bots:
            raise ValueError(f"unknown recipient {recipient!r}; allowed: {sorted(self.allowed_bots)}")
        if sender == recipient:
            raise ValueError("cannot send a message to yourself")
        if allowed_recipients is not None and recipient not in allowed_recipients:
            raise ValueError(
                f"messaging {recipient!r} is not permitted in round {round_id!r} (allowed: {sorted(allowed_recipients)})"
            )
        if not isinstance(body, str) or not body.strip():
            raise ValueError("message body must be a non-empty string")
        if len(body) > self.max_message_chars:
            raise ValueError(f"message exceeds {self.max_message_chars} character limit ({len(body)} chars)")
        key = (round_id, sender)
        sent = self._round_counts.get(key, 0)
        if sent >= self.max_messages_per_round:
            raise ValueError(f"message limit ({self.max_messages_per_round}) reached for round {round_id!r}")
        self._round_counts[key] = sent + 1

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
