"""Stdlib-only LLM client with declarative schema translation and token budgets.

Translates the JSON Schema from prompts.json into provider-native structured
output parameters (Gemini responseSchema by default, or OpenAI-compatible
json_schema for endpoints such as DeepSeek or OpenAI). Keeps API keys strictly
inside the host orchestrator process — never inside bot containers.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any


DEFAULT_MAX_OUTPUT_TOKENS = 4096
MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024


class BudgetExceededError(RuntimeError):
    """Raised when a bot or run exceeds its configured token budget."""


class LLMError(RuntimeError):
    """Raised on unrecoverable LLM HTTP or response parsing failures."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse HTTP redirects so API key headers are never forwarded off-origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise urllib.error.HTTPError(req.full_url, code, f"refusing redirect to {newurl}", headers, fp)


_HTTP_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def redact_secret(text: str, secret: str) -> str:
    if not secret:
        return text
    return text.replace(secret, "[REDACTED]")


@dataclass
class BotTokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    api_calls: int = 0
    estimated_calls: int = 0


@dataclass
class TokenLedger:
    max_total_tokens: int = 300_000
    max_bot_tokens: int = 120_000
    by_bot: dict[str, BotTokenUsage] = field(default_factory=dict)

    def _entry(self, bot: str) -> BotTokenUsage:
        if bot not in self.by_bot:
            self.by_bot[bot] = BotTokenUsage()
        return self.by_bot[bot]

    @property
    def total_tokens(self) -> int:
        return sum(u.total_tokens for u in self.by_bot.values())

    def check_budget(self, bot: str, projected_tokens: int = 0) -> None:
        proj = max(0, int(projected_tokens))
        if self.total_tokens >= self.max_total_tokens or (proj > 0 and self.total_tokens + proj > self.max_total_tokens):
            raise BudgetExceededError(
                f"run token budget exceeded (used={self.total_tokens}, projected={proj}, max={self.max_total_tokens})"
            )
        bot_total = self._entry(bot).total_tokens
        if bot_total >= self.max_bot_tokens or (proj > 0 and bot_total + proj > self.max_bot_tokens):
            raise BudgetExceededError(
                f"bot '{bot}' token budget exceeded (used={bot_total}, projected={proj}, max={self.max_bot_tokens})"
            )

    def record(
        self,
        bot: str,
        input_tokens: int,
        output_tokens: int,
        total_tokens: int | None = None,
        estimated: bool = False,
    ) -> None:
        in_tok = max(0, int(input_tokens))
        out_tok = max(0, int(output_tokens))
        tot_tok = max(in_tok + out_tok, int(total_tokens) if total_tokens is not None else in_tok + out_tok)
        entry = self._entry(bot)
        entry.input_tokens += in_tok
        entry.output_tokens += out_tok
        entry.total_tokens += tot_tok
        entry.api_calls += 1
        if estimated:
            entry.estimated_calls += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_total_tokens": self.max_total_tokens,
            "max_bot_tokens": self.max_bot_tokens,
            "total_input_tokens": sum(u.input_tokens for u in self.by_bot.values()),
            "total_output_tokens": sum(u.output_tokens for u in self.by_bot.values()),
            "total_tokens": self.total_tokens,
            "total_api_calls": sum(u.api_calls for u in self.by_bot.values()),
            "estimated_calls": sum(u.estimated_calls for u in self.by_bot.values()),
            "by_bot": {
                bot: {
                    "input_tokens": u.input_tokens,
                    "output_tokens": u.output_tokens,
                    "total_tokens": u.total_tokens,
                    "api_calls": u.api_calls,
                    "estimated_calls": u.estimated_calls,
                }
                for bot, u in sorted(self.by_bot.items())
            },
        }


def estimate_tokens(text: str) -> int:
    """Conservative ~4 chars/token fallback when an API omits usage metadata."""
    return max(1, (len(text) + 3) // 4)


def translate_schema_for_gemini(schema: dict[str, Any]) -> dict[str, Any]:
    """Translate standard JSON Schema into Gemini OpenAPI-subset responseSchema."""
    out: dict[str, Any] = {}
    type_map = {
        "object": "OBJECT",
        "array": "ARRAY",
        "string": "STRING",
        "integer": "INTEGER",
        "number": "NUMBER",
        "boolean": "BOOLEAN",
    }
    raw_type = schema.get("type")
    if isinstance(raw_type, str):
        out["type"] = type_map.get(raw_type.lower(), raw_type.upper())
    if "description" in schema:
        out["description"] = schema["description"]
    if "enum" in schema:
        out["enum"] = list(schema["enum"])
    if "required" in schema:
        out["required"] = list(schema["required"])
    if "properties" in schema and isinstance(schema["properties"], dict):
        out["properties"] = {
            k: translate_schema_for_gemini(v) for k, v in schema["properties"].items()
        }
    if "items" in schema and isinstance(schema["items"], dict):
        out["items"] = translate_schema_for_gemini(schema["items"])
    return out


def build_gemini_payload(
    system_prompt: str,
    messages: list[dict[str, str]],
    response_schema: dict[str, Any],
    temperature: float = 0.2,
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
) -> dict[str, Any]:
    contents = []
    for msg in messages:
        role = "model" if msg["role"] == "assistant" else "user"
        contents.append({"role": role, "parts": [{"text": msg["content"]}]})
    return {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": contents,
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": max_output_tokens,
            "responseMimeType": "application/json",
            "responseSchema": translate_schema_for_gemini(response_schema),
        },
    }


def build_openai_compat_payload(
    model: str,
    system_prompt: str,
    messages: list[dict[str, str]],
    response_schema: dict[str, Any],
    temperature: float = 0.2,
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
    use_json_schema: bool = True,
) -> dict[str, Any]:
    chat_messages = [{"role": "system", "content": system_prompt}] + [
        {"role": m["role"], "content": m["content"]} for m in messages
    ]
    base: dict[str, Any] = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_output_tokens,
        "messages": chat_messages,
    }
    if use_json_schema:
        base["response_format"] = {
            "type": "json_schema",
            "json_schema": {
                "name": "arena_bot_turn",
                "strict": True,
                "schema": response_schema,
            },
        }
    else:
        # Provider does not support response_format=json_schema (e.g. DeepSeek):
        # translate the declarative schema into a forced OpenAI function call.
        base["tools"] = [
            {
                "type": "function",
                "function": {
                    "name": "arena_bot_turn",
                    "description": "Submit the next structured arena action.",
                    "parameters": response_schema,
                },
            }
        ]
        base["tool_choice"] = {
            "type": "function",
            "function": {"name": "arena_bot_turn"},
        }
    return base


def validate_turn_payload(
    data: Any,
    response_schema: dict[str, Any],
    *,
    allow_extra_fields: bool = False,
) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise LLMError(f"expected JSON object from model, got {type(data).__name__}")
    required = response_schema.get("required", [])
    missing = [k for k in required if k not in data]
    if missing:
        raise LLMError(f"model response missing required fields: {missing}")

    props = response_schema.get("properties") or {}
    if response_schema.get("additionalProperties") is False:
        extra = sorted(k for k in data if k not in props)
        if extra and not allow_extra_fields:
            raise LLMError(f"model response included unexpected fields: {extra}")

    cleaned = {k: data[k] for k in props if k in data} if allow_extra_fields else data

    for key, spec in props.items():
        if key not in cleaned:
            continue
        expected_type = spec.get("type")
        val = cleaned[key]
        if expected_type == "string" and not isinstance(val, str):
            raise LLMError(f"field {key!r} must be a string, got {type(val).__name__}")
        if expected_type == "integer" and (isinstance(val, bool) or not isinstance(val, int)):
            raise LLMError(f"field {key!r} must be an integer, got {type(val).__name__}")
        if expected_type == "boolean" and not isinstance(val, bool):
            raise LLMError(f"field {key!r} must be a boolean, got {type(val).__name__}")

    allowed_actions = set(props["action"]["enum"])
    if cleaned.get("action") not in allowed_actions:
        raise LLMError(f"invalid model action {cleaned.get('action')!r}; expected one of {sorted(allowed_actions)}")
    return cleaned


def _http_post_json(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    api_key_for_redaction: str = "",
    timeout: int = 90,
) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            with _HTTP_OPENER.open(req, timeout=timeout) as resp:
                raw_bytes = resp.read(MAX_HTTP_RESPONSE_BYTES + 1)
                if len(raw_bytes) > MAX_HTTP_RESPONSE_BYTES:
                    raise LLMError(f"LLM API response exceeded {MAX_HTTP_RESPONSE_BYTES} byte limit")
                return json.loads(raw_bytes.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            err_body = redact_secret(exc.read(4096).decode("utf-8", errors="replace")[:800], api_key_for_redaction)
            if exc.code in (429, 500, 502, 503, 504) and attempt < 2:
                time.sleep(2 * (attempt + 1))
                last_err = LLMError(f"HTTP {exc.code}: {err_body}")
                continue
            raise LLMError(f"HTTP {exc.code}: {err_body}") from exc
        except urllib.error.URLError as exc:
            if attempt < 2:
                time.sleep(2 * (attempt + 1))
                last_err = exc
                continue
            raise LLMError(f"network error calling LLM API: {redact_secret(str(exc), api_key_for_redaction)}") from exc
    raise LLMError(f"LLM API failed after retries: {last_err}")


def _record_usage_or_estimate(
    ledger: TokenLedger,
    bot: str,
    in_tok: Any,
    out_tok: Any,
    tot_tok: Any,
    prompt_text: str,
    reply_text: str,
) -> None:
    parsed_in = int(in_tok) if isinstance(in_tok, (int, float)) and in_tok > 0 else 0
    parsed_out = int(out_tok) if isinstance(out_tok, (int, float)) and out_tok > 0 else 0
    parsed_tot = int(tot_tok) if isinstance(tot_tok, (int, float)) and tot_tok > 0 else 0
    if parsed_in == 0 and parsed_out == 0 and parsed_tot == 0:
        est_in = estimate_tokens(prompt_text)
        est_out = estimate_tokens(reply_text)
        ledger.record(bot, est_in, est_out, est_in + est_out, estimated=True)
        return
    ledger.record(bot, parsed_in, parsed_out, parsed_tot if parsed_tot > 0 else None, estimated=False)


class LLMClient:
    """Thin structured-output client for Gemini (default) or OpenAI-compatible APIs."""

    def __init__(
        self,
        provider: str = "gemini",
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        ledger: TokenLedger | None = None,
        temperature: float = 0.2,
        max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
    ) -> None:
        self.provider = provider.strip().lower()
        self.ledger = ledger or TokenLedger()
        self.temperature = temperature
        self.max_output_tokens = max_output_tokens
        self._openai_use_json_schema = True

        if self.provider == "gemini":
            self.model = model or os.environ.get("ARENA_LLM_MODEL", "gemini-2.5-flash")
            self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
            self.base_url = (
                base_url
                or os.environ.get("ARENA_LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta")
            ).rstrip("/")
            if not self.api_key:
                raise LLMError("GEMINI_API_KEY is not set (keep it on the host orchestrator only)")
        elif self.provider == "openai-compat":
            self.model = model or os.environ.get("ARENA_LLM_MODEL", "deepseek-chat")
            self.api_key = (
                api_key
                or os.environ.get("OPENAI_API_KEY")
                or os.environ.get("DEEPSEEK_API_KEY")
                or ""
            )
            self.base_url = (
                base_url
                or os.environ.get("ARENA_LLM_BASE_URL", "https://api.deepseek.com/v1")
            ).rstrip("/")
            if not self.api_key:
                raise LLMError("OPENAI_API_KEY or DEEPSEEK_API_KEY is not set")
        else:
            raise LLMError(f"unsupported provider {provider!r}; use 'gemini' or 'openai-compat'")

    def next_turn(
        self,
        bot: str,
        system_prompt: str,
        messages: list[dict[str, str]],
        response_schema: dict[str, Any],
    ) -> dict[str, Any]:
        prompt_text = system_prompt + "\n" + "\n".join(m["content"] for m in messages)
        projected = estimate_tokens(prompt_text) + self.max_output_tokens
        self.ledger.check_budget(bot, projected_tokens=projected)

        if self.provider == "gemini":
            return self._call_gemini(bot, system_prompt, messages, response_schema)
        return self._call_openai_compat(bot, system_prompt, messages, response_schema)

    def _call_gemini(
        self,
        bot: str,
        system_prompt: str,
        messages: list[dict[str, str]],
        response_schema: dict[str, Any],
    ) -> dict[str, Any]:
        url = f"{self.base_url}/models/{self.model}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key,
        }
        payload = build_gemini_payload(
            system_prompt, messages, response_schema, self.temperature, self.max_output_tokens
        )
        raw = _http_post_json(url, headers, payload, api_key_for_redaction=self.api_key)

        candidates = raw.get("candidates") or []
        parts = ((candidates[0].get("content") or {}).get("parts") or []) if candidates else []
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict)).strip()

        usage = raw.get("usageMetadata") or {}
        prompt_text = system_prompt + "\n" + "\n".join(m["content"] for m in messages)
        _record_usage_or_estimate(
            self.ledger,
            bot,
            usage.get("promptTokenCount"),
            usage.get("candidatesTokenCount"),
            usage.get("totalTokenCount"),
            prompt_text,
            text,
        )

        if not candidates:
            raise LLMError(f"Gemini returned no candidates: {json.dumps(raw)[:500]}")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMError(f"Gemini returned invalid JSON: {exc}: {text[:400]}") from exc
        return validate_turn_payload(parsed, response_schema)

    def _call_openai_compat(
        self,
        bot: str,
        system_prompt: str,
        messages: list[dict[str, str]],
        response_schema: dict[str, Any],
    ) -> dict[str, Any]:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        payload = build_openai_compat_payload(
            self.model,
            system_prompt,
            messages,
            response_schema,
            self.temperature,
            self.max_output_tokens,
            use_json_schema=self._openai_use_json_schema,
        )
        try:
            raw = _http_post_json(url, headers, payload, api_key_for_redaction=self.api_key)
        except LLMError as exc:
            err_lower = str(exc).lower()
            if (
                self._openai_use_json_schema
                and "http 400" in err_lower
                and ("json_schema" in err_lower or "response_format" in err_lower)
            ):
                self._openai_use_json_schema = False
                fallback_payload = build_openai_compat_payload(
                    self.model,
                    system_prompt,
                    messages,
                    response_schema,
                    self.temperature,
                    self.max_output_tokens,
                    use_json_schema=False,
                )
                raw = _http_post_json(url, headers, fallback_payload, api_key_for_redaction=self.api_key)
            else:
                raise

        choices = raw.get("choices") or []
        msg = (choices[0].get("message") or {}) if choices else {}
        tool_calls = msg.get("tool_calls") or []
        if tool_calls:
            text = (((tool_calls[0].get("function") or {}).get("arguments")) or "").strip()
        else:
            text = (msg.get("content") or "").strip()

        usage = raw.get("usage") or {}
        prompt_text = system_prompt + "\n" + "\n".join(m["content"] for m in messages)
        _record_usage_or_estimate(
            self.ledger,
            bot,
            usage.get("prompt_tokens"),
            usage.get("completion_tokens"),
            usage.get("total_tokens"),
            prompt_text,
            text,
        )

        if not choices:
            raise LLMError(f"OpenAI-compatible endpoint returned no choices: {json.dumps(raw)[:500]}")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMError(f"OpenAI-compatible endpoint returned invalid JSON: {exc}: {text[:400]}") from exc
        return validate_turn_payload(
            parsed,
            response_schema,
            allow_extra_fields=not self._openai_use_json_schema,
        )
