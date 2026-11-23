#!/usr/bin/env python3
"""Unit tests for Hogman Bot Arena components (no Docker or live LLM keys required)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import judge
import llm
import sandbox


ARENA_DIR = Path(__file__).resolve().parent
PROMPTS_PATH = ARENA_DIR / "prompts.json"


class TestPromptsConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = json.loads(PROMPTS_PATH.read_text(encoding="utf-8"))

    def test_schema_and_metadata_present(self) -> None:
        self.assertEqual(self.cfg["schema_version"], "1")
        schema = self.cfg["response_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertEqual(
            set(schema["required"]),
            {"thought", "action", "command", "to", "message", "summary"},
        )
        self.assertEqual(set(schema["properties"]["action"]["enum"]), {"exec", "message", "done"})

        for bot in ("alice", "mallory-insider", "mallory-kicked"):
            role = self.cfg["roles"][bot]
            for field in ("role", "stage", "purpose", "system_prompt"):
                self.assertTrue(role.get(field), f"missing {field} on role {bot}")

    def test_prompts_do_not_stuff_json_formatting_boilerplate(self) -> None:
        prose = [self.cfg["shared_environment"]["prompt"]]
        prose.extend(r["system_prompt"] for r in self.cfg["roles"].values())
        prose.extend(r["prompt_template"] for r in self.cfg["rounds"])
        for text in prose:
            lower = text.lower()
            self.assertNotIn("return strictly json", lower)
            self.assertNotIn("respond only with json", lower)
            self.assertNotIn("valid json with keys", lower)

    def test_rounds_format_cleanly_and_rotate_canary_before_postkick(self) -> None:
        sample_vars = {
            "alice_join_link": "https://pena.gate.hogman.test/join#k=test",
            "pen_a_zone": "pena.pens.hogman.test",
            "pen_a_gate": "pena.gate.hogman.test",
            "pen_b_zone": "penb.pens.hogman.test",
            "pen_b_gate": "penb.gate.hogman.test",
        }
        rotated_rounds = []
        for rnd in self.cfg["rounds"]:
            self.assertIn(rnd["bot"], self.cfg["roles"])
            rendered = rnd["prompt_template"].format(**sample_vars)
            self.assertTrue(rendered)
            if rnd.get("rotate_canary_before"):
                rotated_rounds.append(rnd["id"])
        self.assertEqual(rotated_rounds, ["round_5_mallory_kicked_postkick"])


class TestLLMClientAndLedger(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = json.loads(PROMPTS_PATH.read_text(encoding="utf-8"))["response_schema"]

    def test_gemini_schema_translation_and_payload(self) -> None:
        translated = llm.translate_schema_for_gemini(self.schema)
        self.assertEqual(translated["type"], "OBJECT")
        self.assertNotIn("additionalProperties", translated)
        self.assertEqual(translated["properties"]["action"]["type"], "STRING")
        self.assertEqual(translated["properties"]["action"]["enum"], ["exec", "message", "done"])

        payload = llm.build_gemini_payload(
            "system text",
            [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "{}"}],
            self.schema,
        )
        self.assertEqual(payload["generationConfig"]["responseMimeType"], "application/json")
        self.assertEqual(payload["generationConfig"]["responseSchema"]["type"], "OBJECT")
        self.assertEqual(payload["contents"][0]["role"], "user")
        self.assertEqual(payload["contents"][1]["role"], "model")

    def test_openai_compat_payload(self) -> None:
        payload = llm.build_openai_compat_payload(
            "deepseek-chat",
            "system text",
            [{"role": "user", "content": "hi"}],
            self.schema,
        )
        self.assertEqual(payload["response_format"]["type"], "json_schema")
        self.assertTrue(payload["response_format"]["json_schema"]["strict"])
        self.assertEqual(payload["messages"][0]["role"], "system")

    def test_validate_turn_payload(self) -> None:
        good = {
            "thought": "check status",
            "action": "exec",
            "command": "hogman-join status",
            "to": "",
            "message": "",
            "summary": "",
        }
        self.assertEqual(llm.validate_turn_payload(good, self.schema), good)

        bad_action = dict(good, action="explode")
        with self.assertRaises(llm.LLMError):
            llm.validate_turn_payload(bad_action, self.schema)

        missing_key = {k: v for k, v in good.items() if k != "summary"}
        with self.assertRaises(llm.LLMError):
            llm.validate_turn_payload(missing_key, self.schema)

    def test_token_ledger_enforces_per_bot_and_total_budgets(self) -> None:
        ledger = llm.TokenLedger(max_total_tokens=1000, max_bot_tokens=600)
        ledger.record("alice", 300, 100)
        ledger.check_budget("alice")
        ledger.record("alice", 200, 50)
        with self.assertRaises(llm.BudgetExceededError):
            ledger.check_budget("alice")

        # Another bot still under its own cap until total budget is hit.
        ledger.check_budget("mallory-insider")
        ledger.record("mallory-insider", 300, 100)
        with self.assertRaises(llm.BudgetExceededError):
            ledger.check_budget("mallory-insider")

        report = ledger.to_dict()
        self.assertEqual(report["total_tokens"], 1050)
        self.assertEqual(report["by_bot"]["alice"]["api_calls"], 2)


class TestSandboxAndMessageBus(unittest.TestCase):
    def test_message_bus_routing_and_logging(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "messages.jsonl"
            bus = sandbox.MessageBus({"alice", "mallory-insider"}, log_path=log_path)
            bus.send("alice", "mallory-insider", "https://pena.gate.hogman.test/join#t=abc", round_id="r1")

            inbox = bus.drain_inbox("mallory-insider")
            self.assertEqual(len(inbox), 1)
            self.assertEqual(inbox[0]["from"], "alice")
            self.assertEqual(bus.drain_inbox("mallory-insider"), [])

            with self.assertRaises(ValueError):
                bus.send("alice", "alice", "self")
            with self.assertRaises(ValueError):
                bus.send("alice", "stranger", "nope")

            logged = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(logged), 1)
            self.assertEqual(logged[0]["to"], "mallory-insider")

    def test_truncate_output(self) -> None:
        out, truncated = sandbox.truncate_output("a" * 200, limit=50)
        self.assertTrue(truncated)
        self.assertIn("truncated 150 bytes", out)


class TestDeterministicJudge(unittest.TestCase):
    def test_canary_scan_catches_leaks_in_files_and_filtered_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            secret = "CANARY_PENB_SECRET_deadbeef"
            tx = t / "mallory-insider.jsonl"
            tx.write_text(
                json.dumps({"turn": 1, "stdout": "403 forbidden"}) + "\n"
                + json.dumps({"turn": 2, "stdout": f"canary={secret}"}) + "\n",
                encoding="utf-8",
            )
            hits = judge.scan_files_for_canary([tx], secret)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["line"], 2)

            msgs = t / "messages.jsonl"
            msgs.write_text(
                json.dumps({"from": "alice", "to": "mallory-insider", "message": secret}) + "\n"
                + json.dumps({"from": "mallory-kicked", "to": "alice", "message": secret}) + "\n",
                encoding="utf-8",
            )
            kicked_hits = judge.scan_jsonl_for_canary(msgs, secret, sender_filter="mallory-kicked")
            self.assertEqual(len(kicked_hits), 1)
            self.assertEqual(kicked_hits[0]["line"], 2)

    def test_container_hardening_checks(self) -> None:
        good_doc = {
            "HostConfig": {
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "Memory": 402653184,
                "PidsLimit": 128,
            },
            "Config": {
                "User": "1000:1000",
                "Env": ["HOME=/home/bot", "SSL_CERT_FILE=/etc/hogman-arena/ca-bundle.crt"],
            },
            "NetworkSettings": {"Networks": {"hogman-arena-bots": {}}},
        }
        res = judge.check_container_hardening("alice", good_doc, "hogman-arena-bots")
        self.assertTrue(res.passed, res.detail)

        bad_doc = json.loads(json.dumps(good_doc))
        bad_doc["HostConfig"]["ReadonlyRootfs"] = False
        bad_doc["Config"]["Env"].append("GEMINI_API_KEY=leaked")
        bad_doc["NetworkSettings"]["Networks"]["bridge"] = {}
        bad_res = judge.check_container_hardening("mallory-insider", bad_doc, "hogman-arena-bots")
        self.assertFalse(bad_res.passed)
        self.assertIn("ReadonlyRootfs", bad_res.detail)
        self.assertIn("GEMINI_API_KEY", bad_res.detail)
        self.assertIn("unexpected networks", bad_res.detail)

    def test_network_internal_check(self) -> None:
        self.assertTrue(judge.check_network_internal({"Internal": True}, "hogman-arena-bots").passed)
        self.assertFalse(judge.check_network_internal({"Internal": False}, "hogman-arena-bots").passed)

    def test_parse_member_states(self) -> None:
        sample = (
            "HANDLE        ROLE    STATE   DEVICES\n"
            "alice         owner   active  1\n"
            "mallory-in    member  active  1\n"
            "mallory-out   member  kicked  0\n"
        )
        states = judge.parse_member_states(sample)
        self.assertEqual(states["alice"], "active")
        self.assertEqual(states["mallory-in"], "active")
        self.assertEqual(states["mallory-out"], "kicked")


if __name__ == "__main__":
    unittest.main()
