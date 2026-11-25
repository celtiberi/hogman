"""Tests for b2.py against a local fake of the B2 native API (no network, no account).

Run: python3 deploy/backup-b2/test_b2.py   (needs `age` and `age-keygen` on PATH)
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))


class FakeB2:
    def __init__(self):
        self.buckets: dict[str, dict] = {}
        self.keys: list[dict] = []
        self.files: dict[str, bytes] = {}
        self.calls: list[str] = []
        self.corrupt_sha1 = False
        self.fail_uploads = 0
        self.hide_lock = False


def make_handler(state: FakeB2, base: list[str]):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            state.calls.append(self.path)
            if self.path.endswith("/b2_authorize_account"):
                if not self.headers.get("Authorization", "").startswith("Basic "):
                    return self._json({"code": "unauthorized"}, 401)
                return self._json({"accountId": "acct", "authorizationToken": "tok",
                                   "apiInfo": {"storageApi": {"apiUrl": base[0]}}})
            self._json({"code": "not_found"}, 404)

        def do_POST(self):
            state.calls.append(self.path)
            n = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(n)
            if self.path.startswith("/upload"):
                if state.fail_uploads > 0:
                    state.fail_uploads -= 1
                    return self._json({"code": "service_unavailable", "message": "busy"}, 503)
                sha1 = hashlib.sha1(raw).hexdigest()
                if sha1 != self.headers.get("X-Bz-Content-Sha1"):
                    return self._json({"code": "bad_request", "message": "sha1 mismatch"}, 400)
                name = urllib.parse.unquote(self.headers["X-Bz-File-Name"])
                state.files[name] = raw
                return self._json({"fileName": name, "contentSha1": "0" * 40 if state.corrupt_sha1 else sha1})
            body = json.loads(raw or b"{}")
            op = self.path.rsplit("/", 1)[-1]
            if op == "b2_list_buckets":
                bs = [dict(b) for b in state.buckets.values()]
                if state.hide_lock:
                    for b in bs:
                        b["fileLockConfiguration"] = None
                return self._json({"buckets": bs})
            if op == "b2_create_bucket":
                b = {"bucketId": "bkt" + str(len(state.buckets)), "bucketName": body["bucketName"],
                     "bucketType": body["bucketType"],
                     "fileLockConfiguration": {"value": {"isFileLockEnabled": body["fileLockEnabled"]}},
                     "lifecycleRules": body.get("lifecycleRules", [])}
                state.buckets[b["bucketId"]] = b
                return self._json(b)
            if op == "b2_update_bucket":
                b = dict(state.buckets[body["bucketId"]])
                if state.hide_lock:
                    b["fileLockConfiguration"] = None
                    return self._json(b)
                b = state.buckets[body["bucketId"]]
                b["defaultRetention"] = body["defaultRetention"]
                b["lifecycleRules"] = body["lifecycleRules"]
                return self._json(b)
            if op == "b2_create_key":
                k = {"applicationKeyId": f"kid{len(state.keys)}", "applicationKey": f"SECRET-{len(state.keys)}",
                     "capabilities": body["capabilities"], "bucketId": body["bucketId"], "keyName": body["keyName"]}
                state.keys.append(k)
                return self._json(k)
            if op == "b2_get_upload_url":
                return self._json({"uploadUrl": base[0] + "/upload/" + body["bucketId"], "authorizationToken": "uptok"})
            self._json({"code": "not_found"}, 404)

    return H


def load_b2(api_url: str):
    os.environ["B2_API_URL"] = api_url
    spec = importlib.util.spec_from_file_location("b2mod", os.path.join(HERE, "b2.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(shutil.which("age") and shutil.which("age-keygen"), "needs age")
class B2Test(unittest.TestCase):
    def setUp(self):
        self.state = FakeB2()
        base: list[str] = []
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state, base))
        base.append(f"http://127.0.0.1:{self.srv.server_address[1]}")
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.b2 = load_b2(base[0])
        self.tmp = tempfile.mkdtemp()
        os.environ["B2_MASTER_KEY_ID"] = "master"
        os.environ["B2_MASTER_KEY"] = "mastersecret"
        self.ids = {}
        for who in ("server", "maintainer"):
            ident = os.path.join(self.tmp, f"{who}.key")
            subprocess.run(["age-keygen", "-o", ident], check=True, capture_output=True)
            pub = subprocess.run(["age-keygen", "-y", ident], check=True, capture_output=True, text=True).stdout.strip()
            with open(os.path.join(self.tmp, f"{who}.pub"), "w") as f:
                f.write(pub + "\n")
            self.ids[who] = ident

    def tearDown(self):
        self.srv.shutdown()
        shutil.rmtree(self.tmp)

    def ensure(self, *extra):
        for who in ("server", "maintainer"):
            with open(os.path.join(self.tmp, f"{who}.pub")) as f:
                os.environ[f"B2_{who.upper()}_RECIPIENT"] = f.read().strip()
        return self.b2.main(["ensure", "--out", os.path.join(self.tmp, "out"), *extra])

    def decrypt(self, who, path):
        return subprocess.run(["age", "-d", "-i", self.ids[who], path], check=True, capture_output=True, text=True).stdout

    def test_ensure_creates_locked_private_bucket_once(self):
        self.assertEqual(self.ensure(), 0)
        self.assertEqual(self.ensure(), 0)
        self.assertEqual(len(self.state.buckets), 1, "second run must reuse the bucket")
        b = next(iter(self.state.buckets.values()))
        self.assertTrue(b["bucketName"].startswith("hogman-backups-"))
        self.assertEqual(b["bucketType"], "allPrivate")
        self.assertTrue(b["fileLockConfiguration"]["value"]["isFileLockEnabled"])
        self.assertEqual(b["defaultRetention"]["mode"], "compliance")
        self.assertEqual(b["defaultRetention"]["period"], {"duration": 27, "unit": "days"})
        self.assertEqual(b["lifecycleRules"], [{"fileNamePrefix": "", "daysFromUploadingToHiding": 27, "daysFromHidingToDeleting": 1}])
        self.assertEqual(self.state.keys, [], "no keys without --new-keys")

    def test_ensure_fails_closed_when_lock_not_reported(self):
        self.assertEqual(self.ensure(), 0)
        self.state.hide_lock = True
        self.assertEqual(self.ensure(), 1)

    def test_bad_recipient_refused(self):
        os.environ["B2_SERVER_RECIPIENT"] = "not-a-key"
        self.assertEqual(self.b2.main(["ensure", "--new-keys", "--out", os.path.join(self.tmp, "out")]), 1)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "out", "server-b2.env.age")))

    def test_new_keys_are_scoped_and_only_written_encrypted(self):
        self.assertEqual(self.ensure("--new-keys"), 0)
        caps = {k["keyName"]: (k["capabilities"], k["bucketId"]) for k in self.state.keys}
        bid = next(iter(self.state.buckets))
        self.assertEqual(caps["hogman-server-backup-write"], (["writeFiles"], bid))
        self.assertEqual(caps["hogman-maintainer-backup-read"], (["listFiles", "readFiles"], bid))
        out = os.path.join(self.tmp, "out")
        self.assertEqual(sorted(os.listdir(out)), ["maintainer-restore-b2.env.age", "server-b2.env.age"])
        for f in os.listdir(out):
            with open(os.path.join(out, f), "rb") as fh:
                self.assertNotIn(b"SECRET-", fh.read(), "keys must never be written in plain text")
        self.assertIn("B2_KEY=SECRET-0", self.decrypt("server", os.path.join(out, "server-b2.env.age")))
        self.assertIn("B2_KEY=SECRET-1", self.decrypt("maintainer", os.path.join(out, "maintainer-restore-b2.env.age")))
        with self.assertRaises(subprocess.CalledProcessError):
            self.decrypt("server", os.path.join(out, "maintainer-restore-b2.env.age"))

    def _server_env(self):
        self.ensure("--new-keys")
        env = os.path.join(self.tmp, "b2.env")
        with open(env, "w") as f:
            f.write(self.decrypt("server", os.path.join(self.tmp, "out", "server-b2.env.age")))
        return env

    def test_upload_checks_sha1_and_prefixes_host(self):
        env = self._server_env()
        f = os.path.join(self.tmp, "pen-x-20261125T033000Z.tar.gz.age")
        with open(f, "wb") as fh:
            fh.write(b"ciphertext" * 100)
        self.assertEqual(self.b2.main(["upload", f, "--env", env, "--host", "host-a"]), 0)
        self.assertEqual(self.state.files["host-a/pen-x-20261125T033000Z.tar.gz.age"], b"ciphertext" * 100)
        self.state.fail_uploads = 2  # B2 busy twice, then fine: retried with a fresh URL
        self.assertEqual(self.b2.main(["upload", f, "--env", env, "--host", "host-a", "--backoff", "0"]), 0)
        self.state.fail_uploads = 99  # never recovers: gives up
        self.assertEqual(self.b2.main(["upload", f, "--env", env, "--host", "host-a", "--backoff", "0"]), 1)
        self.state.fail_uploads = 0
        self.state.corrupt_sha1 = True
        self.assertEqual(self.b2.main(["upload", f, "--env", env, "--host", "host-a"]), 1)

    def test_upload_refuses_anything_but_encrypted_backups(self):
        env = self._server_env()
        f = os.path.join(self.tmp, "registrar.db")
        with open(f, "wb") as fh:
            fh.write(b"plaintext")
        self.assertEqual(self.b2.main(["upload", f, "--env", env]), 1)
        self.assertEqual(self.state.files, {})


if __name__ == "__main__":
    unittest.main()
