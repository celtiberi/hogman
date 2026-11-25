#!/usr/bin/env python3
"""Off-site pen backups on Backblaze B2 (D-48). Standard library only.

Two jobs, run in two different places:

  ensure   (CI, locked `infra` environment, maintainer approves each run)
           Makes sure the backup bucket exists with Object Lock (compliance
           retention) and a lifecycle rule that deletes every file after
           RETENTION_DAYS + 1 days. With --new-keys it also creates:
             - a write-only key for the server (writeFiles, this bucket only),
               encrypted with age to the server's own public key;
             - a read key for restores (listFiles+readFiles, this bucket only),
               encrypted with age to the maintainer's backup key.
           Plain keys are never printed or written unencrypted.

  upload   (the server, from `hogman-host backup`)
           Uploads one already-encrypted *.tar.gz.age file with the write-only
           key from /etc/hogman/b2.env and checks B2's SHA-1 against ours.

Environment for `ensure`: B2_MASTER_KEY_ID, B2_MASTER_KEY, and the two age
public keys B2_SERVER_RECIPIENT and B2_MAINTAINER_RECIPIENT. All four live in
the locked `infra` environment, so a pull request can't swap a recipient.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = os.environ.get("B2_API_URL", "https://api.backblazeb2.com")
BUCKET_PREFIX = "hogman-backups-"
# Compliance-mode lock: nobody (not even us, not a hacked server) can delete a
# backup for RETENTION_DAYS. The lifecycle rule then hides it and deletes it a
# day later. B2 runs lifecycle once a day, which can add up to ~2 days, so
# 27 + 1 keeps every backup gone within 30 days of upload (D-37).
RETENTION_DAYS = 27
UPLOAD_ATTEMPTS = 5
WRITE_KEY_NAME = "hogman-server-backup-write"
READ_KEY_NAME = "hogman-maintainer-backup-read"
RETRYABLE = re.compile(r"HTTP (408|429|5\d\d)\b|timed out|Connection|reset")
REMOTE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}/[a-z][a-z0-9-]{0,62}-[0-9]{8}T[0-9]{6}Z\.tar\.gz\.age$")
MAX_DOWNLOAD = 2 << 30  # 2 GiB; a pen backup is a few hundred KB
NAME_RE = re.compile(r"^[A-Za-z0-9._-]+\.tar\.gz\.age$")


class B2Error(RuntimeError):
    pass


def _call(url: str, *, token: str | None = None, basic: str | None = None,
          body: dict | None = None, data: bytes | None = None,
          headers: dict | None = None) -> dict:
    h = dict(headers or {})
    if token:
        h["Authorization"] = token
    if basic:
        h["Authorization"] = "Basic " + basic
    payload = data
    if body is not None:
        payload = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=payload, headers=h,
                                 method="POST" if payload is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read() or b"{}")
    except TimeoutError:
        raise B2Error(f"{url.rsplit('/', 1)[-1]}: timed out") from None
    except urllib.error.URLError as e:
        if not isinstance(e, urllib.error.HTTPError):
            raise B2Error(f"{url.rsplit('/', 1)[-1]}: Connection error {e.reason}") from None
        # B2 error bodies carry a code and a message, never our secrets.
        try:
            detail = json.loads(e.read() or b"{}")
        except ValueError:
            detail = {}
        raise B2Error(f"{url.rsplit('/', 1)[-1]}: HTTP {e.code} {detail.get('code', '')} {detail.get('message', '')}".strip()) from None


class B2:
    def __init__(self, key_id: str, key: str):
        if not key_id or not key:
            raise B2Error("missing B2 key id or key")
        basic = base64.b64encode(f"{key_id}:{key}".encode()).decode()
        auth = _call(f"{API}/b2api/v3/b2_authorize_account", basic=basic)
        self.account_id = auth["accountId"]
        self.token = auth["authorizationToken"]
        self.api_url = auth["apiInfo"]["storageApi"]["apiUrl"]
        self.download_url = auth["apiInfo"]["storageApi"].get("downloadUrl", self.api_url)

    def call(self, name: str, body: dict) -> dict:
        return _call(f"{self.api_url}/b2api/v3/{name}", token=self.token, body=body)


# ------------------------------------------------------------------ ensure --

def lifecycle_rules() -> list[dict]:
    return [{"fileNamePrefix": "", "daysFromUploadingToHiding": RETENTION_DAYS, "daysFromHidingToDeleting": 1}]


def default_retention() -> dict:
    return {"mode": "compliance", "period": {"duration": RETENTION_DAYS, "unit": "days"}}


def ensure_bucket(b2: B2) -> dict:
    buckets = b2.call("b2_list_buckets", {"accountId": b2.account_id})["buckets"]
    ours = [b for b in buckets if b["bucketName"].startswith(BUCKET_PREFIX)]
    if len(ours) > 1:
        raise B2Error(f"more than one {BUCKET_PREFIX}* bucket; refusing to guess")
    if not ours:
        name = BUCKET_PREFIX + secrets.token_hex(6)
        bucket = b2.call("b2_create_bucket", {
            "accountId": b2.account_id, "bucketName": name, "bucketType": "allPrivate",
            "fileLockEnabled": True, "lifecycleRules": lifecycle_rules(),
        })
    else:
        bucket = ours[0]
    if bucket.get("bucketType") != "allPrivate":
        raise B2Error("backup bucket is not private")
    # Fail closed: Object Lock must be positively reported as on.
    lock = ((bucket.get("fileLockConfiguration") or {}).get("value") or {})
    if lock.get("isFileLockEnabled") is not True:
        raise B2Error("backup bucket does not report Object Lock on; it can't be turned on later, recreate it")
    # Re-assert retention and lifecycle on every run so drift is corrected.
    bucket = b2.call("b2_update_bucket", {
        "accountId": b2.account_id, "bucketId": bucket["bucketId"],
        "defaultRetention": default_retention(), "lifecycleRules": lifecycle_rules(),
    })
    return bucket


def create_key(b2: B2, name: str, caps: list[str], bucket_id: str) -> dict:
    return b2.call("b2_create_key", {
        "accountId": b2.account_id, "keyName": name,
        "capabilities": caps, "bucketId": bucket_id,
    })


AGE_RE = re.compile(r"^age1[0-9a-z]{58}$")


def age_encrypt(recipient: str, plaintext: bytes, out_path: str) -> None:
    recipient = (recipient or "").strip()
    if not AGE_RE.match(recipient):
        raise B2Error("recipient is not an age public key (age1...)")
    res = subprocess.run(["age", "-r", recipient, "-o", out_path], input=plaintext, capture_output=True)
    if res.returncode != 0:
        raise B2Error(f"age failed: {res.stderr.decode(errors='replace').strip()}")


def cmd_ensure(args: argparse.Namespace) -> int:
    b2 = B2(os.environ.get("B2_MASTER_KEY_ID", ""), os.environ.get("B2_MASTER_KEY", ""))
    bucket = ensure_bucket(b2)
    print(f"backup bucket ok: private, Object Lock compliance {RETENTION_DAYS}d, lifecycle delete after {RETENTION_DAYS + 1}d")
    if not args.new_keys:
        return 0
    # Check both recipients BEFORE creating anything, so a typo can't leave a
    # live key in B2 that nobody can decrypt.
    for var in ("B2_SERVER_RECIPIENT", "B2_MAINTAINER_RECIPIENT"):
        if not AGE_RE.match(os.environ.get(var, "").strip()):
            raise B2Error(f"{var} is not an age public key (age1...); no keys created")
    os.makedirs(args.out, exist_ok=True)
    w = create_key(b2, WRITE_KEY_NAME, ["writeFiles"], bucket["bucketId"])
    env = (f"B2_KEY_ID={w['applicationKeyId']}\nB2_KEY={w['applicationKey']}\n"
           f"B2_BUCKET={bucket['bucketName']}\nB2_BUCKET_ID={bucket['bucketId']}\n").encode()
    age_encrypt(os.environ.get("B2_SERVER_RECIPIENT", ""), env, os.path.join(args.out, "server-b2.env.age"))
    r = create_key(b2, READ_KEY_NAME, ["listFiles", "readFiles"], bucket["bucketId"])
    renv = (f"B2_KEY_ID={r['applicationKeyId']}\nB2_KEY={r['applicationKey']}\n"
            f"B2_BUCKET={bucket['bucketName']}\nB2_BUCKET_ID={bucket['bucketId']}\n").encode()
    age_encrypt(os.environ.get("B2_MAINTAINER_RECIPIENT", ""), renv, os.path.join(args.out, "maintainer-restore-b2.env.age"))
    print("keys: new write-only (server) and read (maintainer) keys created; both encrypted to their owners, plaintext discarded")
    return 0


# ------------------------------------------------------------------ upload --

def read_env(path: str) -> dict:
    out = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
    return out


def cmd_upload(args: argparse.Namespace) -> int:
    name = os.path.basename(args.file)
    if not NAME_RE.match(name):
        raise B2Error(f"refusing to upload {name}: only *.tar.gz.age backups go off-site")
    env = read_env(args.env)
    b2 = B2(env.get("B2_KEY_ID", ""), env.get("B2_KEY", ""))
    with open(args.file, "rb") as f:
        data = f.read()
    sha1 = hashlib.sha1(data).hexdigest()
    res = None
    for attempt in range(1, UPLOAD_ATTEMPTS + 1):
        # B2's contract: on a retryable error, get a new upload URL and back off.
        try:
            up = b2.call("b2_get_upload_url", {"bucketId": env["B2_BUCKET_ID"]})
            res = _call(up["uploadUrl"], token=up["authorizationToken"], data=data, headers={
                "X-Bz-File-Name": urllib.parse.quote(f"{args.host}/{name}"),
                "Content-Type": "application/octet-stream",
                "X-Bz-Content-Sha1": sha1,
                "Content-Length": str(len(data)),
            })
            break
        except B2Error as e:
            if not RETRYABLE.search(str(e)) or attempt == UPLOAD_ATTEMPTS:
                raise
            time.sleep(min(64, 2 ** attempt) * args.backoff)
    if res.get("contentSha1") != sha1:
        raise B2Error(f"{name}: B2 stored SHA-1 {res.get('contentSha1')} but we sent {sha1}")
    print(f"uploaded {args.host}/{name} ({len(data)} bytes, sha1 {sha1[:12]})")
    return 0


# ------------------------------------------------------- list / download --
# Restore side, run by the maintainer on their own machine with the read key
# (maintainer-restore-b2.env.age, decrypted with their backup key). Backups stay
# age-encrypted; decrypting them needs that same offline key.

def cmd_list(args: argparse.Namespace) -> int:
    env = read_env(args.env)
    b2 = B2(env.get("B2_KEY_ID", ""), env.get("B2_KEY", ""))
    start = None
    while True:
        body = {"bucketId": env["B2_BUCKET_ID"], "maxFileCount": 1000, "prefix": args.prefix}
        if start:
            body["startFileName"] = start
        res = b2.call("b2_list_file_names", body)
        for f in res.get("files", []):
            if f.get("action") == "upload":
                print(f"{f['fileName']}\t{f.get('contentLength', 0)}")
        start = res.get("nextFileName")
        if not start:
            return 0


def cmd_download(args: argparse.Namespace) -> int:
    name = args.name
    if not REMOTE_RE.match(name):
        raise B2Error(f"refusing to download {name!r}: expected <host>/<name>-<YYYYMMDDTHHMMSSZ>.tar.gz.age")
    env = read_env(args.env)
    b2 = B2(env.get("B2_KEY_ID", ""), env.get("B2_KEY", ""))
    out = args.out or os.path.basename(name)
    url = f"{b2.download_url}/file/{urllib.parse.quote(env['B2_BUCKET'])}/{urllib.parse.quote(name)}"
    req = urllib.request.Request(url, headers={"Authorization": b2.token})
    # O_EXCL: never overwrite; 0600: backups are private even while encrypted.
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    ok = False
    try:
        h = hashlib.sha1()
        size = 0
        with os.fdopen(fd, "wb") as f, urllib.request.urlopen(req, timeout=300) as resp:
            want = (resp.headers.get("X-Bz-Content-Sha1") or "").strip().lower()
            # Fail closed: every backup we upload carries its SHA-1.
            if not re.fullmatch(r"[0-9a-f]{40}", want):
                raise B2Error(f"{name}: B2 gave no usable SHA-1 ({want!r}); not saved")
            clen = resp.headers.get("Content-Length")
            if clen and int(clen) > MAX_DOWNLOAD:
                raise B2Error(f"{name}: {clen} bytes is over the {MAX_DOWNLOAD} byte limit; not saved")
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_DOWNLOAD:
                    raise B2Error(f"{name}: over the {MAX_DOWNLOAD} byte limit; not saved")
                h.update(chunk)
                f.write(chunk)
        got = h.hexdigest()
        if got != want:
            raise B2Error(f"{name}: SHA-1 mismatch (B2 {want}, got {got}); not saved")
        ok = True
    except urllib.error.HTTPError as e:
        raise B2Error(f"download {name}: HTTP {e.code}") from None
    finally:
        if not ok:
            try:
                os.unlink(out)
            except OSError:
                pass
    print(f"downloaded {name} -> {out} ({size} bytes, sha1 verified)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("ensure")
    e.add_argument("--new-keys", action="store_true", help="also create and encrypt fresh server/maintainer keys")
    e.add_argument("--out", default="b2-keys")
    u = sub.add_parser("upload")
    u.add_argument("file")
    u.add_argument("--env", default="/etc/hogman/b2.env")
    u.add_argument("--host", default=os.uname().nodename)
    u.add_argument("--backoff", type=float, default=1.0, help=argparse.SUPPRESS)
    ls = sub.add_parser("list", help="list backups (needs the maintainer read key)")
    ls.add_argument("--env", required=True)
    ls.add_argument("--prefix", default="")
    d = sub.add_parser("download", help="download one backup (needs the maintainer read key)")
    d.add_argument("name", help="<host>/<pen>-<timestamp>.tar.gz.age, as shown by list")
    d.add_argument("--env", required=True)
    d.add_argument("-o", "--out")
    args = ap.parse_args(argv)
    cmds = {"ensure": cmd_ensure, "upload": cmd_upload, "list": cmd_list, "download": cmd_download}
    try:
        return cmds[args.cmd](args)
    except (B2Error, KeyError, OSError) as e:
        print(f"b2: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
