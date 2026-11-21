# Signed releases (D-15): design

Status: **draft, revision 2**, which folds in the red-team on PR #38. It goes to a second review before any code. P1, after `hogman-join update` (merged in PR #37).

## Problem

Every download is checked only against a `SHA256SUMS` file that comes from the same server, over the same TLS connection:

- a new computer downloading `hogman-join` from `/join/dl/`;
- `hogman-join update`;
- `install.sh` fetching a pen's release from hogman.network.

That catches corrupted or cut-off downloads. It does not catch a server that has been broken into: that server serves a tampered build together with a matching checksum. It also cannot stop an old, vulnerable build from being served as current.

## Standard practice we follow

- **The Update Framework (TUF) spec.** TUF is the standard threat model for software updaters. Its attack list is our checklist (below). Its root role and targets role are our key layout. Its version numbers and expiry dates on every signed document are our rollback, freeze and revocation defences.
- **Tailscale's `clientupdate/distsign`.** This is the same two-tier Ed25519 pattern in Go, used in production by the client our pens run on. We follow its structure:
  - root keys kept offline, in more than one place, and built into the client;
  - root keys certify signing keys;
  - signing keys certify releases.

  We don't call its functions. Its formats don't fit: `SignSigningKeys` only signs raw PEM bundles, and `SignPackageHash` signs `BLAKE2s || len` with an unexported key. We use Go's standard `crypto/ed25519` directly and write no cryptography of our own.
- **SLSA build provenance via GitHub artifact attestations.** These are a public, independent record that each file was built by our workflow from a specific commit, and anyone can check one with `gh attestation verify`. They are a supplement, not what clients check.
- **Reproducible builds.** Anyone can rebuild a tagged commit and compare hashes (see Operations).

We considered **go-tuf v2** and left it out. It needs an online, frequently re-signed timestamp key, which brings operational risk and does nothing for a single publisher who approves each release by hand. We would revisit it if we ever have several publishers or mirrors. The two documents below keep the TUF properties that matter here: a version and an expiry on both the key list and the release.

## Keys

| Key | Where it lives | What it signs | Rotation |
|---|---|---|---|
| Root keys (2, Ed25519) | Offline, in two different places, held by the maintainer. Never on a server and never in CI. | `keys.json` only | Only by shipping a new client that lists the new root. Having two roots means a lost one can be retired with the other. |
| Signing key (Ed25519) | A GitHub Actions secret in a protected `release` environment. It needs maintainer approval for each run, and can only be deployed from protected tags. Never on a pen. | `release.json` | A new `keys.json` with a higher `key_version`, signed by a root key. |

The public root keys are compiled into `hogman-join` and into `hogman-host`.

## Signed documents

Every signature covers a domain-separation prefix followed by the exact file bytes, so a signature made for one kind of document can never be accepted as another:

- `keys.json.sig` = Ed25519(root, `"hogman-keys-v1\x00" || keys.json`)
- `release.json.sig` = Ed25519(signing key, `"hogman-release-v1\x00" || release.json`)

The verifier checks the bytes it downloaded before parsing them, so no canonical JSON encoding is needed.

`keys.json`:

```json
{"key_version": 3, "expires": "2027-11-20T00:00:00Z", "keys": ["<base64 ed25519 public key>"]}
```

`release.json`:

```json
{
  "version": 42,
  "key_version": 3,
  "commit": "<git sha>",
  "expires": "2027-02-18T00:00:00Z",
  "files": {
    "hogman-join-Darwin-arm64": {"sha256": "…", "size": 123},
    "hogman-<ver>.tar.gz": {"sha256": "…", "size": 456},
    "hogman-bin-<ver>.tar.gz": {"sha256": "…", "size": 789}
  }
}
```

- `version` is a plain counter (1, 2, 3, …). It isn't a date, because unpadded dates sort wrongly as numbers.
- `files` lists every published file: all five `hogman-join` builds and both pen tarballs.

## Client checks

These apply to `hogman-join update` and to `hogman-host`'s verifier.

1. Fetch `keys.json` and its signature, and verify them with any built-in root key.
2. **Revocation:** refuse a `key_version` lower than the highest one seen, or lower than the compiled-in floor. Refuse an expired `keys.json`.
3. Fetch `release.json` and its signature, and verify them with a key from `keys.json`. Its `key_version` must match.
4. **Rollback:** refuse a `version` lower than the highest one seen, or lower than the compiled-in floor.
5. **Freeze:** refuse an expired `release.json`. Its expiry is 90 days and every release re-signs, so a quiet project doesn't lock people out.
6. Download the file, and check its size and SHA-256 against `release.json` before replacing anything. PR #37 already does the atomic swap and the restart if the swap fails.
7. Any failure leaves the installed version untouched and says which check failed.

**Where the highest versions are stored.** The highest `version` and `key_version` seen are stored in Hogman's user configuration folder (`~/.config/hogman/`, `~/Library/Application Support/hogman/`). That folder survives `leave` and isn't tied to where the binary sits. The minimum `version` and `key_version` are also compiled into each build, so even a freshly downloaded binary refuses anything older than itself. A signing key that leaked and was then rotated can't be brought back by replaying an old `keys.json`.

**Pens built from source.** A pen whose operator compiled their own binaries has no signed `release.json`. Against such a pen, `update` stops with a clear error. `--unsigned` skips signature checks for that run only, and says so loudly. The signed path is the default and never falls back by itself.

## First install and server upgrades

- **First install** (`curl https://hogman.network/install.sh | sudo bash`) trusts whatever that HTTPS connection serves the first time. We say so plainly; nothing inside a script served by a possibly compromised server can vouch for that same server. Careful operators can check out of band:
  - against GitHub with `gh attestation verify`;
  - or with stock OpenSSL (`openssl pkeyutl -verify -rawin`) and the root public keys, which we publish on GitHub and on the site.
- **Every later upgrade** goes through the `hogman-host` that is already installed, which carries the built-in root keys. It verifies `keys.json`, `release.json` and the tarballs itself, and never fetches `install.sh` again. Today `install.sh` does the downloading and `hogman-host upgrade` only syncs local source. Part of this work is moving the download and the checks into `hogman-host`.

## TUF attack checklist

| Attack (TUF spec) | Covered by |
|---|---|
| Arbitrary software installation | Root key → `keys.json` → `release.json` → file hash |
| Rollback | Highest `version` stored on the computer, plus the compiled-in floor |
| Indefinite freeze | `expires` on both documents |
| Endless data | Size caps (#37) plus `size` in `release.json` |
| Mix-and-match | One `release.json` lists every file in the release |
| Signing-key compromise | New `keys.json` with a higher `key_version`; the old bundle can't be replayed |
| Root-key compromise (one) | Retire it with the other root in the next client release |
| Malicious mirror or pen server | Pens serve files only and hold no keys; every document is signed |
| Slow retrieval | Timeouts (#37) |
| Cross-context signature reuse | Domain-separation prefixes |

## Operations

- **The `release` environment:** maintainer approval, and deployment allowed only from protected tags. No pull request or branch run can ask for approval.
- **Reproducible builds:**
  - pin the builder image by digest in `core/join/Dockerfile` and `.github/workflows/build.yml`;
  - build with `-trimpath` and a fixed build ID;
  - take `VERSION` from the git tag and commit time, not from `date`.
- **A runbook in `docs/security/`:**
  - generating the root keys (offline, two copies each, in different places);
  - signing a new `keys.json`;
  - rotating the signing key;
  - what to do if a key leaks.

## What this does not cover

- A compromised GitHub account together with the maintainer approving the release run. The required approval and the public attestations make this visible, but they can't prevent it.
- First install, which trusts that first HTTPS download (above).
- Mac code signing and notarization (Phase 2, D-13). That is Apple's check that the program runs, and is separate from this one.

## Plan

1. A small `cmd/hogman-keys`, using only `crypto/ed25519`, generates the keys and signs `keys.json`. Root keys are generated offline in a session with the maintainer.
2. CI: `release.json` is signed in the protected `release` environment, plus `actions/attest-build-provenance`, the pinned builder image and a deterministic `VERSION`.
3. Client: the checks above in `hogman-join update`, and the same verifier in `hogman-host`, which takes over downloading from `install.sh` for upgrades.
4. Tests: a negative case for each line of the TUF checklist (wrong root, replayed old `keys.json`, lower `version`, expired document, file missing from `release.json`, wrong size, wrong prefix).
5. Docs: verifying a release by hand, the root fingerprints on the site, and this design's limits in the FAQ.
