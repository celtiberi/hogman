# Signed releases (D-15): design

Status: **draft**, for @hogman's review and a red-team before any code. P1, after `hogman-join update` (PR #37).

## Problem

Every download is checked only against a `SHA256SUMS` file that comes from the same server, over the same TLS connection:

- a new computer downloading `hogman-join` from `/join/dl/`;
- `hogman-join update`;
- `install.sh` and `hogman-host upgrade` fetching a pen's release from hogman.network.

That catches corrupted or cut-off downloads. It does not catch a server that has been broken into: that server serves a tampered build together with a matching checksum. It also cannot stop an old, vulnerable build from being served as current.

## Standard practice we follow

We don't invent a scheme. The design follows these sources:

- **The Update Framework (TUF) spec.** TUF is the standard threat model for software updaters. Its attack list is our checklist (below), and its separation of roles (offline root keys, an online signing key) is our key layout.
- **Tailscale's `clientupdate/distsign`.** This is the same pattern applied to a Go client. It is already in our dependency tree (`tailscale.com@v1.104.7`) and is used in production by the client our pens run on:
  - Ed25519 throughout;
  - root keys kept offline, in more than one place, and built into the client;
  - root keys sign a bundle of signing keys, and a signing key signs each file.

  We reuse its exported building blocks: `GenerateRootKey`, `RootKey.SignSigningKeys`, `SigningKey.SignPackageHash` and `VerifyAny`. We don't write any new cryptography. (Its `Client` hard-codes Tailscale's own root keys, so we write the small client part ourselves.)
- **SLSA build provenance via GitHub artifact attestations.** These are a public, independent record that each binary was built by our workflow from a specific commit. Anyone can check one with `gh attestation verify`. They are a supplement, not what clients check.
- **Reproducible Go builds** (`-trimpath`, fixed build ID). Anyone can rebuild a tagged commit and compare hashes. The build step already compiles with `CGO_ENABLED=0`.

## Keys

| Key | Where it lives | What it signs | Rotation |
|---|---|---|---|
| Root keys (2, Ed25519) | Offline, in two different places, held by @patrick. Never on a server and never in CI. | The signing-key bundle (`hogman-sign.pub`), so roots are used only to bring in a new signing key. | Only by shipping a new client that lists the new root. Having two roots means a lost one can be retired with the other. |
| Signing key (Ed25519) | A GitHub Actions secret in a protected `release` environment that needs @patrick's approval for each run. Never on a pen. | The release manifest. | Freely: re-sign the bundle with a root key. |

The public root keys are compiled into `hogman-join` and into `hogman-host`'s verifier.

## What gets signed: one manifest per release

`release.json`:

```json
{
  "version": 202611201,
  "commit": "…",
  "expires": "…",
  "files": {"hogman-join-Darwin-arm64": {"sha256": "…", "size": 123}, …}
}
```

The release is published with `release.json.sig`, and the signing-key bundle with `hogman-sign.pub` and `hogman-sign.pub.sig`. Signing one manifest instead of each file gives us a version number and an expiry date, which TUF's rollback and freeze defences need and which per-file signatures (as in `distsign`) don't carry.

## Client checks (`hogman-join update`, `install.sh` through a verifier, `hogman-host upgrade`)

1. Fetch `hogman-sign.pub` and its signature, and verify them against the built-in root keys.
2. Fetch `release.json` and its signature, and verify them against those signing keys.
3. **Rollback:** refuse a `version` lower than the highest one this computer has installed. That version is stored next to the binary. It's on by default and an override needs an explicit flag.
4. **Freeze:** refuse an expired manifest. Expiry is long (90 days) and every release re-signs, so a quiet project doesn't lock people out.
5. Download the file, and check its size and SHA-256 against the manifest before replacing anything. PR #37 already does the atomic swap and the restart if the swap fails.
6. Any failure leaves the installed version untouched and says which check failed.

`install.sh` is a shell script, so it can't check Ed25519 by itself. It fetches a small verifier, pinned by its hash in the script, or the first install falls back to "check the fingerprint we publish on the site". This is an open question for the red-team.

## TUF attack checklist

| Attack (TUF spec) | Covered by |
|---|---|
| Arbitrary software installation | Signature from built-in root keys through the signing key |
| Rollback | Highest installed version stored on the computer |
| Indefinite freeze | Manifest `expires` |
| Endless data | Size caps (#37) plus the manifest's `size` |
| Mix-and-match | One manifest lists every file in the release |
| Key compromise (signing key) | Rotate: re-sign the bundle with a root key, and all clients pick it up |
| Key compromise (one root) | Retire it with the other root in the next client release |
| Malicious mirror or pen server | Pens serve files only; they hold no keys |
| Slow retrieval | Timeouts (#37) |

What full TUF adds that we leave out for now: a separate snapshot and timestamp role, signing thresholds, and delegations. We have one publisher and one channel, and Tailscale ships the same reduced form. go-tuf v2 was considered; it's worth adopting if we ever have several publishers or mirrors.

## What this does not cover

- A compromised GitHub account together with @patrick approving the release run. The required approval and the public attestations make this visible, but they can't prevent it.
- The first download of `hogman-join` (trust on first use). The site will publish the root-key fingerprints so careful users can check them.
- Mac code signing and notarization (Phase 2, D-13). That is Apple's check that the program runs, and is separate from this one.

## Plan

1. Generate the root keys offline with a small `cmd/hogman-keys` built on `distsign`, in a session with @patrick. Keep two copies of each, in different places.
2. CI: sign `release.json` in the protected `release` environment, and add `actions/attest-build-provenance`.
3. Client: steps 1–6 above in `hogman-join update`, and the same checks in `hogman-host upgrade`.
4. Docs: how to verify a release by hand, the root fingerprints on the site, and this design's limits in the FAQ.
