# Security Policy

## Reporting a vulnerability

If you find a security vulnerability in Hogman, please report it privately:

- **Preferred:** use **"Report a vulnerability"** under the repository's [Security tab](https://github.com/celtiberi/hogman/security/advisories/new).
- **Fallback:** email `hogman-support@proton.me`.

**Never report a security vulnerability in a public GitHub issue or pull request.**

## Scope

This policy covers:

- [`core/`](core/) — the `hogman` client CLI, registrar, and pen configuration
- [`browser-ext/`](browser-ext/) — the Chrome and Firefox browser extension
- [`deploy/challenge-dns`](deploy/challenge-dns) — the ACME DNS-01 challenge server
- Official released client binaries and the `ghcr.io/celtiberi/hogman-sidecar` container image

## What to expect

- We will acknowledge your report within a few days and follow up as we investigate and prepare a fix.
- We are happy to credit you in the security advisory and release notes if you want to be named.
- Security fixes follow the same rule as [`CONTRIBUTING.md`](CONTRIBUTING.md): we do not accept external code pull requests without a signed CLA, so please report the vulnerability privately and we will write the fix.
