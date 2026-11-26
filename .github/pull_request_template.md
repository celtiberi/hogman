## What and why

<!-- One or two sentences. Link the decision (D-n), audit item (Hn) or issue it comes from. -->

## Checklist

- [ ] **Docs:** `README.md` and relevant module docs (`core/README.md`, `docs/`, `browser-ext/README.md`, website docs if user-facing) say what this changes, **or** it isn't user-facing because: ___
- [ ] **Changelog:** added a fragment in `changelog.d/` (or `CHANGELOG.md` under Unreleased).
- [ ] **Security-relevant?** Then it names the standard it follows (OWASP, TUF, SLSA, CIS, RFC…) and has a dedicated security review.
- [ ] Tests cover the change, and local `go vet` / `go test` pass for the modules touched (`GOFLAGS="-tags=ts_omit_peerapiserver"` is required for `core/join` and `core/registrar`).

The reviewer checks the Docs box as well as the code: a change that changes what users or keepers see isn't done until the docs say so.
