## What and why

<!-- One or two sentences. Link the decision (D-n), audit item (Hn) or issue it comes from. -->

## Checklist

- [ ] **Docs:** the README and the keeper's guide (`deploy/README.md`) say what this changes (plus the website docs if user-facing), **or** it isn't user-facing because: ___
- [ ] **CHANGELOG.md** has a line under Unreleased.
- [ ] **Security-relevant?** Then it names the standard it follows (OWASP, TUF, SLSA, CIS, RFC…) and was reviewed by the other AI.
- [ ] Tests cover the change, and local `go vet` / `go test` pass for the modules touched.

The reviewer checks the Docs box as well as the code: a change that changes what users or keepers see isn't done until the docs say so.
