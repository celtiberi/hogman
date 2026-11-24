# Changelog fragments

Add one file per PR here instead of editing `CHANGELOG.md` directly, so parallel PRs do not conflict.

## File name

```
changelog.d/<pr-or-branch>.<section>.md
```

Where `<section>` is one of:
- `security`
- `added`
- `changed`
- `fixed`

## Format

One or more Markdown list items starting with `- `:

```markdown
- `core/registrar`: added live `online` and `last_seen` presence fields to `/api/directory`.
```

## Folding at release time

Before running `deploy/release.sh`, fold fragments into `CHANGELOG.md`:

```bash
deploy/changelog-fold.sh <version>
```

`deploy/release.sh` refuses to publish a commit that still contains unfolded fragments.
