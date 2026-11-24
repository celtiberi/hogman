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

## Release and post-release fold

`deploy/release.sh` releases directly from any green commit on `main` and builds the GitHub Release
notes from the fragments at that commit (plus any entries still under `## [Unreleased]`).

After publishing release `<version>`, fold the fragments into `CHANGELOG.md` in a small housekeeping PR:

```bash
deploy/changelog-fold.sh <version>
```
