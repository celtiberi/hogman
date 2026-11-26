#!/usr/bin/env bash
# Unit test for deploy/changelog-fold.sh.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/changelog-fold.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/changelog.d"
printf '# README\n' > "$TMP/changelog.d/README.md"
cat > "$TMP/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

### Fixed
- Existing unreleased fix.

## [2026.11.20-abc1234] - 2026-11-20

### Added
- Previous release item.
EOF

# 1. Invalid fragment name fails --check.
printf -- '- bad\n' > "$TMP/changelog.d/oops.unknown.md"
if CHANGELOG_REPO="$TMP" "$SCRIPT" --check >/dev/null 2>&1; then
  echo "FAIL: invalid section passed --check" >&2
  exit 1
fi
rm -f "$TMP/changelog.d/oops.unknown.md"

# 2. Non-bullet fragment fails --check.
printf 'not a bullet\n' > "$TMP/changelog.d/bad.added.md"
if CHANGELOG_REPO="$TMP" "$SCRIPT" --check >/dev/null 2>&1; then
  echo "FAIL: non-bullet fragment passed --check" >&2
  exit 1
fi
rm -f "$TMP/changelog.d/bad.added.md"

# 3. Valid fragments across sections pass --check, render --notes from git, and fold cleanly.
printf -- '- Security hardening item.\n' > "$TMP/changelog.d/sec.security.md"
printf -- '- Brand new feature.\n  - Sub-bullet detail.\n' > "$TMP/changelog.d/feat.added.md"
printf -- '- Changed behavior.\n' > "$TMP/changelog.d/chg.changed.md"
printf -- '- Fragment bugfix.\n' > "$TMP/changelog.d/bug.fixed.md"

CHANGELOG_REPO="$TMP" "$SCRIPT" --check

git -C "$TMP" init -q
git -C "$TMP" config user.name "test"
git -C "$TMP" config user.email "test@example.com"
git -C "$TMP" add CHANGELOG.md changelog.d
git -C "$TMP" commit -q -m "fixture"

cat > "$TMP/expected-notes.md" <<'EOF'
### Security
- Security hardening item.

### Added
- Brand new feature.
  - Sub-bullet detail.

### Changed
- Changed behavior.

### Fixed
- Fragment bugfix.
- Existing unreleased fix.
EOF
CHANGELOG_REPO="$TMP" "$SCRIPT" --notes HEAD > "$TMP/got-notes.md"
diff -u "$TMP/expected-notes.md" "$TMP/got-notes.md"

CHANGELOG_REPO="$TMP" "$SCRIPT" 2026.11.24-deadbee 2026-11-24 >/dev/null

# Fragments removed, README.md preserved.
[ -f "$TMP/changelog.d/README.md" ] || { echo "FAIL: README.md deleted" >&2; exit 1; }
for f in sec.security.md feat.added.md chg.changed.md bug.fixed.md; do
  [ ! -e "$TMP/changelog.d/$f" ] || { echo "FAIL: $f not deleted" >&2; exit 1; }
done

# Expected CHANGELOG.md content.
cat > "$TMP/expected.md" <<'EOF'
# Changelog

## [Unreleased]

## [2026.11.24-deadbee] - 2026-11-24

### Security
- Security hardening item.

### Added
- Brand new feature.
  - Sub-bullet detail.

### Changed
- Changed behavior.

### Fixed
- Fragment bugfix.
- Existing unreleased fix.

## [2026.11.20-abc1234] - 2026-11-20

### Added
- Previous release item.
EOF

diff -u "$TMP/expected.md" "$TMP/CHANGELOG.md"

# 4. --notes rejects unknown git refs and malformed committed fragment names.
if CHANGELOG_REPO="$TMP" "$SCRIPT" --notes refs/heads/does-not-exist >/dev/null 2>&1; then
  echo "FAIL: unknown git ref passed --notes" >&2
  exit 1
fi
printf -- '- bad\n' > "$TMP/changelog.d/bad.unknown.md"
git -C "$TMP" add changelog.d/bad.unknown.md
git -C "$TMP" commit -q -m "bad fragment"
if CHANGELOG_REPO="$TMP" "$SCRIPT" --notes HEAD >/dev/null 2>&1; then
  echo "FAIL: malformed fragment name passed --notes" >&2
  exit 1
fi

echo "PASS: changelog-fold.sh tests OK"
