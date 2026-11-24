#!/usr/bin/env bash
# Fold changelog.d/<name>.<section>.md fragments into CHANGELOG.md for a release,
# or validate fragments with --check.
#
# Usage:
#   deploy/changelog-fold.sh --check
#   deploy/changelog-fold.sh <version> [YYYY-MM-DD]
set -euo pipefail

REPO="${CHANGELOG_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
FRAG_DIR="$REPO/changelog.d"
CHANGELOG="$REPO/CHANGELOG.md"

usage() {
  echo "usage: deploy/changelog-fold.sh --check | <version> [YYYY-MM-DD]" >&2
  exit 2
}

valid_fragment() {
  local f="$1" base section first
  base="$(basename "$f")"
  case "$base" in
    README.md) return 1 ;;
    *.security.md|*.added.md|*.changed.md|*.fixed.md) ;;
    *.md)
      echo "changelog-fold: invalid fragment name '$base' (expected <name>.<security|added|changed|fixed>.md)" >&2
      return 2
      ;;
    *)
      echo "changelog-fold: unexpected file in changelog.d/: '$base'" >&2
      return 2
      ;;
  esac
  if ! grep -q '[^[:space:]]' "$f"; then
    echo "changelog-fold: empty fragment '$base'" >&2
    return 2
  fi
  first="$(awk 'NF { print; exit }' "$f")"
  case "$first" in
    "- "*) ;;
    *)
      echo "changelog-fold: fragment '$base' must start with a Markdown bullet ('- ...')" >&2
      return 2
      ;;
  esac
  return 0
}

collect_fragments() {
  [ -d "$FRAG_DIR" ] || return 0
  local f rc
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    rc=0
    valid_fragment "$f" || rc=$?
    if [ "$rc" -eq 2 ]; then
      return 2
    elif [ "$rc" -eq 0 ]; then
      printf '%s\n' "$f"
    fi
  done < <(find "$FRAG_DIR" -mindepth 1 -maxdepth 1 -type f | sort)
}

if [ "${1:-}" = "--check" ]; then
  [ $# -eq 1 ] || usage
  collect_fragments >/dev/null
  exit 0
fi

[ $# -ge 1 ] && [ $# -le 2 ] || usage
ver="${1#v}"
date_str="${2:-$(date -u +%Y-%m-%d)}"
[[ "$ver" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]] || { echo "changelog-fold: invalid version '$ver'" >&2; exit 2; }
[[ "$date_str" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { echo "changelog-fold: invalid date '$date_str' (expected YYYY-MM-DD)" >&2; exit 2; }
[ -f "$CHANGELOG" ] || { echo "changelog-fold: missing $CHANGELOG" >&2; exit 1; }

frags=()
while IFS= read -r f; do
  [ -n "$f" ] && frags+=("$f")
done < <(collect_fragments)

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for sec in security added changed fixed; do
  : > "$tmp/$sec"
done

# Extract header (up to ## [Unreleased]), existing Unreleased section buckets, and older releases.
awk -v outdir="$tmp" '
  BEGIN { mode = "header"; sec = "" }
  /^## \[Unreleased\]/ {
    mode = "unreleased"
    next
  }
  /^## \[/ && mode == "unreleased" {
    mode = "tail"
  }
  mode == "header" {
    print > (outdir "/header")
    next
  }
  mode == "tail" {
    print > (outdir "/tail")
    next
  }
  mode == "unreleased" {
    if ($0 == "### Security") { sec = "security"; next }
    if ($0 == "### Added")    { sec = "added"; next }
    if ($0 == "### Changed")  { sec = "changed"; next }
    if ($0 == "### Fixed")    { sec = "fixed"; next }
    if (sec != "") {
      print > (outdir "/existing_" sec)
    }
  }
' "$CHANGELOG"

# Append fragments into each section bucket (fragments first, then existing Unreleased items).
for f in "${frags[@]+"${frags[@]}"}"; do
  base="$(basename "$f")"
  sec="${base%.md}"
  sec="${sec##*.}"
  awk 'NF { seen=1 } seen { print }' "$f" | awk '
    { lines[NR] = $0 }
    END {
      last = NR
      while (last > 0 && lines[last] ~ /^[[:space:]]*$/) last--
      for (i = 1; i <= last; i++) print lines[i]
    }' >> "$tmp/$sec"
done

for sec in security added changed fixed; do
  if [ -s "$tmp/existing_$sec" ]; then
    awk 'NF { seen=1 } seen { print }' "$tmp/existing_$sec" | awk '
      { lines[NR] = $0 }
      END {
        last = NR
        while (last > 0 && lines[last] ~ /^[[:space:]]*$/) last--
        for (i = 1; i <= last; i++) print lines[i]
      }' >> "$tmp/$sec"
  fi
done

has_any=0
for sec in security added changed fixed; do
  [ -s "$tmp/$sec" ] && has_any=1
done
if [ "$has_any" -eq 0 ]; then
  echo "changelog-fold: nothing under [Unreleased] or changelog.d/ to release" >&2
  exit 1
fi

{
  if [ -s "$tmp/header" ]; then
    cat "$tmp/header"
  fi
  printf '## [Unreleased]\n\n'
  printf '## [%s] - %s\n' "$ver" "$date_str"
  for pair in "security:Security" "added:Added" "changed:Changed" "fixed:Fixed"; do
    sec="${pair%%:*}"
    title="${pair#*:}"
    if [ -s "$tmp/$sec" ]; then
      printf '\n### %s\n' "$title"
      cat "$tmp/$sec"
    fi
  done
  if [ -s "$tmp/tail" ]; then
    printf '\n'
    cat "$tmp/tail"
  fi
} > "$tmp/CHANGELOG.md.new"

mv -f "$tmp/CHANGELOG.md.new" "$CHANGELOG"

for f in "${frags[@]+"${frags[@]}"}"; do
  if git -C "$REPO" ls-files --error-unmatch "${f#"$REPO/"}" >/dev/null 2>&1; then
    git -C "$REPO" rm -q -- "${f#"$REPO/"}"
  else
    rm -f -- "$f"
  fi
done

echo "folded ${#frags[@]} fragment(s) into CHANGELOG.md [$ver - $date_str]"
