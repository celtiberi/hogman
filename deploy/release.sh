#!/usr/bin/env bash
# Publish a Hogman release on hogman.network, where install.sh fetches it.
#
#   deploy/release.sh [git-ref]      default: origin/main
#
# Packages committed code only (never the working folder), writes
#   site/public/dl/hogman-<version>.tar.gz, SHA256SUMS and latest,
# plus hogman-bin-<version>.tar.gz (compiled join tool, registrar and sign-up page),
# then deploys the website.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
REF="${1:-origin/main}"
cd "$REPO"
git fetch -q origin 2>/dev/null || true
sha="$(git rev-parse --short=7 "$REF")"
ver="$(date -u +%Y.%m.%d)-$sha"
out="$REPO/site/public/dl"
mkdir -p "$out"

tarball="hogman-$ver.tar.gz"
git archive --format=tar --prefix= "$REF" core deploy/hogman-host deploy/bootstrap.sh deploy/README.md deploy/signup LICENSE README.md \
  | gzip -9n > "$out/$tarball"

# Compiled parts, so servers don't spend half an hour building them: built
# here when Docker is running, otherwise taken from GitHub's build of this
# exact commit (.github/workflows/build.yml), so no Docker is needed locally.
bins="hogman-bin-$ver.tar.gz"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
full="$(git rev-parse "$REF^{commit}")"   # a tag resolves to its commit
if [ "${USE_CI_BUILD:-}" != 1 ] && docker info >/dev/null 2>&1; then
  git archive --format=tar "$REF" core/join core/registrar deploy/signup | tar -x -C "$work"
  deploy/build-bins.sh "$work" "$work/prebuilt"
else
  echo "Docker isn't running here: using GitHub's build of $sha..."
  # Only push or manual runs: a pull-request run builds a merge commit, and
  # its artifact is named after that, not $full.
  run="$(gh run list --workflow build.yml --commit "$full" --status success --limit 20 \
          --json databaseId,event --jq '[.[] | select(.event != "pull_request")][0].databaseId // empty')"
  if [ -z "$run" ]; then
    echo "no successful GitHub build for $sha yet. Watch it: gh run list --workflow build.yml" >&2
    echo "(it runs on every push to main; or start one: gh workflow run build.yml --ref main)" >&2
    exit 1
  fi
  if ! gh run download "$run" --name "hogman-bin-$full" --dir "$work/prebuilt"; then
    echo "GitHub's build of $sha can't be downloaded (builds are kept 30 days)." >&2
    echo "Start Docker and run this again, or release a newer commit." >&2
    exit 1
  fi
  # Artifacts lose the executable bit.
  find "$work/prebuilt" -type f ! -name SHA256SUMS -exec chmod 0755 {} +
fi
# No macOS file metadata in the bundle (Linux tar warns about it).
COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -C "$work" -czf "$out/$bins" prebuilt

# Keep only the newest bundles; the website serves just the current release.
find "$out" -maxdepth 1 -name 'hogman-*.tar.gz' ! -name "$tarball" ! -name "$bins" -delete

( cd "$out"
  if command -v sha256sum >/dev/null; then sha256sum "$tarball" "$bins"; else shasum -a 256 "$tarball" "$bins"; fi > SHA256SUMS
  echo "$ver" > latest )
echo "compiled bundle $bins ($(du -h "$out/$bins" | cut -f1))"

echo "release $ver ($(du -h "$out/$tarball" | cut -f1)) from $REF"
if [ "${NO_DEPLOY:-}" != 1 ]; then
  (cd "$REPO/site" && fly deploy --ha=false 2>&1 | grep -E "Visit|rror")
  echo "live: https://hogman.network/dl/latest -> $(curl -fsS https://hogman.network/dl/latest)"
fi
