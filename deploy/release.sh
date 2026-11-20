#!/usr/bin/env bash
# Publish a Hogman release on hogman.network, where install.sh fetches it.
#
#   deploy/release.sh [git-ref]      default: origin/main
#
# Packages committed code only (never the working folder), writes
#   site/public/dl/hogman-<version>.tar.gz, SHA256SUMS and latest,
# then deploys the website. Old tarballs stay listed in SHA256SUMS.
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
git archive --format=tar --prefix= "$REF" core deploy/hogman-host deploy/bootstrap.sh deploy/README.md LICENSE README.md \
  | gzip -9n > "$out/$tarball"

( cd "$out"
  touch SHA256SUMS
  grep -v "  $tarball\$" SHA256SUMS > SHA256SUMS.tmp || true
  if command -v sha256sum >/dev/null; then sha256sum "$tarball" >> SHA256SUMS.tmp; else shasum -a 256 "$tarball" >> SHA256SUMS.tmp; fi
  mv SHA256SUMS.tmp SHA256SUMS
  echo "$ver" > latest )

echo "release $ver ($(du -h "$out/$tarball" | cut -f1)) from $REF"
if [ "${NO_DEPLOY:-}" != 1 ]; then
  (cd "$REPO/site" && fly deploy --ha=false 2>&1 | grep -E "Visit|rror")
  echo "live: https://hogman.network/dl/latest -> $(curl -fsS https://hogman.network/dl/latest)"
fi
