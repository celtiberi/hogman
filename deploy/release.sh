#!/usr/bin/env bash
# Publish a Hogman release to GitHub Releases on celtiberi/hogman, where
# deploy/install.sh fetches it.
#
#   deploy/release.sh [git-ref]      default: origin/main
#
# Packages committed code only (never the working folder):
#   hogman-<version>.tar.gz, hogman-bin-<version>.tar.gz (compiled join tool,
#   registrar, sign-up page and challenge DNS), install.sh, SHA256SUMS and latest.
#
# Creates the GitHub Release as a draft with every asset uploaded first, verifies
# the asset list, then publishes it and marks it latest atomically (compatible
# with GitHub's immutable releases setting).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
REF="${1:-origin/main}"
cd "$REPO"
git fetch -q origin 2>/dev/null || true
sha="$(git rev-parse --short=7 "$REF")"
ver="$(date -u +%Y.%m.%d)-$sha"
tag="v$ver"

git cat-file -e "$REF:deploy/install.sh" 2>/dev/null || {
  echo "commit $sha does not contain deploy/install.sh: not releasing" >&2
  exit 1
}

tarball="hogman-$ver.tar.gz"
bins="hogman-bin-$ver.tar.gz"

# Compiled parts, so servers don't spend half an hour building them. They come
# only from GitHub's build of this exact commit (.github/workflows/build.yml),
# never from this machine (audit H5), and every file must carry GitHub's signed
# provenance from that workflow before anything is published.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
out="${OUT_DIR:-$work/out}"
mkdir -p "$out"

full="$(git rev-parse "$REF^{commit}")"   # a tag resolves to its commit
echo "using GitHub's build of $sha..."
# Only push or manual runs: a pull-request run builds a merge commit, and its
# artifact is named after that, not $full (and isn't attested).
run="$(gh run list --workflow build.yml --commit "$full" --status success --limit 20 \
        --json databaseId,event --jq '[.[] | select(.event != "pull_request")][0].databaseId // empty')"
if [ -z "$run" ]; then
  echo "no successful GitHub build for $sha yet. Watch it: gh run list --workflow build.yml" >&2
  echo "(it runs on every push to main; or start one: gh workflow run build.yml --ref main)" >&2
  exit 1
fi
if ! gh run download "$run" --name "hogman-bin-$full" --dir "$work/prebuilt"; then
  echo "GitHub's build of $sha can't be downloaded (builds are kept 30 days); release a newer commit." >&2
  exit 1
fi
# Artifacts lose the executable bit.
find "$work/prebuilt" -type f ! -name SHA256SUMS -exec chmod 0755 {} +
repo="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
checked=0
while IFS= read -r -d '' f; do
  gh attestation verify "$f" --repo "$repo" --deny-self-hosted-runners \
    --signer-workflow "$repo/.github/workflows/build.yml" --source-digest "$full" >/dev/null \
    || { echo "no valid provenance for ${f#"$work/"}: not releasing" >&2; exit 1; }
  checked=$((checked + 1))
done < <(find "$work/prebuilt" -type f -print0)
[ "$checked" -gt 0 ] || { echo "GitHub's build of $sha has no files: not releasing" >&2; exit 1; }
echo "provenance checked: $checked files, each built by build.yml from $sha on GitHub's runners"

# Only now that the compiled parts check out, package release assets from $REF.
git archive --format=tar --prefix= "$REF" core deploy/hogman-host deploy/bootstrap.sh deploy/README.md deploy/signup deploy/challenge-dns LICENSE README.md \
  | gzip -9n > "$out/$tarball"
# No macOS file metadata in the bundle (Linux tar warns about it).
COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -C "$work" -czf "$out/$bins" prebuilt
git show "$REF:deploy/install.sh" > "$out/install.sh"

( cd "$out"
  if command -v sha256sum >/dev/null; then
    sha256sum "$tarball" "$bins" install.sh
  else
    shasum -a 256 "$tarball" "$bins" install.sh
  fi > SHA256SUMS
  printf '%s\n' "$ver" > latest )

echo "compiled bundle $bins ($(du -h "$out/$bins" | cut -f1))"
echo "release $ver ($(du -h "$out/$tarball" | cut -f1)) from $REF"

if [ "${NO_DEPLOY:-}" != 1 ]; then
  if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
    echo "release $tag already exists on $repo: not overwriting" >&2
    exit 1
  fi
  # Upload every asset into a draft release first, verify the asset list, then
  # publish and mark latest atomically (required for immutable releases).
  gh release create "$tag" \
    --repo "$repo" \
    --draft \
    --target "$full" \
    --title "Hogman $ver" \
    --notes "Release \`$ver\` from commit \`$full\` (compiled binaries verified via GitHub build provenance)." \
    "$out/$tarball" "$out/$bins" "$out/SHA256SUMS" "$out/latest" "$out/install.sh"

  want_assets="$(printf '%s\n' "$bins" "$tarball" "SHA256SUMS" "install.sh" "latest" | sort)"
  got_assets="$(gh release view "$tag" --repo "$repo" --json assets --jq '[.assets[].name] | sort | join("\n")')"
  if [ "$got_assets" != "$want_assets" ]; then
    echo "draft release $tag asset mismatch (leaving as draft): got '$got_assets'" >&2
    exit 1
  fi

  gh release edit "$tag" --repo "$repo" --draft=false --latest

  live=""
  for _ in 1 2 3 4 5; do
    live="$(curl -fsSL "https://github.com/$repo/releases/latest/download/latest" 2>/dev/null | tr -d '\r\n' || true)"
    [ "$live" = "$ver" ] && break
    sleep 2
  done
  [ "$live" = "$ver" ] || { echo "live latest returned '$live', expected '$ver'" >&2; exit 1; }
  echo "live: https://github.com/$repo/releases/tag/$tag (latest -> $live)"
fi
