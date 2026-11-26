#!/usr/bin/env bash
# Publish a Hogman release to GitHub Releases on celtiberi/hogman.
#
#   deploy/release.sh [git-ref]      default: origin/main
#
# Normally run by .github/workflows/release.yml, in two steps so the packaged
# files can be given GitHub build provenance before anything is published:
#   NO_DEPLOY=1 OUT_DIR=<dir> deploy/release.sh <ref>    package only
#   PUBLISH_FROM=<dir> deploy/release.sh <ref>           publish exactly those files
#
# Packages committed code only (never the working folder):
#   hogman-<version>.tar.gz (core/, deploy/challenge-dns/, LICENSE, README.md),
#   hogman-bin-<version>.tar.gz (compiled client CLI, registrar, and challenge
#   DNS), standalone hogman-* client binaries + hogman-SHA256SUMS (for
#   `hogman update`), SHA256SUMS, and latest.
#
# Creates the GitHub Release as a draft with every asset uploaded first, verifies
# the asset list, then publishes it and marks it latest atomically (compatible
# with GitHub's immutable releases setting).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
REF="${1:-origin/main}"
cd "$REPO"
git fetch -q origin 2>/dev/null || true
full="$(git rev-parse "$REF^{commit}")"   # a tag resolves to its commit
sha="${full:0:7}"
commit_date="$(TZ=UTC git show -s --format=%cd --date=format-local:%Y.%m.%d "$full")"
ver="$commit_date-$sha"
tag="v$ver"

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

repo="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
# Standalone attested hogman client binaries + checksums for `hogman update`.
cli_bins=(
  hogman-Darwin-arm64
  hogman-Darwin-x86_64
  hogman-Linux-x86_64
  hogman-Linux-aarch64
  hogman-windows-amd64.exe
)

package() {
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
# Reject any symlink or non-regular/non-directory entry inside the downloaded
# build artifact before verifying provenance or archiving into hogman-bin.
bad_entries="$(find "$work/prebuilt" ! -type f ! -type d)"
if [ -n "$bad_entries" ]; then
  echo "unexpected non-regular entries in build artifact (not releasing):" >&2
  printf '%s\n' "$bad_entries" >&2
  exit 1
fi
# Artifacts lose the executable bit.
find "$work/prebuilt" -type f ! -name SHA256SUMS -exec chmod 0755 {} +
checked=0
while IFS= read -r -d '' f; do
  gh attestation verify "$f" --repo "$repo" --deny-self-hosted-runners \
    --signer-workflow "$repo/.github/workflows/build.yml" --source-digest "$full" >/dev/null \
    || { echo "no valid provenance for ${f#"$work/"}: not releasing" >&2; exit 1; }
  checked=$((checked + 1))
done < <(find "$work/prebuilt" -type f -print0)
[ "$checked" -gt 0 ] || { echo "GitHub's build of $sha has no files: not releasing" >&2; exit 1; }
echo "provenance checked: $checked files, each built by build.yml from $sha on GitHub's runners"

# Refuse to publish a client whose embedded --version doesn't match this release
# (I-8: prevents releasing binaries stamped "dev" or built for another commit).
host_cli="$work/prebuilt/join/hogman-$(uname -s)-$(uname -m)"
[ -x "$host_cli" ] || { echo "missing runnable host client binary $(basename "$host_cli"): not releasing" >&2; exit 1; }
got_ver_out="$("$host_cli" --version)"
got_ver="$(printf '%s\n' "$got_ver_out" | awk '{print $2}')"
got_ver="${got_ver#v}"
if [ -z "$got_ver" ] || [ "$got_ver" = "dev" ] || [ "$got_ver" != "$ver" ]; then
  echo "$(basename "$host_cli") reported version '${got_ver:-<empty>}' ('$got_ver_out'), expected '$ver': not releasing" >&2
  exit 1
fi
echo "client version checked: $got_ver_out"

# Only now that the compiled parts check out, package release assets from $REF.
git archive --format=tar --prefix= "$REF" core deploy/challenge-dns LICENSE README.md \
  | gzip -9n > "$out/$tarball"
# No macOS file metadata in the bundle (Linux tar warns about it), and every
# entry owned by root (0:0). Without that the archive carries the builder's
# uid and account name: install.sh runs as root, so the files would land owned
# by whichever local user has that uid, and the name would be public.
if tar --version 2>/dev/null | grep -q bsdtar; then
  COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata --uid 0 --gid 0 --uname root --gname root \
    -C "$work" -czf "$out/$bins" prebuilt
else
  tar --owner=root:0 --group=root:0 -C "$work" -czf "$out/$bins" prebuilt
fi
# Refuse to publish an archive with any other owner (both archives).
for a in "$out/$tarball" "$out/$bins"; do
  bad="$(tar --numeric-owner -tvzf "$a" | awk '{ o = ($2 ~ "/") ? $2 : $3 "/" $4; if (o != "0/0") n++ } END { print n + 0 }')"
  [ "$bad" = 0 ] || { echo "$(basename "$a"): $bad entries are not owned by 0:0: not releasing" >&2; exit 1; }
  # (root is the name every entry is meant to carry, so skip this when run as root.)
  me="$(id -un)"
  if [ "$me" != root ] && tar -tvzf "$a" | awk '{ print $2, $3, $4 }' | grep -qw -- "$me"; then
    echo "$(basename "$a") contains this account's name: not releasing" >&2; exit 1
  fi
done

[ -f "$work/prebuilt/join/SHA256SUMS" ] || { echo "missing prebuilt/join/SHA256SUMS: not releasing" >&2; exit 1; }
for cb in "${cli_bins[@]}"; do
  [ -f "$work/prebuilt/join/$cb" ] || { echo "missing prebuilt/join/$cb: not releasing" >&2; exit 1; }
  cp "$work/prebuilt/join/$cb" "$out/$cb"
done
cp "$work/prebuilt/join/SHA256SUMS" "$out/hogman-SHA256SUMS"
( cd "$out"
  if command -v sha256sum >/dev/null; then
    sha256sum -c --quiet hogman-SHA256SUMS
  else
    shasum -a 256 -c --quiet hogman-SHA256SUMS
  fi ) || { echo "hogman-SHA256SUMS verification failed: not releasing" >&2; exit 1; }

( cd "$out"
  if command -v sha256sum >/dev/null; then
    sha256sum "$tarball" "$bins"
  else
    shasum -a 256 "$tarball" "$bins"
  fi > SHA256SUMS
  printf '%s\n' "$ver" > latest )

echo "compiled bundle $bins ($(du -h "$out/$bins" | cut -f1))"
echo "release $ver ($(du -h "$out/$tarball" | cut -f1)) from $REF"

}

# PUBLISH_FROM=<dir>: publish files an earlier NO_DEPLOY=1 run packaged for this
# same commit, without rebuilding them (a rebuilt archive has a different
# digest, so provenance made for the first one would not match).
if [ -n "${PUBLISH_FROM:-}" ]; then
  [ "${NO_DEPLOY:-}" != 1 ] || { echo "PUBLISH_FROM and NO_DEPLOY=1 together make no sense" >&2; exit 2; }
  out="$(cd "$PUBLISH_FROM" && pwd)"
  [ "$(tr -d '\r\n' < "$out/latest" 2>/dev/null)" = "$ver" ] \
    || { echo "$out was not packaged for $ver: not publishing" >&2; exit 1; }
  for f in "$tarball" "$bins" SHA256SUMS hogman-SHA256SUMS latest "${cli_bins[@]}"; do
    [ -f "$out/$f" ] && [ ! -L "$out/$f" ] || { echo "missing or not a regular file in $out: $f" >&2; exit 1; }
  done
  # `sha256sum -c` only checks the lines a checksum file has, so a shortened
  # file would leave an archive unchecked: each must list exactly its files.
  sums_names() { awk '{ sub(/^\*/, "", $2); print $2 }' "$1" | sort; }
  [ "$(sums_names "$out/SHA256SUMS")" = "$(printf '%s\n' "$tarball" "$bins" | sort)" ] \
    || { echo "$out/SHA256SUMS does not list exactly the two archives: not publishing" >&2; exit 1; }
  [ "$(sums_names "$out/hogman-SHA256SUMS")" = "$(printf '%s\n' "${cli_bins[@]}" | sort)" ] \
    || { echo "$out/hogman-SHA256SUMS does not list exactly the client binaries: not publishing" >&2; exit 1; }
  ( cd "$out"
    if command -v sha256sum >/dev/null; then
      sha256sum -c --quiet SHA256SUMS && sha256sum -c --quiet hogman-SHA256SUMS
    else
      shasum -a 256 -c --quiet SHA256SUMS && shasum -a 256 -c --quiet hogman-SHA256SUMS
    fi ) || { echo "checksums in $out do not match its files: not publishing" >&2; exit 1; }
else
  package
fi

if [ "${NO_DEPLOY:-}" != 1 ]; then
  if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
    echo "release $tag already exists on $repo: not overwriting" >&2
    exit 1
  fi
  release_files=(
    "$out/$tarball" "$out/$bins" "$out/SHA256SUMS" "$out/latest"
    "$out/hogman-SHA256SUMS"
  )
  for cb in "${cli_bins[@]}"; do
    release_files+=("$out/$cb")
  done
  {
    printf 'Release `%s` from commit `%s` (compiled binaries verified via GitHub build provenance).\n' "$ver" "$full"
    if [ -x "$REPO/deploy/changelog-fold.sh" ]; then
      notes="$(CHANGELOG_REPO="$REPO" "$REPO/deploy/changelog-fold.sh" --notes "$REF" || true)"
      if [ -n "$notes" ]; then
        printf '\n%s\n' "$notes"
      fi
    fi
  } > "$work/release-notes.md"

  # Upload every asset into a draft release first, verify the asset list, then
  # publish and mark latest atomically (required for immutable releases).
  gh release create "$tag" \
    --repo "$repo" \
    --draft \
    --target "$full" \
    --title "Hogman $ver" \
    --notes-file "$work/release-notes.md" \
    "${release_files[@]}"

  want_assets="$(printf '%s\n' "$bins" "$tarball" "SHA256SUMS" "latest" "hogman-SHA256SUMS" "${cli_bins[@]}" | sort)"
  got_assets="$(gh release view "$tag" --repo "$repo" --json assets --jq '[.assets[].name] | sort | join("\n")')"
  if [ "$got_assets" != "$want_assets" ]; then
    echo "draft release $tag asset mismatch (leaving as draft): got '$got_assets'" >&2
    exit 1
  fi

  gh release edit "$tag" --repo "$repo" --draft=false --latest

  live=""
  for _ in 1 2 3 4 5; do
    live="$(curl --proto '=https' --proto-redir '=https' -fsSL "https://github.com/$repo/releases/latest/download/latest" 2>/dev/null | tr -d '\r\n' || true)"
    [ "$live" = "$ver" ] && break
    sleep 2
  done
  [ "$live" = "$ver" ] || { echo "live latest returned '$live', expected '$ver'" >&2; exit 1; }
  echo "live: https://github.com/$repo/releases/tag/$tag (latest -> $live)"
fi
