#!/usr/bin/env python3
"""Deterministic, reproducible packager for Hogman browser extensions.

Default (store build):
  Builds unpacked directories and reproducible .zip bundles for Chrome (MV3) and
  Firefox (MV3) under browser-ext/dist/ along with SHA256SUMS, strictly scoped
  to pens.hogman.network.

Staging / custom-domain test build (--zone-suffix <suffix>):
  Builds unpacked-only, never-published extensions under
  browser-ext/dist/staging/{chrome,firefox} scoped exclusively to <suffix> with
  distinct name ("Hogman (staging)") and extension ID. Refuses to generate .zip
  archives or SHA256SUMS so staging builds cannot be published to stores.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent
SRC = ROOT / "src"
DIST = ROOT / "dist"
DEFAULT_ZONE_SUFFIX = "pens.hogman.network"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
IGNORED_NAMES = frozenset({"Thumbs.db", "__pycache__"})
IGNORED_SUFFIXES = (".swp", ".swo", ".tmp", ".pyc", "~")
ZONE_SUFFIX_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
ZONE_SUFFIX_LINE = f'export const ZONE_SUFFIX = "{DEFAULT_ZONE_SUFFIX}";'


def should_include(rel: pathlib.Path) -> bool:
    for part in rel.parts:
        if part.startswith(".") or part in IGNORED_NAMES:
            return False
    return not any(rel.name.endswith(sfx) for sfx in IGNORED_SUFFIXES)


def validate_zone_suffix(raw: str) -> str:
    if not isinstance(raw, str):
        raise ValueError("zone suffix must be a string")
    suffix = raw.strip().lower()
    if not suffix or len(suffix) > 200 or not ZONE_SUFFIX_RE.fullmatch(suffix):
        raise ValueError(
            f"invalid --zone-suffix {raw!r}: expected lowercase DNS hostname with at least two labels (e.g. pens.staging.example)"
        )
    if suffix == DEFAULT_ZONE_SUFFIX:
        raise ValueError(
            f"--zone-suffix must not be {DEFAULT_ZONE_SUFFIX!r}; omit --zone-suffix for the store build"
        )
    return suffix


def verify_manifest_versions(src_root: pathlib.Path = SRC) -> str:
    versions: dict[str, str] = {}
    for target in ("chrome", "firefox"):
        manifest_path = src_root / target / "manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        ver = data.get("version")
        if not isinstance(ver, str) or not ver.strip():
            raise ValueError(f"{manifest_path}: missing non-empty version")
        versions[target] = ver.strip()
    if versions["chrome"] != versions["firefox"]:
        raise ValueError(
            f"manifest version mismatch: chrome={versions['chrome']!r} != firefox={versions['firefox']!r}"
        )
    return versions["chrome"]


def _copy_target_tree(target: str, src_root: pathlib.Path, unpacked: pathlib.Path) -> None:
    if unpacked.is_symlink():
        raise ValueError(f"refusing symlink output directory: {unpacked}")
    if unpacked.exists():
        shutil.rmtree(unpacked)
    unpacked.mkdir(parents=True)

    for src_dir in (src_root / "shared", src_root / target):
        entries = sorted(
            src_dir.rglob("*"),
            key=lambda p: p.relative_to(src_dir).as_posix(),
        )
        for path in entries:
            rel = path.relative_to(src_dir)
            if path.is_symlink():
                raise ValueError(f"refusing symlink in extension source: {path}")
            if path.is_dir():
                continue
            if not path.is_file() or not should_include(rel):
                continue
            dst = unpacked / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, dst)


def build_target(target: str, src_root: pathlib.Path = SRC, dist_root: pathlib.Path = DIST) -> pathlib.Path:
    unpacked = dist_root / target
    _copy_target_tree(target, src_root, unpacked)

    zip_path = dist_root / f"hogman-ext-{target}.zip"
    if zip_path.is_symlink():
        raise ValueError(f"refusing symlink output archive: {zip_path}")
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        packed_files = sorted(
            (p for p in unpacked.rglob("*") if p.is_file() and not p.is_symlink()),
            key=lambda p: p.relative_to(unpacked).as_posix(),
        )
        for path in packed_files:
            rel = path.relative_to(unpacked).as_posix()
            info = zipfile.ZipInfo(filename=rel, date_time=FIXED_ZIP_TIME)
            info.create_system = 3  # Unix, for byte-identical zips across OSes
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, path.read_bytes())
    return zip_path


def build_staging_target(
    target: str,
    zone_suffix: str,
    src_root: pathlib.Path = SRC,
    dist_root: pathlib.Path = DIST,
) -> pathlib.Path:
    """Build an unpacked-only, never-published staging/test extension for zone_suffix."""
    if target not in ("chrome", "firefox"):
        raise ValueError(f"unsupported target: {target!r}")
    suffix = validate_zone_suffix(zone_suffix)
    unpacked = dist_root / "staging" / target
    _copy_target_tree(target, src_root, unpacked)

    # 1. Rewrite constants.js ZONE_SUFFIX strictly in the staged output.
    const_path = unpacked / "constants.js"
    const_text = const_path.read_text(encoding="utf-8")
    if const_text.count(ZONE_SUFFIX_LINE) != 1:
        raise ValueError(f"{const_path}: expected exactly one ZONE_SUFFIX definition")
    const_path.write_text(
        const_text.replace(ZONE_SUFFIX_LINE, f"export const ZONE_SUFFIX = {json.dumps(suffix)};", 1),
        encoding="utf-8",
    )

    # 2. Rewrite manifest.json with distinct name, staging description, and scoped permissions/ID.
    manifest_path = unpacked / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["name"] = "Hogman (staging)"
    manifest["description"] = (
        f"Staging/test build — routes *.{suffix} pen sites to your local hogman proxy (unpacked only, never publish)."
    )
    if isinstance(manifest.get("action"), dict):
        manifest["action"]["default_title"] = "Hogman (staging)"
    if target == "chrome":
        manifest.pop("key", None)
        if "host_permissions" in manifest:
            raise ValueError("chrome staging manifest must not declare host_permissions")
    else:
        manifest["host_permissions"] = [f"*://*.{suffix}/*", f"*://{suffix}/*"]
        bss = manifest.setdefault("browser_specific_settings", {})
        gecko = bss.setdefault("gecko", {})
        gecko["id"] = f"hogman-browser-staging@{suffix}"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    # 3. Update popup.html labels so the staging build is visually unmistakable.
    popup_path = unpacked / "popup.html"
    if popup_path.is_file():
        popup = popup_path.read_text(encoding="utf-8")
        popup = popup.replace("<title>Hogman</title>", "<title>Hogman (staging)</title>", 1)
        popup = popup.replace("<h1>Hogman</h1>", "<h1>Hogman (staging)</h1>", 1)
        popup = popup.replace(f"*.{DEFAULT_ZONE_SUFFIX}", f"*.{suffix}")
        popup_path.write_text(popup, encoding="utf-8")

    return unpacked


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Build Hogman browser extensions (store zips by default, or unpacked staging builds with --zone-suffix)."
    )
    parser.add_argument(
        "--zone-suffix",
        default=None,
        help=(
            "Build unpacked-only, never-published staging/test extensions under dist/staging/ "
            "scoped strictly to this pens zone suffix (e.g. pens.staging.example)."
        ),
    )
    args = parser.parse_args(argv)

    verify_manifest_versions()
    if args.zone_suffix is not None:
        suffix = validate_zone_suffix(args.zone_suffix)
        chrome_dir = build_staging_target("chrome", suffix)
        firefox_dir = build_staging_target("firefox", suffix)
        print(f"Built unpacked-only staging extensions for *.{suffix} (never publish):")
        print(f"  Chrome:  {chrome_dir}")
        print(f"  Firefox: {firefox_dir} (id: hogman-browser-staging@{suffix})")
        print("Load into a separate browser profile and explicitly register the ID:")
        print("  ~/hogman browser-setup --chrome-id <32-char-unpacked-id>")
        print(f"  ~/hogman browser-setup --firefox-id hogman-browser-staging@{suffix}")
        return

    DIST.mkdir(parents=True, exist_ok=True)
    zips = [build_target("chrome"), build_target("firefox")]
    lines = [f"{sha256_file(z)}  {z.name}\n" for z in zips]
    (DIST / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")
    for line in lines:
        print(line.strip())


if __name__ == "__main__":
    main()
