#!/usr/bin/env python3
"""Deterministic, reproducible packager for Hogman browser extensions.

Builds unpacked directories and reproducible .zip bundles for Chrome (MV3) and
Firefox (MV3) under browser-ext/dist/ along with SHA256SUMS.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent
SRC = ROOT / "src"
DIST = ROOT / "dist"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
IGNORED_NAMES = frozenset({"Thumbs.db", "__pycache__"})
IGNORED_SUFFIXES = (".swp", ".swo", ".tmp", ".pyc", "~")


def should_include(rel: pathlib.Path) -> bool:
    for part in rel.parts:
        if part.startswith(".") or part in IGNORED_NAMES:
            return False
    return not any(rel.name.endswith(sfx) for sfx in IGNORED_SUFFIXES)


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


def build_target(target: str, src_root: pathlib.Path = SRC, dist_root: pathlib.Path = DIST) -> pathlib.Path:
    unpacked = dist_root / target
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


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main() -> None:
    verify_manifest_versions()
    DIST.mkdir(parents=True, exist_ok=True)
    zips = [build_target("chrome"), build_target("firefox")]
    lines = [f"{sha256_file(z)}  {z.name}\n" for z in zips]
    (DIST / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")
    for line in lines:
        print(line.strip())


if __name__ == "__main__":
    main()
