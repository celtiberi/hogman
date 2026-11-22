#!/usr/bin/env python3
"""Deterministic, reproducible packager for Hogman browser extensions.

Builds unpacked directories and reproducible .zip bundles for Chrome (MV3) and
Firefox (MV3) under browser-ext/dist/ along with SHA256SUMS.
"""

from __future__ import annotations

import hashlib
import pathlib
import shutil
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent
SRC = ROOT / "src"
DIST = ROOT / "dist"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def build_target(target: str) -> pathlib.Path:
    unpacked = DIST / target
    if unpacked.exists():
        shutil.rmtree(unpacked)
    unpacked.mkdir(parents=True)

    for src_dir in (SRC / "shared", SRC / target):
        for path in sorted(src_dir.rglob("*")):
            if path.is_dir():
                continue
            rel = path.relative_to(src_dir)
            dst = unpacked / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, dst)

    zip_path = DIST / f"hogman-ext-{target}.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(unpacked.rglob("*")):
            if path.is_dir():
                continue
            rel = path.relative_to(unpacked).as_posix()
            info = zipfile.ZipInfo(filename=rel, date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, path.read_bytes())
    return zip_path


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main() -> None:
    DIST.mkdir(parents=True, exist_ok=True)
    zips = [build_target("chrome"), build_target("firefox")]
    lines = [f"{sha256_file(z)}  {z.name}\n" for z in zips]
    (DIST / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")
    for line in lines:
        print(line.strip())


if __name__ == "__main__":
    main()
