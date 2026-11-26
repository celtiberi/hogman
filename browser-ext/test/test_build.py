"""Unit tests for browser-ext/build.py packaging hygiene."""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import build  # noqa: E402


class TestBuildExtension(unittest.TestCase):
    def test_excludes_junk_and_validates_manifest_versions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            src = root / "src"
            dist = root / "dist"
            (src / "shared" / ".hidden").mkdir(parents=True)
            (src / "chrome").mkdir(parents=True)
            (src / "firefox").mkdir(parents=True)

            (src / "shared" / "pac.js").write_text("export const x = 1;\n", encoding="utf-8")
            (src / "shared" / ".DS_Store").write_bytes(b"junk")
            (src / "shared" / "._pac.js").write_bytes(b"appledouble")
            (src / "shared" / "pac.js.swp").write_bytes(b"swap")
            (src / "shared" / "Thumbs.db").write_bytes(b"thumbs")
            (src / "shared" / ".hidden" / "secret.txt").write_text("nope", encoding="utf-8")

            (src / "chrome" / "manifest.json").write_text(json.dumps({"version": "0.1.1"}), encoding="utf-8")
            (src / "firefox" / "manifest.json").write_text(json.dumps({"version": "0.1.1"}), encoding="utf-8")

            self.assertEqual(build.verify_manifest_versions(src), "0.1.1")

            (src / "shared" / "icons").mkdir(parents=True)
            (src / "shared" / "icons" / "b.png").write_bytes(b"pngb")
            (src / "shared" / "icons" / "a.png").write_bytes(b"pnga")

            zip_path = build.build_target("chrome", src_root=src, dist_root=dist)
            hash1 = build.sha256_file(zip_path)
            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
            self.assertEqual(names, ["icons/a.png", "icons/b.png", "manifest.json", "pac.js"])

            # Rebuilding must produce byte-identical output.
            zip_path2 = build.build_target("chrome", src_root=src, dist_root=dist)
            self.assertEqual(build.sha256_file(zip_path2), hash1)

            # Symlinks inside src must be rejected.
            (src / "shared" / "link.js").symlink_to(src / "shared" / "pac.js")
            with self.assertRaises(ValueError):
                build.build_target("chrome", src_root=src, dist_root=dist)
            (src / "shared" / "link.js").unlink()

            # Mismatched versions must fail loudly.
            (src / "firefox" / "manifest.json").write_text(json.dumps({"version": "0.1.2"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                build.verify_manifest_versions(src)

    def test_repo_manifests_match(self) -> None:
        ver = build.verify_manifest_versions()
        self.assertRegex(ver, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
