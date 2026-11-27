"""Unit tests for browser-ext/build.py packaging hygiene."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
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

    def test_real_builds_include_all_local_module_imports(self) -> None:
        import_re = re.compile(r"""from\s+["']\./([^"']+\.js)["']""")
        script_re = re.compile(r"""<script[^>]+src=["']([^"']+\.js)["']""")
        with tempfile.TemporaryDirectory() as td:
            dist = pathlib.Path(td)
            for target in ("chrome", "firefox"):
                zip_path = build.build_target(target, dist_root=dist)
                with zipfile.ZipFile(zip_path) as zf:
                    names = set(zf.namelist())
                    self.assertIn("manifest.json", names)
                    for name in sorted(names):
                        if name.endswith(".js"):
                            body = zf.read(name).decode("utf-8")
                            for imp in import_re.findall(body):
                                self.assertIn(imp, names, f"{target} {name} imports missing ./{imp}")
                        elif name.endswith(".html"):
                            body = zf.read(name).decode("utf-8")
                            for src in script_re.findall(body):
                                self.assertIn(src, names, f"{target} {name} references missing {src}")

    def test_store_build_contains_only_production_domain(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            dist = pathlib.Path(td)
            for target in ("chrome", "firefox"):
                zip_path = build.build_target(target, dist_root=dist)
                with zipfile.ZipFile(zip_path) as zf:
                    manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
                    constants = zf.read("constants.js").decode("utf-8")
                    self.assertEqual(manifest["name"], "Hogman")
                    self.assertNotIn("staging", json.dumps(manifest).lower())
                    self.assertNotIn("<all_urls>", json.dumps(manifest))
                    self.assertIn('export const ZONE_SUFFIX = "pens.hogman.network";', constants)
                    self.assertNotIn("staging", constants.lower())
                    if target == "chrome":
                        self.assertNotIn("host_permissions", manifest)
                    else:
                        self.assertEqual(
                            manifest["host_permissions"],
                            ["*://*.pens.hogman.network/*", "*://pens.hogman.network/*"],
                        )
                        self.assertEqual(
                            manifest["browser_specific_settings"]["gecko"]["id"],
                            "hogman-browser@hogman.network",
                        )

    def test_staging_build_unpacked_only_and_scoped_to_zone_suffix(self) -> None:
        suffix = "pens.staging.example"
        src_constants_before = (build.SRC / "shared" / "constants.js").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as td:
            dist = pathlib.Path(td)
            chrome_dir = build.build_staging_target("chrome", suffix, dist_root=dist)
            firefox_dir = build.build_staging_target("firefox", suffix, dist_root=dist)

            # Staging builds are strictly unpacked-only: never generate .zip or SHA256SUMS.
            self.assertEqual(list(dist.rglob("*.zip")), [])
            self.assertEqual(list(dist.rglob("SHA256SUMS")), [])

            chrome_manifest = json.loads((chrome_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(chrome_manifest["name"], "Hogman (staging)")
            self.assertEqual(chrome_manifest["action"]["default_title"], "Hogman (staging)")
            self.assertNotIn("host_permissions", chrome_manifest)
            self.assertNotIn("key", chrome_manifest)
            self.assertNotIn("pens.hogman.network", json.dumps(chrome_manifest))

            ff_manifest = json.loads((firefox_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(ff_manifest["name"], "Hogman (staging)")
            self.assertEqual(ff_manifest["action"]["default_title"], "Hogman (staging)")
            self.assertEqual(ff_manifest["host_permissions"], [f"*://*.{suffix}/*", f"*://{suffix}/*"])
            self.assertEqual(
                ff_manifest["browser_specific_settings"]["gecko"]["id"],
                f"hogman-browser-staging@{suffix}",
            )
            self.assertNotIn("pens.hogman.network", json.dumps(ff_manifest))

            for d in (chrome_dir, firefox_dir):
                const_text = (d / "constants.js").read_text(encoding="utf-8")
                popup_text = (d / "popup.html").read_text(encoding="utf-8")
                self.assertIn(f'export const ZONE_SUFFIX = "{suffix}";', const_text)
                self.assertNotIn("pens.hogman.network", const_text)
                self.assertIn("<h1>Hogman (staging)</h1>", popup_text)
                self.assertIn(f"*.{suffix}", popup_text)
                self.assertNotIn("pens.hogman.network", popup_text)

            # Execute the staged pac.js in Node to prove routing and fail-closed scoping.
            script = f"""
import assert from "node:assert/strict";
import vm from "node:vm";
import {{ pathToFileURL }} from "node:url";

const pac = await import(pathToFileURL({json.dumps(str(chrome_dir / "pac.js"))}).href);
const snap = pac.sanitizeNativeSnapshot({{
  ok: true,
  pens: [
    {{ zone: "smoke1.{suffix}", port: 20001, up: true, hosted: false }},
    {{ zone: "prod.pens.hogman.network", port: 20002, up: true, hosted: true }},
  ],
}});
assert.deepEqual(snap.pens.map((p) => p.zone), ["smoke1.{suffix}"]);

const {{ routes }} = pac.computeEffectiveRoutes(snap.pens, {{
  enabledZones: {{ "smoke1.{suffix}": true }},
}});
const scriptSrc = pac.buildPACScript(routes);
const ctx = {{
  dnsDomainIs: (host, domain) => host.endsWith(domain),
}};
vm.runInNewContext(scriptSrc, ctx);
assert.equal(ctx.FindProxyForURL("https://home.smoke1.{suffix}/", "home.smoke1.{suffix}"), "PROXY 127.0.0.1:20001");
assert.equal(ctx.FindProxyForURL("https://other.{suffix}/", "other.{suffix}"), "PROXY 127.0.0.1:1");
assert.equal(ctx.FindProxyForURL("https://{suffix}/", "{suffix}"), "PROXY 127.0.0.1:1");
assert.equal(ctx.FindProxyForURL("https://home.prod.pens.hogman.network/", "home.prod.pens.hogman.network"), "DIRECT");
assert.equal(ctx.FindProxyForURL("https://example.com/", "example.com"), "DIRECT");

assert.deepEqual(pac.resolveFirefoxProxy("home.smoke1.{suffix}", routes), {{ type: "http", host: "127.0.0.1", port: 20001 }});
assert.deepEqual(pac.resolveFirefoxProxy("other.{suffix}", routes), pac.FAIL_CLOSED_FIREFOX);
assert.equal(pac.resolveFirefoxProxy("home.prod.pens.hogman.network", routes), undefined);
"""
            res = subprocess.run(["node", "--input-type=module", "-e", script], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"node check failed:\nstdout={res.stdout}\nstderr={res.stderr}")

        # Source tree must remain untouched.
        self.assertEqual((build.SRC / "shared" / "constants.js").read_text(encoding="utf-8"), src_constants_before)

    def test_staging_build_rejects_invalid_zone_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            dist = pathlib.Path(td)
            for bad in (
                "",
                "   ",
                "pens.hogman.network",
                "PENS.HOGMAN.NETWORK",
                "singlelabel",
                "*.pens.staging.example",
                "https://pens.staging.example",
                "pens.staging.example/path",
                ".pens.staging.example",
                "pens.staging.example.",
                'evil";alert(1);//.example',
            ):
                with self.assertRaises(ValueError, msg=f"expected rejection for {bad!r}"):
                    build.build_staging_target("chrome", bad, dist_root=dist)


if __name__ == "__main__":
    unittest.main()
