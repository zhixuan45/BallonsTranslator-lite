"""Regression tests for the security-supported Pillow baseline (CVE-2026-112403)."""

import io
import sys
import tomllib
import unittest
from pathlib import Path
from importlib.metadata import version

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]


class PillowSecurityBaselineTests(unittest.TestCase):
    def test_secure_version_is_installed(self):
        major = int(version("Pillow").split(".", 1)[0])
        self.assertGreaterEqual(major, 13)
        self.assertLess(major, 14)
        self.assertGreaterEqual(sys.version_info, (3, 11))

    def test_manifests_agree(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(project["project"]["requires-python"], ">=3.11")
        spec = "pillow>=13.0.0,<14"
        self.assertIn(spec, [item.lower() for item in project["project"]["dependencies"]])
        for path in ("requirements.txt", "config/requirements_core.txt"):
            self.assertIn(spec, (ROOT / path).read_text(encoding="utf-8").lower().splitlines())

    def test_jpeg_thumbnail_and_png_roundtrip(self):
        source = Image.new("RGB", (32, 24), (120, 30, 80))
        jpeg = io.BytesIO()
        source.save(jpeg, format="JPEG")
        jpeg.seek(0)
        with Image.open(jpeg) as decoded:
            decoded.thumbnail((16, 16))
            self.assertLessEqual(decoded.width, 16)
            self.assertLessEqual(decoded.height, 16)
            png = io.BytesIO()
            decoded.save(png, format="PNG")
        png.seek(0)
        with Image.open(png) as result:
            self.assertEqual(result.format, "PNG")
            result.load()


if __name__ == "__main__":
    unittest.main()
