"""Tests for the Fluid UI serving (app/main.py /fluid routes + classic toggle).

The Fluid UI is the parallel React GUI (fluid/ in the repo, built into
static/fluid/). These tests pin the serving contract, not the bundle:
routes registered, SPA fallback shape, and the classic page's toggle hook.
"""
import os
import tempfile

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-fluid-"), "test.db"))

import unittest  # noqa: E402

from app import main as main_mod  # noqa: E402


class TestFluidRoutes(unittest.TestCase):
    def test_fluid_routes_registered(self):
        paths = {getattr(r, "path", "") for r in main_mod.app.routes}
        self.assertIn("/fluid", paths)
        self.assertIn("/fluid/", paths)
        self.assertIn("/fluid/{path:path}", paths)

    def test_fluid_index_served_when_built(self):
        static_dir = os.path.join(os.path.dirname(
            os.path.dirname(main_mod.__file__)), "static")
        index = os.path.join(static_dir, "fluid", "index.html")
        if not os.path.isfile(index):
            self.skipTest("fluid bundle not built (npm run build in fluid/)")
        # Route handler resolves the same file it would serve.
        with open(index, encoding="utf-8") as fh:
            html = fh.read()
        # The export is a Next.js static build: assets live under /fluid/_next/
        # because basePath and assetPrefix are both /fluid. A bare /_next/
        # reference would 404 behind the FastAPI mount, so this is the check
        # that the build actually happened with the right prefix.
        self.assertIn("/fluid/_next/", html)
        self.assertNotIn('"/_next/', html)

    def test_every_route_has_its_own_exported_entry(self):
        # trailingSlash export: each route is a directory with an index.html,
        # which is what lets serve_fluid_assets answer a deep link directly
        # instead of bouncing it through the root shell.
        static_dir = os.path.join(os.path.dirname(
            os.path.dirname(main_mod.__file__)), "static")
        fluid_dir = os.path.join(static_dir, "fluid")
        if not os.path.isfile(os.path.join(fluid_dir, "index.html")):
            self.skipTest("fluid bundle not built (npm run build in fluid/)")
        for route in ("security", "claims", "privacy", "design"):
            with self.subTest(route=route):
                self.assertTrue(
                    os.path.isfile(
                        os.path.join(fluid_dir, route, "index.html")),
                    f"missing static/fluid/{route}/index.html")

    def test_assets_are_present_under_the_prefix(self):
        static_dir = os.path.join(os.path.dirname(
            os.path.dirname(main_mod.__file__)), "static")
        fluid_dir = os.path.join(static_dir, "fluid")
        if not os.path.isdir(os.path.join(fluid_dir, "_next")):
            self.skipTest("fluid bundle not built (npm run build in fluid/)")
        # serve_fluid_assets only serves a path when it is a real file; a
        # missing _next/ tree is the most common way a half-finished export
        # reaches an image.
        found = False
        for _root, _dirs, files in os.walk(os.path.join(fluid_dir, "_next")):
            if any(f.endswith((".js", ".css")) for f in files):
                found = True
                break
        self.assertTrue(found, "no JS/CSS under static/fluid/_next/")


class TestClassicToggle(unittest.TestCase):
    def test_classic_page_links_to_fluid(self):
        static_dir = os.path.join(os.path.dirname(
            os.path.dirname(main_mod.__file__)), "static")
        with open(os.path.join(static_dir, "index.html"),
                  encoding="utf-8") as fh:
            html = fh.read()
        # Toggle button + persisted-choice handoff, mirrored by the fluid app.
        self.assertIn("/fluid/", html)
        self.assertIn("akm-ui", html)


if __name__ == "__main__":
    unittest.main()
