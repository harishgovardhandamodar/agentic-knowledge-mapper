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
        self.assertIn('id="root"', html)
        self.assertIn("/fluid/", html)


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
