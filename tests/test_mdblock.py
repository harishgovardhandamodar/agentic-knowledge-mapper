"""Explainer markdown fences render as live diagrams, checked headlessly.

mdBlock() must turn ```mermaid fences into .mermaid nodes (source in
data-src) and the loader must prefer the vendored library with a CDN
failover -- otherwise explainer diagrams sit as raw source text.
Drives the real functions out of static/index.html in Node.

Skipped, not failed, when Node is absent.
"""
import os
import shutil
import subprocess
import unittest

# Suite isolation invariant: pin the database in every test module.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or "sqlite://"

HERE = os.path.dirname(os.path.abspath(__file__))
SMOKE = os.path.join(HERE, "js", "mdblock_smoke.js")
VENDOR = os.path.join(HERE, "..", "static", "vendor", "mermaid.min.js")


class MdblockCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")

    def test_fences_become_diagrams(self):
        if not self.node:
            self.skipTest("node is not on PATH; mdBlock is unchecked")
        r = subprocess.run([self.node, SMOKE], capture_output=True,
                           text=True, timeout=120)
        self.assertEqual(
            r.returncode, 0,
            f"mdblock smoke did not pass:\n{r.stdout}\n{r.stderr}")
        self.assertIn("PASS", r.stdout)

    def test_mermaid_library_is_vendored(self):
        self.assertTrue(os.path.isfile(VENDOR),
                        "static/vendor/mermaid.min.js missing: diagrams "
                        "depend on the CDN alone")
        self.assertGreater(os.path.getsize(VENDOR), 1000000)


if __name__ == "__main__":
    unittest.main()
