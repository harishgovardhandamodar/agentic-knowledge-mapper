"""The council record in the artifacts view, checked headlessly.

The record is template strings behind a browser: a misplaced call or a
dropped section is invisible to the Python suite and fatal only when a
reader opens the tab. This runs the *real* functions extracted out of
``static/index.html`` in Node and asserts the call placement (inside
``loadArtifacts``, never orphaned after its closing brace) plus the four
rendered sections.

Skipped, not failed, when Node is absent, like the other render suites.
"""
import os
import shutil
import subprocess
import unittest

# The suite's isolation invariant: no test module may inherit a live database.
# This file only drives Node and never imports the app, but the pin is
# mandatory for every test_*.py so the invariant stays mechanical.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or "sqlite://"

HERE = os.path.dirname(os.path.abspath(__file__))
SMOKE = os.path.join(HERE, "js", "council_record_smoke.js")


class CouncilRecordRenderCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")

    def test_council_record_renders(self):
        if not self.node:
            self.skipTest("node is not on PATH; the council record is unchecked")
        r = subprocess.run([self.node, SMOKE], capture_output=True,
                           text=True, timeout=120)
        self.assertEqual(
            r.returncode, 0,
            f"council-record smoke did not pass:\n{r.stdout}\n{r.stderr}")
        self.assertIn("PASS", r.stdout)

    def test_record_host_sits_above_the_artifact_list(self):
        # Placement is the contract with the reader: the deliberation comes
        # before the collection, not after it.
        html = open(os.path.join(HERE, "..", "static", "index.html")).read()
        self.assertLess(html.index('id="councilRecord"'),
                        html.index('id="artList"'))


if __name__ == "__main__":
    unittest.main()
