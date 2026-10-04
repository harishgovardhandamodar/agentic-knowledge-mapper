"""The global knowledge graph's search/filter/detail helpers, headlessly.

The finder and the hover/click detail panel are scoring + template-string code
behind a browser. This runs the real functions out of ``static/index.html``
against a DOM shim in Node and asserts ranking, highlight, filter-to-matches,
and a junk-free detail panel. Skipped when Node is absent, like the other
frontend smoke suites.
"""
import os
import shutil
import subprocess
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or "sqlite://"

HERE = os.path.dirname(os.path.abspath(__file__))
SMOKE = os.path.join(HERE, "js", "graph_smoke.js")


class GraphSmokeCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")

    def test_graph_finder_and_detail_pass(self):
        if not self.node:
            self.skipTest("node is not on PATH; the graph helpers are unchecked")
        r = subprocess.run([self.node, SMOKE], capture_output=True,
                           text=True, timeout=120)
        self.assertEqual(
            r.returncode, 0,
            f"graph smoke did not pass:\n{r.stdout}\n{r.stderr}")
        self.assertIn("PASS", r.stdout)


if __name__ == "__main__":
    unittest.main()