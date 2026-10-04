"""The collapsible-section helpers and review-queue grouping, checked headlessly.

The folds are template strings behind a browser: a typo in ``foldSection`` or a
forgotten open/closed default is invisible to the Python suite and fatal only
when a reader clicks. This runs the *real* functions extracted out of
``static/index.html`` against a DOM shim in Node and asserts the fold markup,
state persistence, the review-state partition, and the collection folds.

Skipped, not failed, when Node is absent, like the leadership render suite.
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
SMOKE = os.path.join(HERE, "js", "fold_smoke.js")


class FoldSmokeCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")

    def test_fold_helpers_and_grouping_pass(self):
        if not self.node:
            self.skipTest("node is not on PATH; the fold helpers are unchecked")
        r = subprocess.run([self.node, SMOKE], capture_output=True,
                           text=True, timeout=120)
        self.assertEqual(
            r.returncode, 0,
            f"fold smoke did not pass:\n{r.stdout}\n{r.stderr}")
        self.assertIn("PASS", r.stdout)

    def test_review_groups_are_what_the_queue_promises(self):
        # The partition rule (drift wins; pending/accepted/rejected otherwise)
        # is also asserted in Node, but the static contract that the page's
        # Review toolbar still names the same states is cheap to pin here.
        html = open(os.path.join(HERE, "..", "static", "index.html")).read()
        for state in ("pending", "accepted", "rejected"):
            self.assertIn(f'data-rev="{state}"', html)
        self.assertIn("foldSetAll('#artList'", html)


if __name__ == "__main__":
    unittest.main()