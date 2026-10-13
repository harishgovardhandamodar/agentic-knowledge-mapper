"""Mermaid gate: only parser-safe sources reach the frontend.

A prose paragraph or a special character stored as a diagram renders
as a syntax-error banner instead of a figure. The gate sanitizes what
keeps meaning (bare &) and drops the rest, so a failed figure degrades
to caption text, never to an error. Pin header required suite-wide.
"""
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-mmvalid-"),
                                "test.db"))

from app.explainer import _validate_mermaid  # noqa: E402

SEQ = ("sequenceDiagram\n"
       "    participant A as Agent\n"
       "    participant H as HF\n"
       "    A->>H: exploit systems\n"
       "    Note over H: no customer impact\n")

FLOW = ("flowchart TD\n"
        '    A["agents"] --> B["proof"]\n'
        "    B --> C\n")

TIMELINE = ("timeline\n"
            "    title Chain of Events\n"
            "    section Pre\n"
            "        2026-03-04 : first errors\n"
            "    section Post\n"
            "        Oct 7 : panel scrutinizes; fight intensifies\n")


class GateCase(unittest.TestCase):
    def test_valid_kinds_pass(self):
        for src in (SEQ, FLOW, TIMELINE):
            out = _validate_mermaid(src)
            self.assertIsNotNone(out, src.splitlines()[0])
            self.assertIn(src.splitlines()[0], out)

    def test_bare_ampersand_becomes_words(self):
        src = ("timeline\n    title T\n    section S\n"
               "    2026-01-01 : Buckmaster & Alpoege begin work\n")
        out = _validate_mermaid(src)
        self.assertIsNotNone(out)
        self.assertIn(" and ", out)
        self.assertNotIn("&", out)

    def test_timeline_semicolon_becomes_comma(self):
        out = _validate_mermaid(TIMELINE)
        self.assertIsNotNone(out)
        for line in out.splitlines():
            if ":" in line and not line.strip().startswith(
                    ("timeline", "title", "section")):
                self.assertNotIn(";", line)

    def test_prose_is_not_a_diagram(self):
        self.assertIsNone(_validate_mermaid(
            "From a leak allegation through the breakthrough claim, the "
            "controversy unfolded in three phases."))
        self.assertIsNone(_validate_mermaid(""))

    def test_backtick_and_script_dropped(self):
        self.assertIsNone(_validate_mermaid("flowchart TD\n A`x --> B"))
        self.assertIsNone(_validate_mermaid(
            "flowchart TD\n A-->B\n<script>alert(1)</script>"))

    def test_unbalanced_flowchart_dropped(self):
        self.assertIsNone(
            _validate_mermaid('flowchart TD\n    A["open --> B'))

    def test_colonless_timeline_dropped(self):
        self.assertIsNone(
            _validate_mermaid("timeline\n    title T\n    just prose here"))

    def test_trailing_comma_no_longer_kills_flowcharts(self):
        src = ("flowchart TD\n"
               '    A["x"] --> B["y"],\n')
        out = _validate_mermaid(src)
        self.assertIsNotNone(out)
        self.assertFalse(out.rstrip().endswith(","))


if __name__ == "__main__":
    unittest.main()
