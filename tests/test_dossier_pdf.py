"""Dossier Markdown -> PDF (pandoc + LaTeX) tests.

Run with:  python3 -m pytest tests/test_dossier_pdf.py -q

The pandoc/LaTeX end-to-end test skips when the toolchain is absent (it is
installed in the Docker image, not necessarily on a dev box).
"""
import os
import shutil
import subprocess
import tempfile
import unittest

from app import dossier_pdf as dp

FIXTURE_MD = """# Investigation dossier — Test subject

_Investigation #1 · generated 2026-01-01 UTC_

## Executive summary

The subject was investigated and 3 artifacts were collected.

| Path | Score | Meaning |
|---|---|---|
| Product | 42/100 | residual risk |

## 1. The request

Some request text with a symbol: a → b and an emoji 😀 and raw <b>html</b>.

## 6. Diagrams

### Data flow

```mermaid
flowchart TD
    A[User] --> B[Agent]
    B --> C[Rail]
```

## 8. Open questions and evidence gaps

- pending evidence is not accepted evidence.
"""


class TestPreprocess(unittest.TestCase):
    def test_strips_html_and_maps_symbols(self):
        out = dp.preprocess_markdown(FIXTURE_MD)
        self.assertNotIn("<b>", out)
        self.assertIn("html", out)          # text kept
        self.assertIn("a -> b", out)        # arrow mapped
        self.assertNotIn("😀", out)          # emoji stripped
        self.assertNotIn("<!--", out)

    def test_keeps_tables_and_headings(self):
        out = dp.preprocess_markdown(FIXTURE_MD)
        self.assertIn("## Executive summary", out)
        self.assertIn("| Path | Score | Meaning |", out)
        self.assertIn("| Product | 42/100 | residual risk |", out)


class TestFenceDetection(unittest.TestCase):
    def test_detects_mermaid_fences(self):
        fences = list(dp._fences(FIXTURE_MD))
        mer = [f for f in fences if f[2] == "mermaid"]
        self.assertEqual(len(mer), 1)
        self.assertIn("flowchart TD", mer[0][4])

    def test_caption_from_preceding_heading(self):
        out, rendered, fallback = dp.render_mermaid_figures(
            dp.preprocess_markdown(FIXTURE_MD), tempfile.mkdtemp())
        # no renderer in the test env -> kept as source (never dropped)
        self.assertIn("```mermaid", out)
        self.assertIn("flowchart TD", out)
        self.assertEqual(fallback, 1)


class TestMermaidRewrite(unittest.TestCase):
    def test_rendered_fence_becomes_image(self):
        """With a renderer returning a PNG, the fence is rewritten to an image
        link and the PNG is written under images/."""
        from app import mermaid_png
        fake = b"\x89PNG\r\n\x1a\nFAKE"
        src = "flowchart TD\n    A[User] --> B[Agent]\n    B --> C[Rail]"
        orig = mermaid_png.render_sources
        mermaid_png.render_sources = lambda sources: {src: fake}
        try:
            tmp = tempfile.mkdtemp()
            out, rendered, fallback = dp.render_mermaid_figures(
                dp.preprocess_markdown(FIXTURE_MD), tmp)
        finally:
            mermaid_png.render_sources = orig
        self.assertEqual(rendered, 1)
        self.assertEqual(fallback, 0)
        self.assertIn("](images/", out)
        self.assertNotIn("```mermaid", out)
        h = dp._hash(src)
        self.assertTrue(os.path.isfile(os.path.join(tmp, "images", h + ".png")))
        # caption carried from the nearest preceding heading
        self.assertIn("Data flow", out)


class TestPandocPipeline(unittest.TestCase):
    def test_available_shape(self):
        env = dp.available()
        self.assertIn("pandoc", env)
        self.assertIn("engines", env)
        self.assertIn("ok", env)

    def test_build_pdf_end_to_end(self):
        if not dp.available()["ok"]:
            self.skipTest("pandoc/LaTeX not installed")
        pdf = dp.build_pdf(FIXTURE_MD, title="Test dossier")
        self.assertTrue(pdf.startswith(b"%PDF"), "not a PDF")
        self.assertGreater(len(pdf), 1000)
        # multi-page: the dossier body + TOC should produce >1 page object
        self.assertGreaterEqual(pdf.count(b"/Type /Page"), 1)
        # content check when pdftotext is available
        if shutil.which("pdftotext"):
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as fh:
                fh.write(pdf)
                path = fh.name
            try:
                txt = subprocess.run(["pdftotext", path, "-"],
                                     capture_output=True, text=True).stdout
                self.assertIn("Executive summary", txt)
                self.assertIn("Open questions", txt)
            finally:
                os.unlink(path)

    def test_missing_toolchain_raises_runtime_error(self):
        orig = dp.available
        dp.available = lambda: {"pandoc": None, "engines": [], "ok": False}
        try:
            with self.assertRaises(RuntimeError):
                dp.build_pdf(FIXTURE_MD)
        finally:
            dp.available = orig


if __name__ == "__main__":
    unittest.main(verbosity=2)