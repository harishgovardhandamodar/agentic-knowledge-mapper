"""Unlabelled mermaid fences must print as pictures, not source listings."""
import io
import os
import tempfile
import unittest
from unittest import mock

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-mmpng-"), "test.db"))

from app.mermaid_png import collect_sources, render_sources


FLOW = ("flowchart TD\n"
        "    A[User] --> B[Assistant]\n"
        "    B --> C[Output]")


def _fake_png(w=120, h=60):
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (w, h), (180, 30, 30)).save(buf, format="PNG")
    return buf.getvalue()


class TestCollectSources(unittest.TestCase):
    def test_picks_unlabelled_mermaid(self):
        md = f"before\n```mermaid\n{FLOW}\n```\nafter"
        self.assertEqual(collect_sources(md), [FLOW])

    def test_skips_vector_figures(self):
        md = ("```mermaid dataflow\nflowchart LR\n A-->B\n```\n"
              f"```mermaid\n{FLOW}\n```")
        self.assertEqual(collect_sources(md, skip_labels={"dataflow"}), [FLOW])

    def test_ignores_plain_code(self):
        md = "```python\nprint('hi')\n```"
        self.assertEqual(collect_sources(md), [])

    def test_dedupes_repeated_figures(self):
        md = (f"```mermaid\n{FLOW}\n```\ntext\n"
              f"```mermaid\n{FLOW}\n```")
        self.assertEqual(collect_sources(md), [FLOW])


class TestRenderSources(unittest.TestCase):
    def test_no_chromium_means_no_pictures(self):
        with mock.patch.dict(os.environ, {"AKM_CHROMIUM_BIN": "/nonexistent"}):
            self.assertEqual(render_sources([FLOW]), {})

    def test_disk_cache_avoids_the_browser(self):
        import tempfile
        from app import mermaid_png
        with tempfile.TemporaryDirectory() as tmp:
            key_src = FLOW
            with open(os.path.join(
                    tmp, mermaid_png._key(key_src) + ".png"), "wb") as fh:
                fh.write(_fake_png())
            with mock.patch.dict(os.environ, {"AKM_MERMAID_CACHE": tmp}):
                with mock.patch.object(
                        mermaid_png, "_launch",
                        side_effect=AssertionError("browser launched")):
                    got = render_sources([key_src, "flowchart TD\n X-->Y"])
        self.assertEqual(list(got), [key_src])
        self.assertEqual(got[key_src], _fake_png())


class TestPdfPictures(unittest.TestCase):
    MD = ("## Diagrams\n\n"
          f"```mermaid\n{FLOW}\n```\n")

    def test_rendered_figure_prints_as_picture(self):
        from app import security as sec
        from app import mermaid_png
        with mock.patch.object(mermaid_png, "render_sources",
                               return_value={FLOW: _fake_png()}):
            pdf = sec.build_pdf(self.MD, title="t")
        import pypdf
        pages = pypdf.PdfReader(io.BytesIO(pdf)).pages
        full = "\n".join(p.extract_text() for p in pages)
        self.assertIn("Figure 1", full)
        self.assertNotIn("mermaid source", full)
        # The caption names the figure type; the diagram body must not leak.
        self.assertNotIn("A[User]", full)
        self.assertTrue(any(len(p.images) > 0 for p in pages),
                        "no embedded image found")

    def test_unrendered_figure_keeps_source_fallback(self):
        from app import security as sec
        from app import mermaid_png
        with mock.patch.object(mermaid_png, "render_sources", return_value={}):
            pdf = sec.build_pdf(self.MD, title="t")
        import pypdf
        full = "\n".join(
            p.extract_text() for p in pypdf.PdfReader(io.BytesIO(pdf)).pages)
        self.assertIn("mermaid source", full)
        self.assertIn("flowchart TD", full)


if __name__ == "__main__":
    unittest.main()
