"""Tests for explainer document attachments (PDFs, decks, reports).

Web research used to drop every non-HTML hit as "unreadable", so PDFs and
presentations never reached the answer. Now documents are fetched (text
extracted where a parser exists), offered as candidates, and attached only
after URL validation. Pure helpers only -- no DB, no network.
"""
import io
import os
import tempfile
import unittest
import zipfile

os.environ.setdefault("AKM_DATABASE_URL", "sqlite:///" + os.path.join(
    tempfile.mkdtemp(prefix="akm-doc-test-"), "test.db"))

from app.explainer import (  # noqa: E402
    _doc_kind, _extract_pptx_text, _fetch_document, _pretty_doc_title,
    _valid_artifacts, _valid_documents,
)


def _pptx_bytes(*slides):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i, texts in enumerate(slides, 1):
            runs = "".join(f"<a:r><a:t>{t}</a:t></a:r>" for t in texts)
            z.writestr(f"ppt/slides/slide{i}.xml",
                       f'<p:sld xmlns:p="x" xmlns:a="y"><p:txBody>{runs}</p:txBody></p:sld>')
        z.writestr("[Content_Types].xml", "<Types/>")
    return buf.getvalue()


class TestDocKind(unittest.TestCase):
    def test_extension_detection(self):
        self.assertEqual(_doc_kind("https://x.com/r.pdf"), "pdf")
        self.assertEqual(_doc_kind("https://x.com/d.PPTX"), "slides")
        self.assertEqual(_doc_kind("https://x.com/d.ppt"), "slides")
        self.assertEqual(_doc_kind("https://x.com/d.docx?a=1"), "doc")
        self.assertEqual(_doc_kind("https://x.com/page"), "")

    def test_mime_fallback(self):
        self.assertEqual(_doc_kind("https://x.com/download?id=9",
                                   "application/pdf; charset=binary"), "pdf")
        self.assertEqual(_doc_kind("https://x.com/page", "text/html"), "")

    def test_titles(self):
        self.assertEqual(_pretty_doc_title("https://x.com/a.pdf", "Real Title"),
                         "Real Title")
        self.assertEqual(_pretty_doc_title("https://x.com/my%20report-final.pdf"),
                         "my report final")
        self.assertEqual(_pretty_doc_title("https://x.com/"), "https://x.com/")


class TestPptxExtraction(unittest.TestCase):
    def test_slide_text_joined(self):
        text, n = _extract_pptx_text(_pptx_bytes(["Hello", "world"], ["Slide two"]))
        self.assertEqual(n, 2)
        self.assertIn("Hello", text)
        self.assertIn("Slide two", text)

    def test_garbage_is_metadata_only(self):
        text, n = _extract_pptx_text(b"not a zip")
        self.assertEqual((text, n), ("", 0))


class TestFetchDocument(unittest.TestCase):
    def test_pdf_text_via_reader(self):
        import pypdf

        class Page:
            def __init__(self, t):
                self._t = t

            def extract_text(self):
                return self._t

        class Reader:
            def __init__(self, buf):
                self.pages = [Page("page one "), Page("page two")]

        orig = pypdf.PdfReader
        pypdf.PdfReader = Reader
        try:
            out = _fetch_document("https://x.com/r.pdf", "pdf", b"%PDF fake",
                                  "Risk Report")
        finally:
            pypdf.PdfReader = orig
        self.assertEqual(out["title"], "Risk Report")
        self.assertIn("page one", out["text"])
        self.assertEqual(out["doc_pages"], 2)
        self.assertEqual(out["images"], [])

    def test_broken_pdf_falls_back_to_link(self):
        out = _fetch_document("https://x.com/r.pdf", "pdf", b"garbage")
        self.assertEqual(out["title"], "r")
        self.assertEqual(out["text"], "")
        self.assertEqual(out["url"], "https://x.com/r.pdf")

    def test_oversized_file_not_parsed(self):
        big = b"%PDF-" + b"x" * (16 * 1024 * 1024)
        out = _fetch_document("https://x.com/big.pdf", "pdf", big)
        self.assertEqual(out["text"], "")

    def test_legacy_ppt_is_link_only(self):
        out = _fetch_document("https://x.com/d.ppt", "slides", b"binary")
        self.assertEqual(out["text"], "")
        self.assertTrue(out["url"].endswith(".ppt"))


class TestAttachmentValidation(unittest.TestCase):
    def test_documents_validated_against_candidates(self):
        cands = [{"url": "https://x.com/a.pdf", "title": "A", "kind": "pdf",
                  "pages": 4}]
        out = _valid_documents(
            [{"title": "t", "url": "https://x.com/a.pdf"},
             {"title": "evil", "url": "https://evil.example/x.pdf"},
             "junk", {"title": "no url"}],
            cands)
        self.assertEqual(out, [{"title": "t", "url": "https://x.com/a.pdf",
                                "kind": "pdf", "pages": 4}])

    def test_artifacts_validated_by_id(self):
        cands = [{"id": 7, "title": "T", "url": "", "kind": "news"}]
        out = _valid_artifacts([{"id": 7}, {"id": 999}, {"noid": 1}], cands)
        self.assertEqual(out, [{"id": 7, "title": "T", "url": "",
                                "kind": "news"}])


if __name__ == "__main__":
    unittest.main()
