"""Tests for the Design & Architecture tab backend (app/design_docs.py).

The tab lists the Mermaid design documents and serves one at a time. Three
things have to hold for it to be worth having:

* the list is complete and honest about what is on disk, with a diagram count
  that matches the file rather than a guess;
* a document cannot be reached by anything other than its id -- a traversal
  attempt is a 404, exactly like an unknown id, because from the caller's side
  they are the same request;
* a missing design directory is an explained state, not a 500, because these
  files are documentation and an image may legitimately not ship them.
"""
import os
import tempfile
import unittest
from unittest import mock

# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-design-docs-"), "test.db"))

from app import database  # noqa: E402
from app import design_docs as dd  # noqa: E402

database.init_db()

SAMPLE = """# Sample

Intro paragraph.

## A section

| a | b |
|---|---|
| 1 | 2 |

```mermaid
flowchart TB
    A["one"] --> B["two"]
```

```json
{"not": "a diagram"}
```

```mermaid
sequenceDiagram
    A->>B: hi
```
"""


class TestList(unittest.TestCase):
    def test_index_is_grouped_and_in_reading_order(self):
        out = dd.list_docs()
        self.assertTrue(out["available"])
        self.assertEqual(out["count"], len(out["docs"]))
        self.assertEqual(out["docs"][0]["id"], "readme")
        # Reading order is the index's order, and the groups appear in the order
        # the set is meant to be read: context first, assurance last.
        self.assertEqual(out["groups"][0], "Start here")
        self.assertEqual(out["groups"][-1], "Privacy & assurance")
        ids = [d["id"] for d in out["docs"]]
        for expected in ("system-context", "uml", "data-model", "interaction",
                         "activity", "state", "ui-interaction", "privacy", "controls"):
            self.assertIn(expected, ids)

    def test_every_entry_has_the_fields_the_tab_renders(self):
        for d in dd.list_docs()["docs"]:
            for field in ("id", "title", "group", "kind", "answers", "file",
                          "diagrams", "kinds", "bytes", "mtime", "available"):
                self.assertIn(field, d)
            self.assertTrue(d["available"], d["file"])
            self.assertGreater(d["bytes"], 0)

    def test_diagram_count_and_kinds_are_read_not_guessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "sample.md"), "w", encoding="utf-8") as fh:
                fh.write(SAMPLE)
            with mock.patch.object(dd, "_DOCS", [{"id": "sample", "file": "sample.md",
                                                  "title": "Sample", "group": "G",
                                                  "kind": "k", "answers": "a"}]), \
                 mock.patch.object(dd, "DESIGN_DIR", tmp):
                docs = dd.list_docs()["docs"]
        self.assertEqual(docs[0]["diagrams"], 2)          # the json fence is not a diagram
        self.assertEqual(docs[0]["kinds"], ["flowchart", "sequenceDiagram"])

    def test_the_real_design_set_has_no_dangling_entry(self):
        # A doc added to the index but not to design/ would render as a dead
        # row, so the count and the file have to agree.
        for d in dd.list_docs()["docs"]:
            self.assertTrue(os.path.isfile(os.path.join(dd.design_dir(), d["file"])), d["file"])


class TestMissingDirectory(unittest.TestCase):
    def test_missing_directory_is_explained_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            gone = os.path.join(tmp, "not-here")
            with mock.patch.object(dd, "DESIGN_DIR", gone):
                out = dd.list_docs()
        self.assertFalse(out["available"])
        self.assertEqual(out["count"], len(out["docs"]))  # shape is kept
        self.assertTrue(all(d["available"] is False for d in out["docs"]))
        self.assertIn("AKM_DESIGN_DIR", out["reason"])

    def test_missing_directory_makes_every_fetch_404(self):
        with tempfile.TemporaryDirectory() as tmp:
            gone = os.path.join(tmp, "not-here")
            with mock.patch.object(dd, "DESIGN_DIR", gone):
                with self.assertRaises(FileNotFoundError):
                    dd.get_doc("state")


class TestGetDoc(unittest.TestCase):
    def test_returns_markdown_with_metadata(self):
        d = dd.get_doc("state")
        self.assertEqual(d["id"], "state")
        self.assertTrue(d["markdown"].startswith("#"))
        self.assertEqual(d["lines"], d["markdown"].count("\n") + 1)
        self.assertGreaterEqual(d["diagrams"], 1)
        self.assertFalse(d["truncated"])
        self.assertIn("stateDiagram-v2", d["kinds"])

    def test_unknown_id_is_rejected(self):
        with self.assertRaises(dd.UnknownDoc):
            dd.get_doc("nope")

    def test_traversal_attempts_are_rejected_like_unknown_ids(self):
        # The id is looked up in a constant index, so these never become paths.
        for hostile in ("../secrets", "..%2Fsecrets", "/etc/passwd",
                        "state.md", "./state", "state/../state"):
            with self.assertRaises(dd.UnknownDoc, msg=hostile):
                dd.get_doc(hostile)

    def test_complete_file_without_trailing_newline_is_not_truncated(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "plain.md"), "w", encoding="utf-8") as fh:
                fh.write("# Title\n\nNo final newline.")
            entry = [{"id": "plain", "file": "plain.md", "title": "Plain",
                      "group": "G", "kind": "k", "answers": "a"}]
            with mock.patch.object(dd, "_DOCS", entry), \
                 mock.patch.object(dd, "DESIGN_DIR", tmp):
                d = dd.get_doc("plain")
        self.assertFalse(d["truncated"])
        self.assertTrue(d["markdown"].endswith("No final newline."))

    def test_oversized_document_is_truncated_and_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "big.md"), "w", encoding="utf-8") as fh:
                fh.write("x" * (dd.MAX_BYTES + 500))
            entry = [{"id": "big", "file": "big.md", "title": "Big",
                      "group": "G", "kind": "k", "answers": "a"}]
            with mock.patch.object(dd, "_DOCS", entry), \
                 mock.patch.object(dd, "DESIGN_DIR", tmp), \
                 mock.patch.object(dd, "MAX_BYTES", 1000):
                d = dd.get_doc("big")
        self.assertEqual(len(d["markdown"]), 1000)
        self.assertTrue(d["truncated"])


class TestRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from app import main as main_mod
        cls.client = TestClient(main_mod.app)

    def test_index_route_lists_the_set(self):
        r = self.client.get("/api/design/docs")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["available"])
        self.assertTrue(any(d["id"] == "uml" for d in body["docs"]))

    def test_doc_route_serves_markdown(self):
        r = self.client.get("/api/design/docs/privacy")
        self.assertEqual(r.status_code, 200)
        self.assertIn("```mermaid", r.json()["markdown"])

    def test_unknown_and_hostile_ids_are_both_404(self):
        for hostile in ("nope", "../main", "..%2Fmain"):
            self.assertEqual(self.client.get(f"/api/design/docs/{hostile}").status_code, 404)


if __name__ == "__main__":
    unittest.main()
