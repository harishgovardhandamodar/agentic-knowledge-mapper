"""CLI mermaid: fence extraction and ASCII rendering.

Pure functions, no app import -- but the suite-wide isolation rule still
requires the pin header (see tests/test_db_isolation.py).
"""
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-cli-mm-"),
                                "test.db"))

from cli.mermaid import (  # noqa: E402
    _parse_flowchart,
    diagram_kind,
    extract_fences,
    render_ascii,
    save_mmd,
)

FLOW = """graph TD
    A[Paste secret] --> B{Classifier}
    B -->|clean| C[Allow]
    B -->|dirty| D[Block]
"""

CHAIN = """flowchart LR
    A[a] --> B[b] --> C[c]
"""

SEQ = """sequenceDiagram
    participant U as User
    participant G as Gateway
    U->>G: chat request
    G-->>U: tokens
    Note over G: slow model
"""


class FenceCase(unittest.TestCase):
    def test_extracts_key_and_source(self):
        md = "text\n```mermaid\ngraph TD\n A-->B\n```\ntail"
        fences = extract_fences(md)
        self.assertEqual(len(fences), 1)
        self.assertIn("A-->B", fences[0][1])

    def test_no_fences_is_empty(self):
        self.assertEqual(extract_fences("no diagrams here"), [])

    def test_kind_dispatch(self):
        self.assertEqual(diagram_kind(FLOW), "flowchart")
        self.assertEqual(diagram_kind(SEQ), "sequence")
        self.assertEqual(diagram_kind("pie title x\n A: 1"), "other")
        self.assertIsNone(render_ascii("pie title x\n A: 1"))


class FlowchartCase(unittest.TestCase):
    def test_nodes_and_labeled_edges_parsed(self):
        labels, edges = _parse_flowchart(FLOW)
        self.assertEqual(labels["A"], "Paste secret")
        self.assertEqual(labels["B"], "Classifier")
        pairs = {(a, b) for a, b, _ in edges}
        self.assertIn(("A", "B"), pairs)
        self.assertIn(("B", "C"), pairs)
        self.assertIn(("B", "D"), pairs)
        lbl = [lbl for a, b, lbl in edges if (a, b) == ("B", "C")]
        self.assertEqual(lbl, ["clean"])

    def test_chains_unroll_pairwise(self):
        _, edges = _parse_flowchart(CHAIN)
        pairs = [(a, b) for a, b, _ in edges]
        self.assertIn(("A", "B"), pairs)
        self.assertIn(("B", "C"), pairs)

    def test_subgraph_and_style_lines_skipped(self):
        src = ("graph TD\nsubgraph sg\nA[x]-->B[y]\nend\n"
               "style A fill:#fff\nclass A cls\n")
        labels, edges = _parse_flowchart(src)
        self.assertIn(("A", "B"), [(a, b) for a, b, _ in edges])
        self.assertNotIn("subgraph", labels)
        self.assertNotIn("style", labels)

    def test_ascii_has_boxes_layers_and_arrow(self):
        art = render_ascii(FLOW)
        self.assertIsNotNone(art)
        assert art is not None
        self.assertIn("Paste secret", art)
        self.assertIn("Block", art)
        self.assertIn("+", art)
        self.assertIn("v", art)
        # Parent sits above its children.
        self.assertLess(art.index("Paste secret"), art.index("Block"))

    def test_empty_diagram_reports(self):
        self.assertEqual(render_ascii("graph TD\n"), "(empty diagram)")


class SequenceCase(unittest.TestCase):
    def test_ascii_has_participants_messages_and_note(self):
        art = render_ascii(SEQ)
        self.assertIsNotNone(art)
        assert art is not None
        self.assertIn("User", art)
        self.assertIn("Gateway", art)
        self.assertIn("chat request", art)
        self.assertIn("slow model", art)
        self.assertIn(">", art)


class SaveCase(unittest.TestCase):
    def test_save_adds_extension(self):
        path = os.path.join(tempfile.mkdtemp(prefix="akm-cli-save-"),
                            "d1")
        out = save_mmd(FLOW, path)
        self.assertTrue(out.endswith(".mmd"))
        with open(out) as f:
            self.assertIn("graph TD", f.read())


if __name__ == "__main__":
    unittest.main()
