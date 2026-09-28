"""Tests for explainer answer-shape coercion (app.explainer._coerce_answer).

Small models return three shapes for the same schema: the envelope object,
a bare sections array, or a single section object. All three must become an
envelope; anything else must keep failing so the repair ladder retries.
"""
import os
import tempfile
import unittest


# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-explainer-answer-"), "test.db"))

from app.explainer import _coerce_answer, _short_text  # noqa: E402


class TestCoerceAnswer(unittest.TestCase):
    def test_envelope_passes_through(self):
        env = {"summary": "s", "sections": [{"heading": "H"}]}
        self.assertIs(_coerce_answer(env), env)

    def test_bare_array_becomes_sections(self):
        out = _coerce_answer([{"heading": "H", "body": "b"}, "junk", 1])
        self.assertEqual(out, {"sections": [{"heading": "H", "body": "b"}]})

    def test_single_section_wraps_with_rest_preserved(self):
        out = _coerce_answer({"heading": "H", "body": "b", "summary": "s",
                              "image": "u", "claims": []})
        self.assertEqual(out["sections"],
                         [{"heading": "H", "body": "b", "image": "u", "claims": []}])
        self.assertEqual(out["summary"], "s")
        self.assertNotIn("heading", out)
        self.assertNotIn("body", out)

    def test_sectionless_dict_still_fails(self):
        with self.assertRaises(ValueError):
            _coerce_answer({"summary": "s", "key_points": ["a"]})

    def test_garbage_still_fails(self):
        for bad in ([], ["a"], "str", 42, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                _coerce_answer(bad)


class TestShortText(unittest.TestCase):
    def test_short_text_is_untouched(self):
        self.assertEqual(_short_text("abc", 200), "abc")
        self.assertEqual(_short_text("", 200), "")

    def test_prefers_a_sentence_end(self):
        out = _short_text("First sentence here. Second sentence follows.", 30)
        self.assertEqual(out, "First sentence here.…")

    def test_falls_back_to_a_word_boundary(self):
        """The regression: a diagram caption was stored as "...and is no"."""
        out = _short_text(
            "In enterprise M365 Copilot Microsoft is the primary liable party "
            "while the customer retains responsibility and OpenAI sits behind "
            "Microsoft and is not in the enterprise contract chain at all.", 120)
        self.assertTrue(out.endswith("…"), out)
        self.assertNotRegex(out, r"is no…$|transmit…$")


if __name__ == "__main__":
    unittest.main()
