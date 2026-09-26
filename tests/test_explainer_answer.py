"""Tests for explainer answer-shape coercion (app.explainer._coerce_answer).

Small models return three shapes for the same schema: the envelope object,
a bare sections array, or a single section object. All three must become an
envelope; anything else must keep failing so the repair ladder retries.
"""
import os
import tempfile
import unittest

os.environ.setdefault("AKM_DATABASE_URL", "sqlite:///" + os.path.join(
    tempfile.mkdtemp(prefix="akm-coerce-test-"), "test.db"))

from app.explainer import _coerce_answer  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
