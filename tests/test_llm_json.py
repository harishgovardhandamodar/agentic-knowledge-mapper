"""Tests for lenient model-JSON parsing (app.llm._parse_json_lenient).

Deep answers (deep-dive/deep) run ~15KB with long verbatim quotes; small
models routinely emit literal newlines inside strings, trailing commas, and
prose around the payload. Strict parsing turned all of that into a total
explainer failure. These tests pin the repairs. No DB, no network.
"""
import unittest

from app.llm import _parse_json_lenient, LLMError


class TestLenientJson(unittest.TestCase):
    def test_clean_json_unchanged(self):
        self.assertEqual(_parse_json_lenient('{"a": 1, "b": [1, 2]}'),
                         {"a": 1, "b": [1, 2]})
        self.assertEqual(_parse_json_lenient('[1, 2]'), [1, 2])

    def test_code_fences_stripped(self):
        self.assertEqual(_parse_json_lenient('```json\n{"a": 1}\n```'), {"a": 1})

    def test_literal_newlines_inside_strings(self):
        """The deep-dive killer: markdown bodies with real line breaks."""
        raw = '{"summary": "line one\nline two", "key_points": ["a\tb"]}'
        self.assertEqual(_parse_json_lenient(raw),
                         {"summary": "line one\nline two", "key_points": ["a\tb"]})

    def test_prose_around_payload(self):
        raw = 'Here is your explanation:\n{"summary": "ok"}\nHope that helps!'
        self.assertEqual(_parse_json_lenient(raw), {"summary": "ok"})

    def test_trailing_commas_repaired(self):
        self.assertEqual(_parse_json_lenient('{"a": 1, "b": [1, 2,],}'),
                         {"a": 1, "b": [1, 2]})

    def test_trailing_prose_with_braces(self):
        """Greedy first-brace-to-last-brace extraction breaks here; the
        balanced-span scan must stop at the payload's own close."""
        raw = '{"a": 1} surely {not json}'
        self.assertEqual(_parse_json_lenient(raw), {"a": 1})

    def test_leading_citation_markers_do_not_win(self):
        """Regression: prose like 'Sources [1], [2] show...' parses '[1]' as
        JSON. The longest span -- the real payload -- must win."""
        raw = 'Sources [1], [2] show this: {"summary": "ok", "key_points": ["a", "b"]}'
        self.assertEqual(_parse_json_lenient(raw),
                         {"summary": "ok", "key_points": ["a", "b"]})

    def test_explainer_shaped_payload(self):
        raw = ('```json\n{"summary": "Drug discovery uses models.\nIt is risky.",\n'
               '"sections": [{"heading": "IP risk", "body": "Keep secrets\\nsecret.",}],\n'
               '"key_points": ["one", "two",],}\n```')
        out = _parse_json_lenient(raw)
        self.assertEqual(out["sections"][0]["heading"], "IP risk")
        self.assertEqual(out["key_points"], ["one", "two"])

    def test_garbage_raises(self):
        with self.assertRaises(LLMError):
            _parse_json_lenient("no json here at all")
        with self.assertRaises(LLMError):
            _parse_json_lenient("")


if __name__ == "__main__":
    unittest.main()
