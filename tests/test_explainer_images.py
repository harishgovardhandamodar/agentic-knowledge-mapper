"""Tests for explainer image relevance gating.

Sections were getting random stock heroes (e.g. SEO-site og:images) because
fetch kept the first non-logo <img> and the model picked from the bag. Now
every candidate carries alt/caption/page context and each section keeps a
pick only if it shares vocabulary with the section. No DB, no network --
only the pure scoring/assignment helpers.
"""
import os
import tempfile
import unittest

os.environ.setdefault("AKM_DATABASE_URL", "sqlite:///" + os.path.join(
    tempfile.mkdtemp(prefix="akm-img-test-"), "test.db"))

from app.explainer import _assign_images, _content_tokens, _image_score  # noqa: E402

HEADING = "Core IP Exposure: What You Are Actually Sending"
BODY = ("Every prompt sent to a hosted frontier model leaves your boundary. "
        "Molecule structures and assay results in the request can be logged, "
        "retained for training, or exposed through model memorization.")


def junk_img():
    return {"src": "https://www.aimadetools.com/hero-banner.jpg", "alt": "",
            "caption": "", "page": "AI Made Tools - Free AI Tools Directory",
            "page_url": "https://www.aimadetools.com/", "hero": True}


def relevant_img():
    return {"src": "https://example.com/fig1-request-flow.png",
            "alt": "diagram of model API request flow",
            "caption": "Figure 1: how prompts travel from the lab to the hosted model",
            "page": "Hosted LLM privacy risks for drug discovery",
            "page_url": "https://example.com/llm-privacy", "hero": False}


class TestImageScoring(unittest.TestCase):
    def test_junk_scores_zero(self):
        score, matched = _image_score(HEADING, BODY, junk_img())
        self.assertEqual(score, 0)
        self.assertEqual(matched, [])

    def test_relevant_scores_above_bar(self):
        score, matched = _image_score(HEADING, BODY, relevant_img())
        self.assertGreaterEqual(score, 3)
        self.assertTrue(matched)

    def test_short_tokens_do_not_count(self):
        self.assertNotIn("ai", _content_tokens("AI models"))
        self.assertIn("models", _content_tokens("AI models"))


class TestImageAssignment(unittest.TestCase):
    def _answer(self, pick):
        return {"sources": [{"title": "t", "url": "https://example.com/llm-privacy"}],
                "sections": [{"heading": HEADING, "body": BODY, "image": pick,
                              "claims": [{"text": "c", "citations": [
                                  {"sourceIndex": 0, "quote": "a fine quote here"}]}]}]}

    def test_model_junk_pick_is_replaced_by_relevant_best(self):
        ans = self._answer(junk_img()["src"])
        _assign_images(ans, [junk_img(), relevant_img()])
        sec = ans["sections"][0]
        self.assertEqual(sec["image"], relevant_img()["src"])
        self.assertIn("prompts travel", sec["image_caption"])

    def test_model_good_pick_survives_with_caption(self):
        ans = self._answer(relevant_img()["src"])
        _assign_images(ans, [junk_img(), relevant_img()])
        sec = ans["sections"][0]
        self.assertEqual(sec["image"], relevant_img()["src"])
        self.assertTrue(sec["image_caption"])

    def test_no_candidate_above_bar_means_no_image(self):
        ans = self._answer(junk_img()["src"])
        _assign_images(ans, [junk_img()])
        sec = ans["sections"][0]
        self.assertIsNone(sec["image"])
        self.assertNotIn("image_caption", sec)

    def test_unknown_model_pick_falls_back_to_best(self):
        ans = self._answer("https://invented.example/made-up.png")
        _assign_images(ans, [junk_img(), relevant_img()])
        self.assertEqual(ans["sections"][0]["image"], relevant_img()["src"])

    def test_non_dict_sections_ignored(self):
        ans = {"sources": [], "sections": ["just a string", 42, None]}
        _assign_images(ans, [relevant_img()])  # must not raise
        self.assertEqual(ans["sections"], ["just a string", 42, None])


if __name__ == "__main__":
    unittest.main()
