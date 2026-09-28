"""Tests for explainer figure selection.

A stored run audit showed sections illustrated with a site's og:card, an
arXiv logo, a 200x200 badge and even plain HTML pages, and one hero image
reused across four unrelated sections. Each test below pins one of those
failures shut:

  * page chrome (logos, share cards, spacers) is never a figure,
  * a URL that is not an image is never attached,
  * the page title is not an image-level signal, so one hero cannot satisfy
    every section of an article,
  * a figure must overlap the section in more than one word,
  * the same figure is never reused, and the number is capped,
  * a dead link is dropped rather than rendered broken.

No DB, no network: the load probe is stubbed.
"""
import os
import tempfile
import os
import unittest


# Pin the database before app.database is imported: a module that omits
# this can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-explainer-images-"), "test.db"))

from app import explainer as ex  # noqa: E402
from app.explainer import (  # noqa: E402
    _assign_images, _content_tokens, _figure_named, _image_junk, _image_score,
    _is_figure, _looks_like_image_url, _pick_cover,
)

HEADING = "Core IP Exposure: What You Are Actually Sending"
BODY = ("Every prompt sent to a hosted frontier model leaves your boundary. "
        "Molecule structures and assay results in the request can be logged, "
        "retained for training, or exposed through model memorization.")


def relevant_img(src="https://example.com/fig1-request-flow.png"):
    return {"src": src, "alt": "diagram of model API request flow",
            "caption": "Figure 1: how prompts travel from the lab to the hosted model",
            "page": "Hosted LLM privacy risks for drug discovery",
            "page_url": "https://example.com/llm-privacy", "hero": False,
            "figure": True}


def og_card():
    return {"src": "https://learn.microsoft.com/en-us/media/open-graph-image.png",
            "alt": "Data, Privacy, and Security for Microsoft Copilot | Microsoft Learn",
            "caption": "", "page": "Data, Privacy, and Security for Microsoft Copilot",
            "page_url": "https://learn.microsoft.com/en-us/privacy", "hero": True,
            "figure": False}


def stock_photo():
    return {"src": "https://media.licdn.com/dms/image/v2/article-cover_image/hero.jpg",
            "alt": "", "caption": "How GitHub Copilot Handles Multi-File Context",
            "page": "Copilot retention", "page_url": "https://linkedin.com/x",
            "hero": False, "figure": False}


class TestPageChromeRejected(unittest.TestCase):
    def test_share_cards_and_logos_are_junk(self):
        for url in ("https://learn.microsoft.com/en-us/media/open-graph-image.png",
                    "https://stealthcloud.ai/images/og-default.png",
                    "https://microsoft.github.io/zerotrustassessment/img/social-card.png",
                    "https://arxiv.org/static/browse/0.3.4/images/arxiv-logo-fb.png",
                    "https://x.com/i/ogshare?url=abc",
                    "https://site.com/img/spacer.gif",
                    "https://site.com/wp-content/gfg_200x200-min.png"):
            self.assertTrue(_image_junk(url), url)

    def test_real_figures_are_not_junk(self):
        for url in ("https://www.cdc.gov/media/images/JETransmissionCycle1200x675.png",
                    "https://journals.plos.org/plospathogens/article/figure/image?size=inline",
                    "https://storage.googleapis.com/gweb-research2023-media/TabFM_Architecture.png",
                    "https://example.com/figures/attack-chain-diagram.png"):
            self.assertFalse(_image_junk(url), url)

    def test_junk_substrings_do_not_catch_real_words(self):
        # "ads-" is inside "downloads-", "cta" inside "octane", "line" inside
        # "pipeline": a filter that matched those would eat real figures.
        for url in ("https://cdn.com/downloads/pipeline-architecture.png",
                    "https://cdn.com/img/octane-process-diagram.png",
                    "https://cdn.com/img/timeline-of-events.png"):
            self.assertFalse(_image_junk(url), url)


class TestImageUrlShape(unittest.TestCase):
    def test_html_pages_are_not_images(self):
        for url in ("https://arxiv.org/html/2509.15557v1",
                    "https://www.jevai.org/docs",
                    "https://salijona.github.io/blog/2025/tabular/",
                    "https://example.com/page.html",
                    "https://dailysecurityreview.com/resources/cve-2026-42824-x"):
            self.assertFalse(_looks_like_image_url(url), url)

    def test_real_image_urls_pass(self):
        for url in ("https://example.com/fig1.png",
                    "https://cdn.who.int/media/images/default-source/map.png",
                    "https://site.com/_next/image?url=%2Fassets%2Ffig.png&w=800",
                    "https://media2.dev.to/dynamic/image/width=800/https://x.dev/img/a.webp",
                    "https://site.com/photo?id=12"):
            self.assertTrue(_looks_like_image_url(url), url)

    def test_wrapper_around_non_image_is_rejected(self):
        # Next.js optimizer wrapping an API endpoint: the inner target decides.
        self.assertFalse(_looks_like_image_url(
            "https://ts-docs.mintlify.app/mintlify-assets/_next/image"
            "?url=%2F_mintlify%2Fapi%2Fog%3Fdivision%3DGet%2Bs"))


class TestFigureLikeness(unittest.TestCase):
    def test_figcaption_makes_a_figure(self):
        self.assertTrue(_is_figure(relevant_img()))

    def test_figure_named_filename_is_enough(self):
        self.assertTrue(_figure_named("https://x.com/img/attack-chain-diagram.png"))
        self.assertTrue(_is_figure({"src": "https://x.com/img/flow-01.png",
                                    "alt": "", "caption": "", "figure": False}))

    def test_descriptive_alt_is_enough(self):
        self.assertTrue(_is_figure({"src": "https://x.com/a12345",
                                    "alt": "retention lifecycle across chat and api",
                                    "caption": "", "figure": False}))

    def test_hero_cards_and_stock_photos_are_not_figures(self):
        self.assertFalse(_is_figure(og_card()))
        self.assertFalse(_is_figure(stock_photo()))

    def test_hero_never_figures_even_with_a_caption(self):
        self.assertFalse(_is_figure({**og_card(), "caption": "Figure 3: the flow"}))


class TestImageScoring(unittest.TestCase):
    def test_relevant_figure_scores(self):
        score, matched = _image_score(HEADING, BODY, relevant_img())
        self.assertGreaterEqual(score, 4)
        self.assertGreaterEqual(len(matched), 2)

    def test_page_title_is_not_an_image_signal(self):
        """A generic og:card whose alt/caption/filename say nothing must not
        score on the page title it merely happens to sit on."""
        img = {"src": "https://x.com/a1b2c3", "alt": "", "caption": "",
               "page": HEADING + " " + BODY, "hero": False}
        score, matched = _image_score(HEADING, BODY, img)
        self.assertEqual(score, 0)
        self.assertEqual(matched, [])

    def test_filename_counts_as_evidence(self):
        score, matched = _image_score(
            "Attack chain for the exfiltration flaw",
            "A timing gap in streamed content delivery enables the read.",
            {"src": "https://x.com/searchleak-attack-chain-diagram.png",
             "alt": "", "caption": "", "page": "irrelevant", "hero": False})
        self.assertGreaterEqual(len(matched), 2)

    def test_short_tokens_do_not_count(self):
        self.assertNotIn("ai", _content_tokens("AI models"))
        self.assertIn("models", _content_tokens("AI models"))


class TestImageAssignment(unittest.TestCase):
    def _answer(self, pick=None, n=1, heading=HEADING, body=BODY):
        return {"sources": [{"title": "t", "url": "https://example.com/llm-privacy"}],
                "sections": [{"heading": heading, "body": body, "image": pick,
                              "claims": [{"text": "c", "citations": [
                                  {"sourceIndex": 0, "quote": "a fine quote"}]}]}
                             for _ in range(n)]}

    def _no_probe(self):
        return ex.__dict__.setdefault("_imgtest", [])

    def setUp(self):
        # Never touch the network from a unit test.
        self._orig = ex._image_loads
        ex._image_loads = lambda url: True

    def tearDown(self):
        ex._image_loads = self._orig

    def test_model_junk_pick_is_replaced_by_relevant_figure(self):
        ans = self._answer(og_card()["src"])
        _assign_images(ans, [og_card(), relevant_img()])
        sec = ans["sections"][0]
        self.assertEqual(sec["image"], relevant_img()["src"])
        self.assertIn("prompts travel", sec["image_caption"])
        self.assertEqual(sec["image_page"], "https://example.com/llm-privacy")

    def test_stock_photo_never_illustrates_a_section(self):
        ans = self._answer(None)
        _assign_images(ans, [stock_photo()])
        self.assertIsNone(ans["sections"][0]["image"])

    def test_html_page_never_illustrated(self):
        ans = self._answer(None)
        _assign_images(ans, [relevant_img("https://arxiv.org/html/2509.15557v1")])
        self.assertIsNone(ans["sections"][0]["image"])

    def test_weak_overlap_is_rejected(self):
        # Exactly one shared word is not evidence that a figure depicts the
        # section, however plausible the rest of the caption looks.
        img = {"src": "https://x.com/img/retention-overview.png", "alt": "",
               "caption": "Overview of the vendor prompt programme.", "figure": True,
               "page": "p", "page_url": "https://example.com/llm-privacy"}
        ans = self._answer(None)
        _assign_images(ans, [img])
        self.assertIsNone(ans["sections"][0]["image"])

    def test_same_figure_is_never_reused(self):
        ans = self._answer(None, n=3)
        _assign_images(ans, [relevant_img()])
        shown = [s["image"] for s in ans["sections"] if s.get("image")]
        self.assertEqual(len(shown), 1)
        self.assertEqual(shown[0], relevant_img()["src"])

    def test_figure_count_is_capped(self):
        imgs = [relevant_img(f"https://example.com/fig{i}-request-flow.png")
                for i in range(6)]
        ans = self._answer(None, n=6)
        _assign_images(ans, imgs, max_figures=2)
        self.assertEqual(len([s for s in ans["sections"] if s.get("image")]), 2)

    def test_dead_link_is_dropped_not_rendered(self):
        ex._image_loads = lambda url: False
        ans = self._answer(None)
        _assign_images(ans, [relevant_img()])
        self.assertIsNone(ans["sections"][0]["image"])
        self.assertEqual(ans["image_stats"]["rejected"]["did_not_load"], 1)

    def test_probe_failure_never_breaks_the_run(self):
        def boom(url):
            raise RuntimeError("network down")
        ex._image_loads = boom
        ans = self._answer(None)
        try:
            _assign_images(ans, [relevant_img()])
        except RuntimeError:
            self.fail("a probe failure must not abort the explanation")
        self.assertIsNone(ans["sections"][0]["image"])

    def test_no_candidate_means_no_image(self):
        ans = self._answer(og_card()["src"])
        _assign_images(ans, [og_card()])
        sec = ans["sections"][0]
        self.assertIsNone(sec["image"])
        self.assertNotIn("image_caption", sec)

    def test_non_dict_sections_ignored(self):
        ans = {"sources": [], "sections": ["just a string", 42, None]}
        _assign_images(ans, [relevant_img()])
        self.assertEqual(ans["sections"], ["just a string", 42, None])

    def test_stats_report_why_things_were_dropped(self):
        ans = self._answer(None)
        _assign_images(ans, [og_card(), stock_photo()])
        rej = ans["image_stats"]["rejected"]
        self.assertGreaterEqual(rej["not_a_figure"], 1)
        self.assertEqual(ans["image_stats"]["assigned"], 0)


class TestCover(unittest.TestCase):
    def _answer(self, urls):
        return {"sources": [{"title": "t", "url": u} for u in urls]}

    def test_cover_comes_from_a_cited_page(self):
        ans = self._answer(["https://learn.microsoft.com/en-us/privacy"])
        cover = _pick_cover(ans, [og_card()])
        self.assertEqual(cover["url"], og_card()["src"])
        self.assertEqual(cover["page"], "https://learn.microsoft.com/en-us/privacy")

    def test_no_cover_from_uncited_page(self):
        ans = self._answer(["https://other.example/x"])
        self.assertEqual(_pick_cover(ans, [og_card()]), {})

    def test_no_cover_when_no_heroes(self):
        ans = self._answer(["https://example.com/llm-privacy"])
        self.assertEqual(_pick_cover(ans, [relevant_img()]), {})


if __name__ == "__main__":
    unittest.main()
