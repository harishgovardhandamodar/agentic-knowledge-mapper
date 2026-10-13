"""Tests for the preferred/fallback signalling in ``app.llm``.

The base chain always tries the preferred gateway (``LLM_BASE_URL``, Axiom)
first; every other base is a fallback. When Axiom is unreachable the request is
still answered -- by a fallback -- and the UI must be able to say so *before*
the operator assumes the preferred gateway served it. These tests pin that
signal: the live probe's ``fallback_active``/``notice`` and the record of calls
that actually fell back.

No DB, no network: httpx and ``_post`` are mocked, and every base uses a
``.example`` host so nothing resolves.
"""
import os
import tempfile
import unittest
from unittest import mock

# Pin the database before app.database is imported: a module that omits this
# can inherit data/akm.db and write test rows into the live store.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-llm-fb-"), "test.db"))

import app.llm as llm  # noqa: E402

PREFERRED = "http://preferred.example:8210/v1"
FALLBACK = "http://fallback.example:8210/v1"


class _FakeClient:
    """Minimal stand-in for ``httpx.Client`` that does not swallow exceptions.

    A MagicMock's ``__exit__`` returns a truthy Mock, which would suppress the
    raise the probe relies on to move to the next base.
    """

    def __init__(self, get):
        self._get = get

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, **kwargs):
        return self._get(url, **kwargs)


def _models_ok():
    resp = mock.Mock(status_code=200)
    resp.json.return_value = {"data": [{"id": llm.MODEL}]}
    return resp


class HealthFallbackCase(unittest.TestCase):
    def setUp(self):
        self._orig = (llm.BASE_URL, llm.FALLBACK_URL)
        llm.BASE_URL, llm.FALLBACK_URL = PREFERRED, FALLBACK

    def tearDown(self):
        llm.BASE_URL, llm.FALLBACK_URL = self._orig

    def _patch_client(self, get):
        return mock.patch(
            "app.llm.httpx.Client",
            side_effect=lambda *a, **k: _FakeClient(get))

    def test_preferred_reachable_is_not_a_fallback(self):
        with self._patch_client(lambda url, **k: _models_ok()):
            h = llm.health()
        self.assertTrue(h["reachable"])
        self.assertEqual(h["served_by"], PREFERRED)
        self.assertTrue(h["preferred_reachable"])
        self.assertFalse(h["fallback_active"])
        self.assertIsNone(h["notice"])

    def test_fallback_active_when_the_preferred_gateway_is_down(self):
        def get(url, **k):
            if url.startswith(PREFERRED):
                raise RuntimeError("connection refused")
            return _models_ok()

        with self._patch_client(get):
            h = llm.health()
        self.assertTrue(h["reachable"])
        self.assertEqual(h["served_by"], FALLBACK)
        self.assertFalse(h["preferred_reachable"])
        self.assertTrue(h["fallback_active"])
        # The notice names both ends so the operator knows what was bypassed.
        self.assertIn("fallback.example:8210", h["notice"])
        self.assertIn("preferred.example:8210", h["notice"])

    def test_no_gateway_is_an_explicit_notice(self):
        def get(url, **k):
            raise RuntimeError("nope")

        with self._patch_client(get):
            h = llm.health()
        self.assertFalse(h["reachable"])
        self.assertFalse(h["fallback_active"])
        self.assertEqual(h["notice"], "No LLM gateway is reachable.")

    def test_preferred_base_is_always_first_in_the_chain(self):
        # "Preferred is always Axiom" is a property of the chain, not a hope.
        self.assertEqual(llm._bases()[0], llm.BASE_URL)


class FallbackUsageCase(unittest.TestCase):
    def setUp(self):
        self._orig = (llm.BASE_URL, llm.FALLBACK_URL)
        llm.BASE_URL, llm.FALLBACK_URL = PREFERRED, FALLBACK
        with llm._fallback_lock:
            llm._fallback_state.update(uses=0, last_at=None, last_base=None)

    def tearDown(self):
        llm.BASE_URL, llm.FALLBACK_URL = self._orig

    def test_a_call_served_by_the_fallback_is_recorded(self):
        def _post(base, payload, extra=None):
            if base == PREFERRED:
                raise llm.LLMError("down")
            return ({"choices": [{"message": {"content": "ok"}}],
                     "model": llm.MODEL},
                    {"X-Fox-Request-Id": "test"})

        with mock.patch("app.llm._post", side_effect=_post):
            self.assertEqual(llm.chat([{"role": "user", "content": "hi"}]), "ok")
        with llm._fallback_lock:
            self.assertEqual(llm._fallback_state["uses"], 1)
            self.assertEqual(llm._fallback_state["last_base"], FALLBACK)
            self.assertIsNotNone(llm._fallback_state["last_at"])

    def test_a_call_served_by_the_preferred_base_is_not_recorded(self):
        def _post(base, payload, extra=None):
            return ({"choices": [{"message": {"content": "ok"}}],
                     "model": llm.MODEL},
                    {"X-Fox-Request-Id": "test"})

        with mock.patch("app.llm._post", side_effect=_post):
            llm.chat([{"role": "user", "content": "hi"}])
        with llm._fallback_lock:
            self.assertEqual(llm._fallback_state["uses"], 0)


if __name__ == "__main__":
    unittest.main()
