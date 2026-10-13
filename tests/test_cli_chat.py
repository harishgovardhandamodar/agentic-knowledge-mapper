"""Chat console: editor, router, and frame. Headless.

Background jobs run real threads; the stub answers instantly and POLL_S
is patched to zero so tests stay fast. Pin header required suite-wide.
"""
import os
import tempfile
import time
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-chat-"),
                                "test.db"))

import cli.chat as chatmod  # noqa: E402
from cli.chat import Chat, Editor, KeyReader  # noqa: E402

chatmod.POLL_S = 0


class KeyReaderCase(unittest.TestCase):
    def _reader(self, chunks):
        r, w = os.pipe()
        for c in chunks:
            os.write(w, c)
        os.close(w)
        return KeyReader(fd=r)

    def test_printable_arrows_and_enter(self):
        kr = self._reader([b"a\x1b[B\r"])
        self.assertEqual(kr.key(), "a")
        self.assertEqual(kr.key(), "down")
        self.assertEqual(kr.key(), "enter")

    def test_split_multibyte_reassembles(self):
        emoji = "ü".encode()
        kr = self._reader([emoji[:1], emoji[1:]])
        self.assertEqual(kr.key(), "ü")

    def test_eof_reports_once_then_quits(self):
        r, w = os.pipe()
        os.close(w)
        kr = KeyReader(fd=r)
        self.assertEqual(kr.key(0.1), "eof")
        os.close(r)

    def test_bare_esc_is_esc(self):
        kr = self._reader([b"\x1b"])
        self.assertEqual(kr.key(), "esc")


class StubClient:
    base_url = "http://stub"

    def health(self):
        return {"llm": {"served_by": "http://axiom:8210/v1",
                        "preferred_reachable": True,
                        "fallback_active": False}}

    def llm_info(self):
        return self.health()["llm"]

    def list_investigations(self):
        return [{"id": 1, "title": "Alpha Widget", "keywords": "w",
                 "description": "d", "status": "ready"}]

    def get_investigation(self, iid):
        return {"id": iid, "title": "Alpha Widget"}

    def create_investigation(self, title, desc="", kw="", sources="web"):
        return {"id": 9, "title": title}

    def launch_run(self, iid):
        return {"status": "started"}

    def ask_explanation(self, iid, question):
        return {"id": 3, "status": "running"}

    def get_explanation(self, eid):
        return {"id": eid, "status": "done", "phase": "answer",
                "question": "q?",
                "answer": {"answer": "Because reasons.",
                           "diagrams": {"flow": "graph TD\n A[x]-->B[y]"}}}

    def list_assessments(self, iid):
        return []

    def manager_runs(self, limit=10):
        return [{"id": 4, "status": "compiled", "compiled": True,
                 "command": "assess x"}]

    def manager_parse(self, cmd):
        return {"topics": [{"title": "T1"}]}

    def manager_run(self, plan, command="", options=None):
        return {"id": 5}

    def manager_timeline(self, rid):
        return {"flow": ["command", "plan"], "events": []}

    def manager_compile(self, rid):
        return {"artifact_id": 6}

    def manager_report_markdown(self, rid):
        return "# report\n\nbody"

    def list_runs(self):
        return []

    def ledger_timeline(self, limit=8):
        return []

    def approvals_pending(self):
        return []


class EditorCase(unittest.TestCase):
    def test_type_backspace_cursor(self):
        ed = Editor()
        for ch in "abc":
            ed.key(ch)
        ed.key("left")
        ed.key("backspace")
        self.assertEqual(ed.text(), "ac")
        self.assertEqual(ed.key("enter"), "ac")
        self.assertEqual(ed.text(), "")

    def test_history_up_down(self):
        ed = Editor()
        for ch in "one":
            ed.key(ch)
        ed.key("enter")
        for ch in "two":
            ed.key(ch)
        ed.key("enter")
        ed.key("up")
        self.assertEqual(ed.text(), "two")
        ed.key("up")
        self.assertEqual(ed.text(), "one")
        ed.key("down")
        self.assertEqual(ed.text(), "two")
        ed.key("down")
        self.assertEqual(ed.text(), "")


class RouterCase(unittest.TestCase):
    def setUp(self):
        self.chat = Chat(StubClient())  # type: ignore[arg-type]
        from rich.console import Console
        self.chat.console = Console(width=100, height=40)

    def _text(self):
        with self.chat.console.capture() as cap:
            self.chat.console.print(self.chat.frame())
        return cap.get()

    def test_help_and_unknown(self):
        self.chat.submit("/help")
        self.chat.submit("/nope")
        text = self._text()
        self.assertIn("/research", text)
        self.assertIn("unknown /nope", text)

    def test_research_use_new_launch(self):
        self.chat.submit("/research alpha")
        self.chat.submit("/use 1")
        self.assertEqual(self.chat.inv_id, 1)
        self.chat.submit("/new Fresh Title")
        self.assertEqual(self.chat.inv_id, 9)
        self.chat.submit("/launch")
        self.assertIn("started", self._text())

    def test_free_text_needs_selection_then_asks(self):
        self.chat.submit("what is this?")
        self.assertIn("Select an investigation", self._text())
        self.chat.submit("/use 1")
        self.chat.submit("what is this?")
        deadline = time.time() + 10
        while time.time() < deadline:
            self.chat._reap()
            if not any(j["thread"].is_alive() for j in self.chat.jobs):
                break
            time.sleep(0.05)
        text = self._text()
        self.assertIn("Because reasons.", text)
        self.assertIn("+---+", text)

    def test_mgr_ops_health(self):
        self.chat.submit("/mgr")
        self.chat.submit("/ops")
        self.chat.submit("/health")
        text = self._text()
        self.assertIn("assess x", text)
        self.assertIn("axiom:8210", text)

    def test_clear_and_quit(self):
        self.chat.submit("/help")
        self.chat.submit("/clear")
        with self.chat.console.capture() as cap:
            self.chat.console.print(self.chat.frame())
        self.assertNotIn("/research", cap.get())
        self.assertTrue(self.chat.key("esc"))
        self.assertEqual(self.chat.mode, "nav")
        self.assertTrue(self.chat.key("i"))
        self.chat.key("esc")
        self.assertFalse(self.chat.key("q"))


class FrameCase(unittest.TestCase):
    def test_frame_fits_and_modes(self):
        chat = Chat(StubClient())  # type: ignore[arg-type]
        from rich.console import Console
        chat.console = Console(width=100, height=30)
        chat.submit("/help")
        with chat.console.capture() as cap:
            chat.console.print(chat.frame())
        lines = cap.get().splitlines()
        self.assertEqual(len(lines), 30)
        self.assertTrue(all(len(ln) <= 100 for ln in lines))
        self.assertIn("▊", cap.get())
        chat.key("esc")
        with chat.console.capture() as cap2:
            chat.console.print(chat.frame())
        self.assertIn("[NAV]", cap2.get())


if __name__ == "__main__":
    unittest.main()
