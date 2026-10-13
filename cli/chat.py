"""Chat-style agent console (opencode-like) over the shared backend.

``python -m cli chat`` opens a full-screen conversation: a scrollable
transcript on top, a line editor with history at the bottom. Free text
asks the explainer about the selected investigation; slash commands drive
research, diagrams, manager runs, and ops. Slow work (answers, compiles,
launches) runs in background threads and lands in the transcript when
done. Same API/database as the web GUI, so everything here is visible
there. Rich-only rendering, stdlib input.
"""

from __future__ import annotations

import codecs
import os
import re
import select
import sys
import threading
import time

from rich.console import Console, Group
from rich.markdown import Markdown
from rich.text import Text

from cli import mermaid as _mm
from cli.client import AkMClient, ApiError
from cli.tui import _cell, _d, _table

POLL_S = 5.0
HEADER_S = 12.0
MAX_BLOCKS = 120

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")


class KeyReader:
    """Single-key input that survives piped stdin and dead pipes.

    Reads from ``/dev/tty`` when available so the console stays usable
    even when stdin is redirected; falls back to the stdin fd. Raw
    ``os.read`` avoids TextIOWrapper buffering quirks, an incremental
    decoder reassembles split multibyte characters, and EOF (closed
    pipe) reports as ``\"eof\"`` instead of spinning the loop forever.
    """

    def __init__(self, fd: int | None = None) -> None:
        if fd is None:
            try:
                self.fd = os.open("/dev/tty", os.O_RDONLY)
                self._own = True
            except OSError:
                self.fd = sys.stdin.fileno()
                self._own = False
        else:
            self.fd = fd
            self._own = False
        self._dec = codecs.getincrementaldecoder("utf-8")()
        self._chars = ""
        self.eof = False

    def close(self) -> None:
        if self._own:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self._own = False

    def is_tty(self) -> bool:
        try:
            return os.isatty(self.fd)
        except OSError:
            return False

    def _fill(self, timeout_s: float) -> bool:
        try:
            r, _, _ = select.select([self.fd], [], [], timeout_s)
        except (OSError, ValueError):
            self.eof = True
            return False
        if not r:
            return False
        try:
            data = os.read(self.fd, 64)
        except (OSError, InterruptedError):
            return False
        if data == b"":
            self.eof = True  # closed pipe: never spin, report once
            return False
        self._chars += self._dec.decode(data)
        return True

    def key(self, timeout_s: float = 0.25) -> str | None:
        """Next mapped key, None on timeout, ``\"eof\"`` at end of input."""
        while True:
            if self._chars.startswith("\x1b"):
                self._fill(0.05)
                seq = self._chars[1:4]
                for cand, name in (
                        ("[3~", "delete"), ("[5~", "pgup"),
                        ("[6~", "pgdn"), ("[A", "up"), ("[B", "down"),
                        ("[C", "right"), ("[D", "left"),
                        ("[H", "home"), ("[F", "end")):
                    if seq.startswith(cand):
                        self._chars = self._chars[1 + len(cand):]
                        return name
                self._chars = self._chars[1:]
                return "esc"
            if self._chars:
                ch, self._chars = self._chars[0], self._chars[1:]
                return _map_char(ch)
            if self.eof:
                return "eof"
            if not self._fill(timeout_s):
                return None if not self.eof else "eof"

    def readline_cooked(self) -> str:
        """Line input for prompts; caller must have cooked the terminal
        so the kernel echoes and edits. Ctrl-C cancels to empty."""
        buf = b""
        try:
            while not buf.endswith(b"\n"):
                r, _, _ = select.select([self.fd], [], [], 60.0)
                if not r:
                    break
                try:
                    chunk = os.read(self.fd, 256)
                except (OSError, InterruptedError):
                    break
                if chunk == b"":
                    break
                buf += chunk
        except KeyboardInterrupt:
            return ""
        return buf.decode("utf-8", "replace").rstrip("\r\n")


def _map_char(ch: str) -> str | None:
    if ch in ("\r", "\n"):
        return "enter"
    if ch in ("\x7f", "\x08"):
        return "backspace"
    if ch == "\x03":
        return "quit"
    if ch == "\x04":
        return "eof"
    if ch == "\x01":
        return "home"
    if ch == "\x05":
        return "end"
    if ch == "\x15":
        return "kill"
    if ch == "\x17":
        return "wkill"
    if ch == "\t":
        return "tab"
    if ch < " " or ch == "\x7f":
        return None
    return ch


class Editor:
    """Single-line editor with history (raw-mode friendly)."""

    def __init__(self) -> None:
        self.buf: list[str] = []
        self.cursor = 0
        self.history: list[str] = []
        self.hidx = 0
        self._saved = ""

    def text(self) -> str:
        return "".join(self.buf)

    def _recall(self) -> None:
        if self.hidx < len(self.history):
            self.buf = list(self.history[self.hidx])
        else:
            self.buf = list(self._saved)
        self.cursor = len(self.buf)

    def key(self, name: str) -> str | None:
        """Handle an editor key; returns the line on enter."""
        if name == "enter":
            line = self.text()
            if line.strip():
                if not self.history or self.history[-1] != line:
                    self.history.append(line)
            self.hidx = len(self.history)
            self.buf = []
            self.cursor = 0
            self._saved = ""
            return line
        if name == "backspace":
            if self.cursor > 0:
                del self.buf[self.cursor - 1]
                self.cursor -= 1
                self.hidx = len(self.history)
            return None
        if name == "delete":
            if self.cursor < len(self.buf):
                del self.buf[self.cursor]
            return None
        if name == "left":
            self.cursor = max(0, self.cursor - 1)
            return None
        if name == "right":
            self.cursor = min(len(self.buf), self.cursor + 1)
            return None
        if name == "home":
            self.cursor = 0
            return None
        if name == "end":
            self.cursor = len(self.buf)
            return None
        if name == "kill":
            del self.buf[:self.cursor]
            self.cursor = 0
            return None
        if name == "wkill":
            while self.cursor > 0 and self.buf[self.cursor - 1] == " ":
                del self.buf[self.cursor - 1]
                self.cursor -= 1
            while self.cursor > 0 and self.buf[self.cursor - 1] != " ":
                del self.buf[self.cursor - 1]
                self.cursor -= 1
            return None
        if name == "up":
            if self.hidx == len(self.history):
                self._saved = self.text()
            self.hidx = max(0, self.hidx - 1)
            self._recall()
            return None
        if name == "down":
            if self.hidx == len(self.history):
                return None
            self.hidx = min(len(self.history), self.hidx + 1)
            self._recall()
            return None
        if len(name) == 1:
            self.buf.insert(self.cursor, name)
            self.cursor += 1
            self.hidx = len(self.history)
        return None


class Chat:
    """State, rendering, and input loop for the agent console."""

    HELP = (
        "free text asks the selected investigation · /use <id> selects\n"
        "/research [filter] · /new <title> · /launch · /dia · /dia-next\n"
        "/mgr · /mgr-launch <command…> · /timeline <id> · /compile <id>\n"
        "/report <id> [path] · /ops · /health · /clear · /quit")

    def __init__(self, client: AkMClient):
        self.client = client
        self.console = Console()
        self.blocks: list[tuple] = []
        self.scroll = 0
        self.mode = "insert"
        self.editor = Editor()
        self.inv_id: int | None = None
        self.inv_title = ""
        self.filter_text = ""
        self.dia_idx = 0
        self.jobs: list[dict] = []
        self.health: dict = {}
        self._health_fresh = False
        self.lock = threading.Lock()
        self._term_old = None
        self._say("text", "AKM agent console — same database as the web "
                  "GUI. Type `/help` for commands, Esc for navigation.")

    # -- transcript ----------------------------------------------------
    def _say(self, kind: str, body) -> None:
        with self.lock:
            self.blocks.append((kind, body))
            del self.blocks[:max(0, len(self.blocks) - MAX_BLOCKS)]
        self.scroll = 0

    def _render_block(self, block: tuple) -> list[Text]:
        """Render a block to Text lines (never markup strings).

        Captured ANSI is stripped and lines are Text objects, so frame
        assembly can never re-parse terminal codes or user text
        (``[brackets]`` in either) as console markup -- that double
        parse corrupted code spans into visible ``[1m`` soup and could
        raise on unknown style tags.
        """
        kind, body = block
        if kind == "user":
            return [Text(f"❯ {body}", style="bold green")]
        if kind == "status":
            return [Text(f"◌ {body}", style="dim")]
        if kind == "done":
            return [Text(f"● {body}", style="dim")]
        if kind == "error":
            return [Text(f"✗ {body}", style="red")]
        if kind == "ascii":
            return [Text(ln) for ln in str(body).splitlines()]
        with self.console.capture() as cap:
            self.console.print(Markdown(str(body)) if kind == "text"
                               else body)
        return [Text(_ANSI_RE.sub("", ln))
                for ln in cap.get().splitlines()]

    # -- background jobs -------------------------------------------------
    def _submit(self, label: str, fn) -> None:
        self._say("status", f"{label} …")

        def _wrap():
            t0 = time.time()
            try:
                out = fn()
                if isinstance(out, list):
                    for b in out:
                        self._say(*b)
                elif out:
                    self._say(*out)
            except (ApiError, Exception) as e:
                self._say("error", f"{label}: {e}"[:300])
            else:
                self._say("done",
                          f"{label} ({time.time() - t0:.0f}s)")

        t = threading.Thread(target=_wrap, daemon=True)
        self.jobs.append({"label": label, "thread": t})
        t.start()

    def _reap(self) -> None:
        self.jobs = [j for j in self.jobs if j["thread"].is_alive()]

    # -- commands ----------------------------------------------------------
    def submit(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        self._say("user", line)
        if line.startswith("/"):
            self._command(line[1:])
        elif self.inv_id is None:
            self._say("text", "Select an investigation first: "
                      "`/research [filter]` then `/use <id>`.")
        else:
            self._ask(self.inv_id, line)

    def _command(self, text: str) -> None:
        parts = text.split(None, 1)
        cmd = (parts[0] if parts else "").lower()
        arg = parts[1] if len(parts) > 1 else ""
        handler = {"help": self._c_help, "h": self._c_help,
                   "quit": self._c_quit, "q": self._c_quit,
                   "clear": self._c_clear, "health": self._c_health,
                   "ops": self._c_ops, "research": self._c_research,
                   "r": self._c_research, "use": self._c_use,
                   "new": self._c_new, "launch": self._c_launch,
                   "ask": self._c_ask, "dia": self._c_dia,
                   "dia-next": self._c_dia_next,
                   "mgr": self._c_mgr, "mgr-launch": self._c_mgr_launch,
                   "timeline": self._c_timeline,
                   "compile": self._c_compile,
                   "report": self._c_report}.get(cmd)
        if handler is None:
            self._say("error", f"unknown /{cmd} — try /help")
            return
        try:
            handler(arg)
        except (ApiError, Exception) as e:
            self._say("error", str(e)[:300])

    def _c_help(self, _arg: str) -> None:
        self._say("text", self.HELP)

    def _c_quit(self, _arg: str) -> None:
        raise _Quit()

    def _c_clear(self, _arg: str) -> None:
        with self.lock:
            self.blocks = []
            self.scroll = 0

    def _c_health(self, _arg: str) -> None:
        llm = _d(self.client.llm_info())
        self._say("text",
                  f"LLM via {llm.get('served_by') or '?'} "
                  f"(fallback: {llm.get('fallback_active')}) · "
                  f"model {llm.get('model')}")

    def _c_ops(self, _arg: str) -> None:
        llm = _d(self.client.llm_info())
        runs = self.client.list_runs()
        by_status: dict[str, int] = {}
        for r in runs:
            by_status[str(r.get("status"))] = \
                by_status.get(str(r.get("status")), 0) + 1
        pending = self.client.approvals_pending()
        acts = self.client.ledger_timeline(8)
        lines = [
            f"LLM {llm.get('served_by')} "
            f"(fallback={llm.get('fallback_active')})",
            "swarm: " + ", ".join(f"{k}={v}"
                                  for k, v in sorted(by_status.items())),
            f"approvals pending: {len(pending)}",
        ]
        lines += [f"{a.get('ts', '')[:19]} {a.get('kind')} "
                  f"{a.get('verdict')}" for a in acts[-8:]]
        self._say("text", "\n".join(lines))

    def _c_research(self, arg: str) -> None:
        if arg:
            self.filter_text = arg
        rows = self._filtered()
        lines = [f"{r.get('id')}: {_cell(r.get('title'), 80)} "
                 f"[{r.get('status')}]" for r in rows[:15]]
        if not lines:
            lines = ["(no matches — /research <filter> searches "
                     "id/title/keywords/status)"]
        self._say("text", "\n".join(lines))

    def _filtered(self) -> list:
        try:
            rows = self.client.list_investigations()
        except (ApiError, Exception) as e:
            self._say("error", str(e)[:200])
            return []
        f = self.filter_text.strip().lower()
        if not f:
            return rows
        return [r for r in rows if f in " ".join(
            str((r.get(k) if isinstance(r, dict) else "") or "")
            for k in ("id", "title", "keywords", "description",
                      "status")).lower()]

    def _c_use(self, arg: str) -> None:
        if not arg.strip().isdigit():
            self._say("error", "usage: /use <id>")
            return
        inv = self.client.get_investigation(int(arg.strip()))
        self.inv_id = inv.get("id")
        self.inv_title = str(inv.get("title") or "")[:80]
        self._say("text", f"selected #{self.inv_id} {self.inv_title}")

    def _c_new(self, arg: str) -> None:
        if not arg.strip():
            self._say("error", "usage: /new <title>")
            return
        inv = self.client.create_investigation(arg.strip())
        self.inv_id = inv.get("id")
        self.inv_title = str(inv.get("title") or "")[:80]
        self._say("text", f"created + selected #{self.inv_id} "
                  "(also in the web app)")

    def _c_launch(self, _arg: str) -> None:
        if self.inv_id is None:
            self._say("error", "select one first: /use <id>")
            return
        res = self.client.launch_run(self.inv_id)
        self._say("status", f"research launched: {res}")

    def _c_ask(self, arg: str) -> None:
        if self.inv_id is None:
            self._say("error", "select one first: /use <id>")
            return
        if not arg.strip():
            self._say("error", "usage: /ask <question>")
            return
        self._ask(self.inv_id, arg.strip())

    def _ask(self, inv_id: int, question: str) -> None:
        def _fn():
            exp = self.client.ask_explanation(inv_id, question)
            eid = exp.get("id")
            deadline = time.time() + 1500
            while time.time() < deadline:
                time.sleep(POLL_S)
                cur = self.client.get_explanation(eid)
                if (cur.get("status") or "") != "running":
                    return self._answer_blocks(cur)
            return [("error", "answer timed out waiting")]
        self._submit(f"asking #{inv_id}", _fn)

    def _answer_blocks(self, exp: dict) -> list:
        exp = _d(exp)
        out = [("text",
                 f"answer to “{exp.get('question', '')[:120]}” "
                 f"(explanation #{exp.get('id')})")]
        ans = exp.get("answer")
        if isinstance(ans, str):
            try:
                import json as _json
                ans = _json.loads(ans)
            except ValueError:
                pass
        body = ""
        diagrams: list = []
        if isinstance(ans, dict):
            for key in ("answer", "text", "summary", "markdown", "body"):
                if isinstance(ans.get(key), str) and ans[key].strip():
                    body = ans[key]
                    break
            for key in ("diagrams", "diagram", "figures"):
                val = ans.get(key)
                if isinstance(val, dict):
                    diagrams.extend(
                        (k, v) for k, v in val.items()
                        if isinstance(v, str))
                elif isinstance(val, str):
                    diagrams.append((key, val))
        elif isinstance(ans, str):
            body = ans
        if body.strip():
            out.append(("text", body[:6000]))
        for _key, src in diagrams[:2]:
            art = _mm.render_ascii(src, width=76)
            out.append(("ascii" if art is not None else "text",
                        art if art is not None else src[:2000]))
        if not body.strip() and not diagrams:
            out.append(("text", f"status: {exp.get('status')} "
                        f"phase: {exp.get('phase')}"))
        return out

    def _diagram_sources(self) -> list:
        if self.inv_id is None:
            return []
        out = []
        for a in self.client.list_assessments(self.inv_id):
            if not isinstance(a, dict):
                continue
            stored = a.get("diagrams") or {}
            if isinstance(stored, dict):
                out.extend((str(k), v) for k, v in stored.items()
                           if isinstance(v, str))
            md = a.get("markdown") or ""
            if isinstance(md, str):
                out.extend(_mm.extract_fences(md))
        return out

    def _c_dia(self, _arg: str) -> None:
        srcs = self._diagram_sources()
        if not srcs:
            self._say("text", "no diagrams (assess the product first)")
            return
        self.dia_idx = 0
        self._show_dia(srcs)

    def _c_dia_next(self, _arg: str) -> None:
        srcs = self._diagram_sources()
        if not srcs:
            return
        self.dia_idx = (self.dia_idx + 1) % len(srcs)
        self._show_dia(srcs)

    def _show_dia(self, srcs: list) -> None:
        key, src = srcs[self.dia_idx % len(srcs)]
        art = _mm.render_ascii(src, width=76)
        self._say("text", f"{key} ({_mm.diagram_kind(src)}; "
                  f"{self.dia_idx % len(srcs) + 1}/{len(srcs)})")
        self._say("ascii" if art is not None else "text",
                  art if art is not None else src[:3000])

    def _c_mgr(self, _arg: str) -> None:
        rows = self.client.manager_runs(10)
        t = _table("manager runs", [("id", 6), ("status", 10),
                                    ("compiled", 8), ("command", 60)],
                   [[_cell(r.get("id"), 6), _cell(r.get("status"), 10),
                     _cell(r.get("compiled"), 8),
                     _cell(r.get("command"), 60)] for r in rows])
        self._say("table", t)

    def _c_mgr_launch(self, arg: str) -> None:
        if not arg.strip():
            self._say("error", "usage: /mgr-launch <command…>")
            return

        def _fn():
            plan = self.client.manager_parse(arg.strip())
            run = self.client.manager_run(plan, arg.strip(), {})
            topics = [t.get("title") for t in plan.get("topics", [])]
            return [("text", f"manager run #{run.get('id')} "
                     f"({len(topics)} topics):\n" +
                     "\n".join(f"· {t}" for t in topics))]
        self._submit("parsing + launching manager run", _fn)

    def _c_timeline(self, arg: str) -> None:
        if not arg.strip().isdigit():
            self._say("error", "usage: /timeline <run-id>")
            return
        tl = _d(self.client.manager_timeline(int(arg.strip())))
        lines = ["flow: " + " > ".join(str(f) for f in
                                       (tl.get("flow") or []))]
        lines += [f"{e.get('lane')}/{e.get('stage')}: {e.get('message')}"
                  for e in (tl.get("events") or [])[-12:]]
        self._say("text", "\n".join(lines))

    def _c_compile(self, arg: str) -> None:
        if not arg.strip().isdigit():
            self._say("error", "usage: /compile <run-id>")
            return
        rid = int(arg.strip())

        def _fn():
            res = self.client.manager_compile(rid)
            return [(("text", f"compiled artifact "
                      f"#{res.get('artifact_id')}"))]
        self._submit(f"compiling run #{rid}", _fn)

    def _c_report(self, arg: str) -> None:
        bits = arg.split(None, 1)
        if not bits or not bits[0].isdigit():
            self._say("error", "usage: /report <run-id> [path]")
            return
        md = self.client.manager_report_markdown(int(bits[0]))
        if len(bits) > 1:
            with open(bits[1], "w") as f:
                f.write(md)
            self._say("text", f"saved {len(md)} chars to {bits[1]}")
        else:
            head, rest = md[:4000], len(md) - 4000
            self._say("text", head + (f"\n… ({rest} more chars)"
                                      if rest > 0 else ""))

    # -- frame ----------------------------------------------------------
    def _header(self) -> str:
        llm = self.health.get("llm", {}) if self.health else {}
        dot = ("[red]● fallback[/red]" if llm.get("fallback_active")
               else "[green]● axiom[/green]"
               if llm.get("preferred_reachable") else "[yellow]● ?[/yellow]")
        inv = f"inv #{self.inv_id}" if self.inv_id else "no inv"
        jobs = sum(1 for j in self.jobs if j["thread"].is_alive())
        return (f"AKM chat · {inv} · LLM {dot} · "
                f"{jobs} job{'s' if jobs != 1 else ''} · "
                f"[dim]{self.mode} (esc nav)[/dim]")

    def frame(self) -> Group:
        lines: list[Text] = []
        with self.lock:
            blocks = list(self.blocks)
        for b in blocks:
            lines.extend(self._render_block(b))
        budget = max(6, self.console.height - 3)
        total = len(lines)
        self.scroll = max(0, min(self.scroll, max(0, total - budget)))
        end = total - self.scroll
        view = lines[max(0, end - budget):end]
        view = view + [Text("")] * (budget - len(view))
        return Group(self._header(), *view, self._input_line(),
                     self._footer())

    def _input_line(self) -> Text:
        w = max(20, self.console.width - 4)
        if self.mode == "nav":
            return Text.assemble(
                "❯ ", _cell(self.editor.text(), max(10, w - 10)),
                "  [NAV]", style="dim")
        buf = self.editor.text()
        cur = self.editor.cursor
        # Keep the cursor on screen for long lines.
        lo = max(0, cur - (w - 8))
        vis = buf[lo:lo + w - 4]
        cx = cur - lo
        return Text.assemble("❯ ", vis[:cx], ("▊", "reverse"), vis[cx:])

    def _footer(self) -> str:
        if self.mode == "nav":
            return ("[dim]j/k scroll · pgup/pgdn · g/G top/bottom · "
                    "i type · q quit[/dim]")
        return "[dim]enter send · ↑↓ history · esc nav · /help[/dim]"

    # -- input ------------------------------------------------------------
    def key(self, name: str | None) -> bool:
        """One mapped key; False quits."""
        if name is None:
            return True
        if name in ("quit", "eof"):
            return False
        if self.mode == "nav":
            return self._key_nav(name)
        if name == "esc":
            self.mode = "nav"
            return True
        line = self.editor.key(name)
        if line is not None:
            self.submit(line)
        return True

    def _key_nav(self, name: str) -> bool:
        if name in ("i", "/", "enter"):
            self.mode = "insert"
        elif name == "q":
            return False
        elif name in ("j", "down"):
            self.scroll += 1
        elif name in ("k", "up"):
            self.scroll = max(0, self.scroll - 1)
        elif name in ("pgup", "u"):
            self.scroll += 10
        elif name in ("pgdn", "d"):
            self.scroll = max(0, self.scroll - 10)
        elif name == "g":
            self.scroll = 10 ** 9
        elif name == "G":
            self.scroll = 0
        elif name == "r":
            self._poll_header()
        return True

    # -- loop ----------------------------------------------------------------
    def _poll_header(self) -> None:
        try:
            self.health = self.client.health()
        except (ApiError, Exception):
            pass
        self._health_fresh = True

    def _set_raw(self, fd: int) -> None:
        import tty
        tty.setraw(fd)

    def _set_cooked(self, fd: int) -> None:
        if self._term_old is not None:
            import termios
            termios.tcsetattr(fd, termios.TCSADRAIN, self._term_old)

    def run(self) -> int:
        reader = KeyReader()
        if not reader.is_tty():
            self.console.print("chat needs a TTY (stdin is not one)")
            reader.close()
            return 2
        import termios
        try:
            self._term_old = termios.tcgetattr(reader.fd)
        except termios.error:
            self.console.print("chat needs a TTY (stdin is not one)")
            reader.close()
            return 2
        from rich.live import Live
        stop = threading.Event()

        def _poll_loop() -> None:
            while not stop.is_set():
                self._poll_header()
                if stop.wait(HEADER_S):
                    break

        try:
            self._set_raw(reader.fd)
            poller = threading.Thread(target=_poll_loop, daemon=True)
            poller.start()
            with Live(self.frame(), console=self.console,
                      auto_refresh=False, refresh_per_second=4) as live:
                # Redraw only on change: every tick re-rendering the full
                # frame is what flooded scrollback before. Background job
                # threads append blocks at any time; the block-count check
                # picks those up on the next tick.
                dirty = True
                last_n = -1
                while True:
                    self._reap()
                    try:
                        k = reader.key(0.25)
                        cont = self.key(k)
                    except _Quit:
                        return 0
                    if not cont:
                        return 0
                    if k is not None or len(self.blocks) != last_n:
                        dirty = True
                    if self._health_fresh:
                        self._health_fresh = False
                        dirty = True
                    if dirty:
                        live.update(self.frame(), refresh=True)
                        last_n = len(self.blocks)
                        dirty = False
        finally:
            stop.set()
            self._set_cooked(reader.fd)
            reader.close()
            self.console.print("bye")
        return 0


class _Quit(Exception):
    pass
