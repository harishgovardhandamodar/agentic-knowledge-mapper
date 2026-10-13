"""Interactive tabbed dashboard for the agentic workflows.

``python -m cli tui`` opens two tabs over the running web app's API:

* ``1 Research`` (main) -- investigations, research runs, assessments,
  and mermaid diagrams rendered as ASCII (``.mmd`` export included).
* ``2 Ops`` -- runtime logs, LLM gateway info, agent-swarm statuses,
  activity monitor, web-search history, and manager runs.

Everything is read from / written to the shared backend, so CLI work is
visible in the web GUI. Rendering is ``rich`` only (no new dependencies);
keyboard input uses stdlib ``termios`` and degrades to a message when
stdin is not a TTY.
"""

from __future__ import annotations

import select
import sys
import time

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from cli.client import AkMClient, ApiError
from cli.mermaid import diagram_kind, extract_fences, render_ascii, save_mmd

REFRESH_S = 8.0
LOG_TAIL_LINES = 15
LIST_WINDOW = 12
DIAGRAM_MAX_LINES = 18


def _cell(value: object, n: int = 48) -> str:
    """One table cell: None/empty becomes an en dash, rest truncated."""
    if value is None or value == "":
        return "–"
    s = str(value)
    return s if len(s) <= n else s[: n - 1] + "…"


def _d(value: object) -> dict:
    """Coerce an API payload to a dict: a bad shape must never crash a
    frame, it only empties the section."""
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return {"items": value}
    return {}


def _table(title: str, cols: list[tuple[str, int]],
           rows: list[list[str]], highlight: int = -1) -> Table:
    """Compact left-justified table: no full-width stretching, cells wrap
    never (ellipsis instead), so narrow terminals stay readable."""
    t = Table(title=title, box=box.SIMPLE, show_lines=False,
              expand=False, header_style="bold", title_justify="left")
    for name, width in cols:
        t.add_column(name, no_wrap=True, max_width=width,
                     overflow="ellipsis")
    for i, row in enumerate(rows):
        style = "reverse" if i == highlight else ""
        t.add_row(*row, style=style)
    return t


class Dashboard:
    """State + rendering for the two tabs; ``run()`` owns the loop."""

    def __init__(self, client: AkMClient, log_file: str | None = None):
        self.client = client
        self.log_file = log_file
        self.console = Console()
        self.tab = "research"
        self.inv_idx = 0
        self.diagram_idx = 0
        self.mgr_id: int | None = None
        self.scroll = 0
        self.error = ""
        self.note = ""
        self.data: dict = {}
        self.last_fetch = 0.0
        # Research tab is filter-first: the investigations list is only
        # fetched (and only shown) on request, never by auto-refresh.
        self.filter_text = ""
        self._term_old = None

    # -- data ---------------------------------------------------------
    def refresh(self, force: bool = False,
                fetch_list: bool = False) -> None:
        if not force and time.time() - self.last_fetch < 2:
            return
        d: dict = dict(self.data)
        try:
            d["health"] = self.client.health()
            if fetch_list:
                d["investigations"] = self.client.list_investigations()
            d["runs"] = self.client.list_runs()
            d["manager_runs"] = self.client.manager_runs(20)
            d["ledger"] = self.client.ledger_timeline(40)
            d["drops"] = self.client.ledger_audit_drops()
            d["pending"] = self.client.approvals_pending()
            inv = self._selected_inv(d)
            if inv is not None:
                iid = inv.get("id")
                d["summary"] = _d(self.client.investigation_summary(iid))
                d["yields"] = _d(self.client.query_yields(iid))
                d["assessments"] = self.client.list_assessments(iid)
            if self.mgr_id is not None:
                try:
                    d["mgr"] = _d(self.client.manager_get(self.mgr_id))
                    d["mgr_tl"] = _d(self.client.manager_timeline(
                        self.mgr_id))
                except ApiError as e:
                    self.error = str(e)
                    self.mgr_id = None
            self.data = d
            self.error = ""
        except (ApiError, Exception) as e:  # keep stale data on screen
            self.error = str(e)[:160]
        self.last_fetch = time.time()

    def _selected_inv(self, d: dict | None = None) -> dict | None:
        rows = self._filtered(d)
        if not rows:
            return None
        self.inv_idx = max(0, min(self.inv_idx, len(rows) - 1))
        return rows[self.inv_idx]

    def _filtered(self, d: dict | None = None) -> list:
        """Investigations matching the filter; empty filter shows none.

        The list appears only on request (filter submit / r), so the tab
        opens on the input box even with hundreds of rows behind it.
        """
        rows = (d or self.data).get("investigations", [])
        f = self.filter_text.strip().lower()
        if not f:
            return []
        return [r for r in rows if f in " ".join(
            str((r.get(k) if isinstance(r, dict) else "") or "")
            for k in ("id", "title", "keywords", "description",
                      "status")).lower()]

    # -- header / footer ------------------------------------------------
    def _llm_dot(self) -> str:
        llm = (self.data.get("health", {}) or {}).get("llm", {})
        if llm.get("fallback_active"):
            return "[red]● fallback[/red]"
        if llm.get("preferred_reachable"):
            return "[green]● axiom[/green]"
        return "[yellow]● ?[/yellow]"

    def _header(self) -> Panel:
        llm = (self.data.get("health", {}) or {}).get("llm", {})
        served = llm.get("served_by") or llm.get("preferred_url") or "?"
        host = served.replace("http://", "").replace("https://", "")
        host = host.split("/")[0]
        return Panel(
            f"AKM CLI  {self.client.base_url}   LLM {self._llm_dot()} "
            f"via {host}" + (f"   [red]{self.error}[/red]"
                             if self.error else "")
            + (f"   [green]{self.note}[/green]" if self.note else ""),
            style="bold")

    def _tabs(self) -> str:
        r = "[reverse] 1 Research [/reverse]" \
            if self.tab == "research" else " 1 Research "
        o = "[reverse] 2 Ops [/reverse]" \
            if self.tab == "ops" else " 2 Ops "
        return r + " " + o + "  [dim](shares the web app's database)[/dim]"

    def _footer(self) -> str:
        if self.console.width >= 100:
            if self.tab == "research":
                return ("1/2 tabs · / filter · ↑↓ select · l launch · "
                        "n new · d diagram · s save · r refresh · q quit")
            return ("1/2 tabs · j/k scroll · m run · c compile · "
                    "r refresh · q quit")
        if self.tab == "research":
            return ("1/2 · / filt · ↑↓ move · l launch · n new · "
                    "d dia · s save · r refr · q quit")
        return "1/2 · j/k scroll · m run · c comp · r refr · q quit"

    # -- research tab ----------------------------------------------------
    def _research_body(self) -> Group:
        rows = self._filtered()
        w = self.console.width
        total = len(self.data.get("investigations", []))
        filt = self.filter_text
        box_line = (f"Filter: [ {filt} ]  ({len(rows)} match"
                    f"{'' if len(rows) == 1 else 'es'}"
                    f"{f' of {total}' if total else ''})  "
                    f"[dim]/ edit · esc clear · r reload list[/dim]")
        if not filt.strip():
            return Group(
                box_line,
                Panel("Type / and enter text to list matching "
                      "investigations (id / title / keywords / status). "
                      "The list loads only on request.",
                      title="investigations"))
        start = max(0, min(self.inv_idx - LIST_WINDOW // 2,
                           max(0, len(rows) - LIST_WINDOW)))
        view = rows[start:start + LIST_WINDOW]
        inv_rows = [[_cell(r.get("id"), 6), _cell(r.get("title"), w - 30),
                     _cell(r.get("status"), 10)] for r in view]
        left = _table(f"matches ({len(rows)})",
                      [("id", 6), ("title", max(20, w - 30)),
                       ("status", 10)],
                      inv_rows, highlight=self.inv_idx - start)
        left.caption = (f"row {self.inv_idx + 1}/{len(rows)} (↑↓)"
                        if rows else None)
        inv = self._selected_inv()
        if inv is None:
            return Group(box_line, left,
                         Panel("no matches — edit the filter (/)"))
        iid = inv.get("id")
        runs = [r for r in self.data.get("runs", [])
                if r.get("investigation_id") == iid][:8]
        run_rows = [[_cell(r.get("id"), 6), _cell(r.get("trigger"), 24),
                     _cell(r.get("status"), 12)] for r in runs]
        summ = self.data.get("summary", {})
        assess = self.data.get("assessments", [])
        parts: list = [
            box_line,
            left,
            Panel(f"[bold]#{iid} {_cell(inv.get('title'), w - 12)}"
                  f"[/bold]\n{_cell(summ.get('summary') or summ, 400)}",
                  title="detail"),
            _table(f"research runs ({len(run_rows)})",
                   [("id", 6), ("trigger", 24), ("status", 12)], run_rows),
            _table(f"assessments ({len(assess)})",
                   [("id", 6), ("product", 34), ("residual", 10)],
                   [[_cell(a.get("id"), 6),
                     _cell(a.get("product_name"), 34),
                     _cell(a.get("residual_pct",
                                 a.get("overall_pct")), 10)]
                    for a in assess[:8]]),
            self._diagram_panel(),
        ]
        return Group(*parts)

    def _diagram_sources(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for a in self.data.get("assessments", []):
            if not isinstance(a, dict):
                continue
            stored = a.get("diagrams") or {}
            if isinstance(stored, dict):
                out.extend((str(k), v) for k, v in stored.items()
                           if isinstance(v, str))
            md = a.get("markdown") or ""
            if isinstance(md, str):
                out.extend(extract_fences(md))
        return out

    def _diagram_panel(self) -> Panel:
        srcs = self._diagram_sources()
        if not srcs:
            return Panel("no diagrams (assess the product first)",
                         title="diagram")
        w = max(40, self.console.width - 6)
        self.diagram_idx %= len(srcs)
        key, src = srcs[self.diagram_idx]
        head = (f"[bold]{_cell(key, 40)}[/bold] "
                f"({diagram_kind(src)}; "
                f"{self.diagram_idx + 1}/{len(srcs)})")
        art = render_ascii(src, width=w)
        if art is None:
            return Panel(Group(head, Syntax(src[:3000], "text",
                                            word_wrap=True)),
                         title="diagram")
        lines = [ln[:w] for ln in art.splitlines()][
            :DIAGRAM_MAX_LINES]
        return Panel(head + "\n" + "\n".join(lines), title="diagram")

    # -- ops tab ----------------------------------------------------------
    def _ops_sections(self) -> Group:
        llm = (self.data.get("health", {}) or {}).get("llm", {})
        llm_rows = [[k, _cell(llm.get(k), 56)] for k in
                    ("preferred_url", "served_by", "reachable",
                     "preferred_reachable", "fallback_active", "notice",
                     "model", "fallback_uses", "last_fallback_at")]
        return Group(
            _table("LLM gateway", [("key", 20), ("value", 56)], llm_rows),
            self._swarm_panel(),
            self._manager_panel(),
            self._activity_panel(),
            self._searches_panel(),
            self._logs_panel())

    def _swarm_panel(self) -> Table:
        rows = self.data.get("runs", [])[:12]
        return _table(f"agent swarm ({len(rows)} runs)",
                      [("id", 6), ("inv", 6), ("trigger", 20),
                       ("status", 12), ("finished", 16)],
                      [[_cell(r.get("id"), 6),
                        _cell(r.get("investigation_id"), 6),
                        _cell(r.get("trigger"), 20),
                        _cell(r.get("status"), 12),
                        _cell(r.get("finished_at"), 16)] for r in rows])

    def _manager_panel(self) -> Table:
        rows = self.data.get("manager_runs", [])[:8]
        table_rows = []
        for r in rows:
            mark = "> " if r.get("id") == self.mgr_id else "  "
            table_rows.append(
                [mark + _cell(r.get("id"), 5),
                 _cell(r.get("status"), 10),
                 _cell(r.get("compiled"), 8),
                 _cell(r.get("command"), 52)])
        t = _table("manager (m select, c compile)",
                   [("id", 8), ("status", 10), ("compiled", 8),
                    ("command", 52)],
                   table_rows)
        mgr = self.data.get("mgr")
        if isinstance(mgr, dict) and mgr:
            flow = " > ".join(str(f) for f in
                               (_d(self.data.get("mgr_tl")).get("flow")
                                or []))
            t.caption = (f"run #{mgr.get('id')} "
                         f"{mgr.get('status')}/{mgr.get('compiled')}: "
                         f"{flow}"[:110])
        return t

    def _activity_panel(self) -> Table:
        rows = (self.data.get("ledger", []) or [])[-12:]
        return _table("activity monitor (ledger tail)",
                      [("ts", 19), ("actor", 22), ("kind", 18),
                       ("verdict", 8)],
                      [[_cell(r.get("ts"), 19),
                        _cell(f"{r.get('actor_type')}:"
                              f"{r.get('actor')}", 22),
                        _cell(r.get("kind"), 18),
                        _cell(r.get("verdict"), 8)] for r in rows])

    def _searches_panel(self) -> Table:
        yields = _d(self.data.get("yields"))
        shapes = yields.get("shapes") or yields.get("items") or []
        return _table("web-search history (query shapes)",
                      [("shape", 50), ("att", 5), ("found", 6),
                       ("kept", 5)],
                      [[_cell(s.get("shape"), 50),
                        _cell(s.get("attempts"), 5),
                        _cell(s.get("found"), 6),
                        _cell(s.get("kept"), 5)]
                       for s in shapes[:10]])

    def _logs_panel(self) -> Panel:
        lines: list[str] = []
        drops = self.data.get("drops", []) or []
        for d in drops[-6:]:
            lines.append(f"DROP {d.get('run_id')} {d.get('actor')}: "
                         f"{_cell(d.get('error'), 90)}")
        pending = self.data.get("pending", []) or []
        if pending:
            lines.append(f"{len(pending)} approval(s) pending")
        if self.log_file:
            try:
                with open(self.log_file) as f:
                    tail = f.readlines()[-LOG_TAIL_LINES:]
                lines.append(f"--- {self.log_file} (tail) ---")
                lines.extend(ln.rstrip()[:120] for ln in tail)
            except OSError as e:
                lines.append(f"log file unreadable: {e}")
        return Panel("\n".join(lines) or "runtime logs: clean",
                     title="runtime logs")

    # -- frame + input -----------------------------------------------------
    def frame(self) -> Group:
        """Fitted frame: body sliced/padded to the exact visible height.

        The list is windowed around the selection (research) or scrolled
        (ops), then padded with blanks so every frame has a constant
        shape. Constant shape lets rich redraw in place instead of
        flooding scrollback, and no frame ever overflows the screen.
        """
        chrome = 5  # header panel (3) + tabs (1) + footer (1)
        budget = max(6, self.console.height - chrome)
        with self.console.capture() as cap:
            self.console.print(
                self._research_body() if self.tab == "research"
                else self._ops_sections())
        lines = cap.get().splitlines()
        if self.tab == "ops":
            total = len(lines)
            self.scroll = max(0, min(self.scroll, max(0, total - budget)))
            view = lines[self.scroll:self.scroll + budget]
            pos = (f"  [dim]lines {self.scroll + 1}-"
                   f"{self.scroll + len(view)} of {total} (j/k)[/dim]"
                   if total > budget else "")
        else:
            view = lines[:budget]
            pos = ""
        view = view + [""] * (budget - len(view))
        return Group(self._header(), self._tabs(), "\n".join(view),
                     self._footer() + pos)

    def _set_raw(self) -> None:
        import tty
        tty.setraw(sys.stdin.fileno())

    def _set_cooked(self) -> None:
        if self._term_old is not None:
            import termios
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN,
                              self._term_old)

    def _prompt(self, live, text: str) -> str:
        """Line input with echo: raw mode (no echo, CR instead of LF)
        would make typing blind, so cook the terminal for the prompt."""
        live.stop()
        self._set_cooked()
        try:
            self.console.print(text, end="")
            return sys.stdin.readline().rstrip("\n")
        finally:
            self._set_raw()
            live.start()

    def act(self, live, key: str) -> bool:
        """Handle one key; return False to quit."""
        if key in ("q", "\x03"):
            return False
        self.note = ""  # each keypress retires the previous message
        if key == "1":
            self.tab, self.scroll = "research", 0
        elif key == "2":
            self.tab, self.scroll = "ops", 0
        elif key == "r":
            # On research, r also (re)loads the list behind the filter;
            # auto-refresh never fetches it.
            self.refresh(force=True,
                         fetch_list=(self.tab == "research"))
        elif self.tab == "research":
            return self._act_research(live, key)
        else:
            return self._act_ops(live, key)
        return True

    def _act_research(self, live, key: str) -> bool:
        rows = self._filtered()
        if key == "up":
            self.inv_idx = max(0, self.inv_idx - 1)
            self.diagram_idx = 0
        elif key == "down":
            self.inv_idx = min(max(0, len(rows) - 1), self.inv_idx + 1)
            self.diagram_idx = 0
        elif key in ("/", "f"):
            text = self._prompt(
                live, "filter (id/title/keywords/status): ")
            self.filter_text = text.strip()
            self.inv_idx = 0
            self.diagram_idx = 0
            self.refresh(force=True, fetch_list=True)
        elif key == "esc":
            self.filter_text = ""
            self.inv_idx = 0
            self.diagram_idx = 0
        elif key == "d":
            if self._diagram_sources():
                self.diagram_idx += 1
        elif key == "s":
            srcs = self._diagram_sources()
            if srcs:
                self.diagram_idx %= len(srcs)
                path = self._prompt(
                    live, "save .mmd to [diagrams/ + key]: ")
                if path.strip():
                    self.note = "saved " + save_mmd(
                        srcs[self.diagram_idx][1], path.strip())
                    self.refresh(force=True)
        elif key == "l":
            inv = self._selected_inv()
            if inv is not None:
                try:
                    self.client.launch_run(inv["id"])
                    self.note = f"launched run for #{inv['id']}"
                except (ApiError, Exception) as e:
                    self.error = str(e)[:160]
                self.refresh(force=True)
        elif key == "n":
            title = self._prompt(live, "title: ")
            if title.strip():
                desc = self._prompt(live, "description: ")
                kw = self._prompt(live, "keywords: ")
                try:
                    inv = self.client.create_investigation(
                        title.strip(), desc, kw)
                    self.note = f"created #{inv.get('id')} " \
                        "(also in the web app)"
                except (ApiError, Exception) as e:
                    self.error = str(e)[:160]
                self.refresh(force=True, fetch_list=True)
        return True

    def _act_ops(self, live, key: str) -> bool:
        if key == "j":
            self.scroll += 5
        elif key == "k":
            self.scroll = max(0, self.scroll - 5)
        elif key == "m":
            raw = self._prompt(live, "manager run id: ")
            if raw.strip().isdigit():
                self.mgr_id = int(raw.strip())
                self.refresh(force=True)
        elif key == "c":
            if self.mgr_id is not None:
                self.note = f"compiling #{self.mgr_id} (slow)…"
                live.update(self.frame())
                try:
                    res = self.client.manager_compile(self.mgr_id)
                    self.note = (f"compiled artifact "
                                 f"#{res.get('artifact_id')}")
                except (ApiError, Exception) as e:
                    self.error = str(e)[:160]
                self.refresh(force=True)
        return True

    def run(self) -> int:
        if not sys.stdin.isatty():
            self.console.print("tui needs a TTY (stdin is not one)")
            return 2
        import termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        self._term_old = old
        from rich.live import Live
        self.refresh(force=True)
        try:
            self._set_raw()
            with Live(self.frame(), console=self.console,
                      auto_refresh=False, refresh_per_second=2) as live:
                while True:
                    if time.time() - self.last_fetch > REFRESH_S:
                        self.refresh()
                        live.update(self.frame())
                    key = _read_key(0.25)
                    if key is None:
                        continue
                    if not self.act(live, key):
                        return 0
                    live.update(self.frame())
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            self.console.print("bye")
        return 0


def _read_key(timeout_s: float) -> str | None:
    """Read one key (arrows mapped); None on timeout."""
    r, _, _ = select.select([sys.stdin], [], [], timeout_s)
    if not r:
        return None
    ch = sys.stdin.read(1)
    if ch == "\x1b":
        r, _, _ = select.select([sys.stdin], [], [], 0.05)
        seq = sys.stdin.read(2) if r else ""
        return {"[A": "up", "[B": "down", "[C": "right",
                "[D": "left"}.get(seq, "esc")
    if ch in ("\r", "\n"):
        return "enter"
    return ch
