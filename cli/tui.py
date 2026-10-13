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

from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from cli.client import AkMClient, ApiError
from cli.mermaid import diagram_kind, extract_fences, render_ascii, save_mmd

REFRESH_S = 8.0
LOG_TAIL_LINES = 15


def _table(title: str, cols: list[str], rows: list[list[str]],
           highlight: int = -1) -> Table:
    t = Table(title=title, show_lines=False, expand=True)
    for c in cols:
        t.add_column(c, overflow="fold")
    for i, row in enumerate(rows):
        style = "reverse" if i == highlight else ""
        t.add_row(*row, style=style)
    return t


def _short(value: object, n: int = 64) -> str:
    s = "" if value is None else str(value)
    return s if len(s) <= n else s[: n - 1] + "…"


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

    # -- data ---------------------------------------------------------
    def refresh(self, force: bool = False) -> None:
        if not force and time.time() - self.last_fetch < 2:
            return
        d: dict = {}
        try:
            d["health"] = self.client.health()
            d["investigations"] = self.client.list_investigations()
            d["runs"] = self.client.list_runs()
            d["manager_runs"] = self.client.manager_runs(20)
            d["ledger"] = self.client.ledger_timeline(40)
            d["drops"] = self.client.ledger_audit_drops()
            d["pending"] = self.client.approvals_pending()
            inv = self._selected_inv(d)
            if inv is not None:
                iid = inv.get("id")
                d["summary"] = self.client.investigation_summary(iid)
                d["yields"] = self.client.query_yields(iid)
                d["assessments"] = self.client.list_assessments(iid)
            if self.mgr_id is not None:
                try:
                    d["mgr"] = self.client.manager_get(self.mgr_id)
                    d["mgr_tl"] = self.client.manager_timeline(
                        self.mgr_id)
                except ApiError as e:
                    self.error = str(e)
                    self.mgr_id = None
            self.data = d
            self.error = ""
        except (ApiError, Exception) as e:  # keep stale data on screen
            self.error = str(e)[:160]
        self.last_fetch = time.time()

    def _selected_inv(self, d: dict | None = None) -> dict | None:
        rows = (d or self.data).get("investigations", [])
        if not rows:
            return None
        self.inv_idx = max(0, min(self.inv_idx, len(rows) - 1))
        return rows[self.inv_idx]

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
        return r + " " + o + ("   CLI shares the web app's database: "
                              "everything here is visible in the GUI.")

    def _footer(self) -> str:
        if self.tab == "research":
            return ("1/2 tabs · ↑↓ select · l launch run · n new · "
                    "d next diagram · s save .mmd · r refresh · q quit")
        return ("1/2 tabs · j/k scroll · m manager run · c compile · "
                "r refresh · q quit")

    # -- research tab ----------------------------------------------------
    def _research_body(self) -> Group:
        rows = self.data.get("investigations", [])
        inv_rows = [[str(r.get("id")), _short(r.get("title"), 46),
                     str(r.get("status", "?"))] for r in rows]
        left = _table(f"investigations ({len(rows)})",
                      ["id", "title", "status"], inv_rows,
                      highlight=self.inv_idx)
        inv = self._selected_inv()
        if inv is None:
            return Group(left, Panel("no investigations yet (n)"))
        iid = inv.get("id")
        runs = [r for r in self.data.get("runs", [])
                if r.get("investigation_id") == iid][:8]
        run_rows = [[str(r.get("id")), str(r.get("trigger")),
                     str(r.get("status"))] for r in runs]
        summ = self.data.get("summary", {})
        assess = self.data.get("assessments", [])
        parts: list = [
            Panel(f"[bold]#{iid} {inv.get('title')}[/bold]\n"
                  f"{_short(summ.get('summary') or summ, 500)}",
                  title="detail"),
            _table(f"research runs ({len(run_rows)})",
                   ["id", "trigger", "status"], run_rows),
            _table(f"assessments ({len(assess)})",
                   ["id", "product", "residual"],
                   [[str(a.get("id")), _short(a.get("product_name"), 34),
                     str(a.get("residual_pct",
                               a.get("overall_pct", "?")))]
                    for a in assess[:8]]),
            self._diagram_panel(),
        ]
        return Group(left, *parts)

    def _diagram_sources(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for a in self.data.get("assessments", []):
            stored = a.get("diagrams") or {}
            if isinstance(stored, dict):
                out.extend((str(k), str(v)) for k, v in stored.items())
            out.extend(extract_fences(a.get("markdown") or ""))
        return out

    def _diagram_panel(self) -> Panel:
        srcs = self._diagram_sources()
        if not srcs:
            return Panel("no diagrams (assess the product first)",
                         title="diagram")
        self.diagram_idx %= len(srcs)
        key, src = srcs[self.diagram_idx]
        art = render_ascii(src)
        body = art if art is not None else src[:3000]
        if art is None:
            return Panel(Group(
                f"[bold]{key}[/bold] ({diagram_kind(src)}; "
                f"{self.diagram_idx + 1}/{len(srcs)})",
                Syntax(body, "text")), title="diagram")
        return Panel(f"[bold]{key}[/bold] ({diagram_kind(src)}; "
                     f"{self.diagram_idx + 1}/{len(srcs)})\n{body}",
                     title="diagram")

    # -- ops tab ----------------------------------------------------------
    def _ops_body(self) -> Group:
        llm = (self.data.get("health", {}) or {}).get("llm", {})
        llm_rows = [[k, _short(llm.get(k), 60)] for k in
                    ("preferred_url", "served_by", "reachable",
                     "preferred_reachable", "fallback_active", "notice",
                     "model", "fallback_uses", "last_fallback_at")]
        parts: list = [
            _table("LLM gateway", ["key", "value"], llm_rows),
            self._swarm_panel(),
            self._manager_panel(),
            self._activity_panel(),
            self._searches_panel(),
            self._logs_panel(),
        ]
        joined: list[str] = []
        for p in parts:
            with self.console.capture() as cap:
                self.console.print(p)
            joined.extend(cap.get().splitlines())
        window = joined[self.scroll:self.scroll + 60]
        return Group("\n".join(window),
                     f"[dim]line {self.scroll + 1}-{self.scroll + 60} "
                     f"of {len(joined)} (j/k scroll)[/dim]")

    def _swarm_panel(self) -> Table:
        rows = self.data.get("runs", [])[:25]
        return _table(f"agent swarm ({len(rows)} runs)",
                      ["id", "inv", "trigger", "status", "finished"],
                      [[str(r.get("id")),
                        str(r.get("investigation_id")),
                        _short(r.get("trigger"), 18),
                        str(r.get("status")),
                        _short(r.get("finished_at"), 16)] for r in rows])

    def _manager_panel(self) -> Table:
        rows = self.data.get("manager_runs", [])
        table_rows = []
        for r in rows[:12]:
            mark = ">" if r.get("id") == self.mgr_id else " "
            table_rows.append(
                [mark + str(r.get("id")), str(r.get("status")),
                 str(r.get("compiled")), _short(r.get("command"), 52)])
        t = _table("manager (m select, c compile)",
                   ["", "id", "status", "compiled", "command"],
                   [[r[0], r[0].strip(), r[1], r[2], r[3]]
                    for r in table_rows])
        mgr = self.data.get("mgr")
        if mgr is not None:
            flow = " > ".join(str(f) for f in
                               (self.data.get("mgr_tl", {}).get("flow")
                                or []))
            t.caption = (f"run #{mgr.get('id')} "
                         f"{mgr.get('status')}/{mgr.get('compiled')}: "
                         f"{flow}"[:120])
        return t

    def _activity_panel(self) -> Table:
        rows = (self.data.get("ledger", []) or [])[-18:]
        return _table("activity monitor (ledger tail)",
                      ["ts", "actor", "kind", "verdict"],
                      [[_short(r.get("ts"), 19),
                        _short(f"{r.get('actor_type')}:"
                               f"{r.get('actor')}", 24),
                        _short(r.get("kind"), 20),
                        str(r.get("verdict"))] for r in rows])

    def _searches_panel(self) -> Table:
        yields = self.data.get("yields", {}) or {}
        shapes = yields.get("shapes") or yields.get("items") or []
        return _table("web-search history (query shapes)",
                      ["shape", "att", "found", "kept"],
                      [[_short(s.get("shape"), 52),
                        str(s.get("attempts", "?")),
                        str(s.get("found", "?")),
                        str(s.get("kept", "?"))]
                       for s in shapes[:12]])

    def _logs_panel(self) -> Panel:
        lines: list[str] = []
        drops = self.data.get("drops", []) or []
        for d in drops[-6:]:
            lines.append(f"DROP {d.get('run_id')} {d.get('actor')}: "
                         f"{_short(d.get('error'), 90)}")
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
        self.note = ""
        body = self._research_body() if self.tab == "research" \
            else self._ops_body()
        return Group(self._header(), self._tabs(), body, self._footer())

    def _prompt(self, live, text: str) -> str:
        live.stop()
        try:
            self.console.print(text, end="")
            return sys.stdin.readline().rstrip("\n")
        finally:
            live.start()

    def act(self, live, key: str) -> bool:
        """Handle one key; return False to quit."""
        if key in ("q", "\x03"):
            return False
        if key == "1":
            self.tab, self.scroll = "research", 0
        elif key == "2":
            self.tab, self.scroll = "ops", 0
        elif key == "r":
            self.refresh(force=True)
        elif self.tab == "research":
            return self._act_research(live, key)
        else:
            return self._act_ops(live, key)
        return True

    def _act_research(self, live, key: str) -> bool:
        rows = self.data.get("investigations", [])
        if key == "up":
            self.inv_idx = max(0, self.inv_idx - 1)
            self.diagram_idx = 0
        elif key == "down":
            self.inv_idx = min(max(0, len(rows) - 1), self.inv_idx + 1)
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
                self.refresh(force=True)
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
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        from rich.live import Live
        self.refresh(force=True)
        try:
            tty.setraw(fd)
            with Live(self.frame(), console=self.console,
                      refresh_per_second=2) as live:
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
