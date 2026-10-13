"""Scriptable CLI commands over the web app's API.

Every command talks to the running server (``AKM_API_URL`` or
``--api``), so anything created here is stored in the shared database
and is viewable in the web GUI. Run ``python -m cli --help``.
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from cli import CLI_VERSION, DEFAULT_API_URL
from cli.client import AkMClient, ApiError
from cli.mermaid import diagram_kind, extract_fences, render_ascii, save_mmd

console = Console()


def _client(api: str) -> AkMClient:
    return AkMClient(base_url=api or DEFAULT_API_URL)


def _table(title: str, cols: list[str]) -> Table:
    t = Table(title=title, show_lines=False)
    for c in cols:
        t.add_column(c)
    return t


@click.group()
@click.option("--api", default=DEFAULT_API_URL, show_default=True,
              help="Web app base URL (env AKM_API_URL wins when set).")
@click.version_option(CLI_VERSION, prog_name="akm")
@click.pass_context
def main(ctx: click.Context, api: str) -> None:
    """Agentic-workflows CLI: research, diagrams, manager, ops."""
    ctx.obj = {"api": api}


@main.command()
@click.pass_context
def health(ctx: click.Context) -> None:
    """Show LLM gateway health (preferred, fallback, models)."""
    try:
        info = _client(ctx.obj["api"]).llm_info()
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    t = _table("LLM", ["key", "value"])
    for k in ("preferred_url", "served_by", "reachable",
              "preferred_reachable", "fallback_active", "notice",
              "model", "fallback_model", "model_available",
              "fallback_uses", "last_fallback_at", "last_fallback_base"):
        t.add_row(k, str(info.get(k)))
    models = info.get("models") or []
    t.add_row("models", ", ".join(str(m) for m in models[:12]))
    console.print(t)


@main.group()
def research() -> None:
    """Investigations and research runs."""


@research.command("list")
@click.pass_context
def research_list(ctx: click.Context) -> None:
    """List investigations (same rows the web app shows)."""
    try:
        rows = _client(ctx.obj["api"]).list_investigations()
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    t = _table(f"investigations ({len(rows)})",
               ["id", "title", "status", "runs", "artifacts"])
    for r in rows:
        t.add_row(str(r.get("id")), str(r.get("title"))[:60],
                  str(r.get("status", "?")), str(r.get("runs", "?")),
                  str(r.get("artifacts", "?")))
    console.print(t)


@research.command("new")
@click.option("--title", prompt=True)
@click.option("--description", default="")
@click.option("--keywords", default="")
@click.option("--sources", default="web")
@click.pass_context
def research_new(ctx: click.Context, title: str, description: str,
                 keywords: str, sources: str) -> None:
    """Create an investigation (viewable in the web app)."""
    try:
        inv = _client(ctx.obj["api"]).create_investigation(
            title, description, keywords, sources)
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    console.print(f"created investigation #{inv.get('id')}: "
                  f"{inv.get('title')}")


@research.command("launch")
@click.argument("inv_id", type=int)
@click.pass_context
def research_launch(ctx: click.Context, inv_id: int) -> None:
    """Launch a research run for an investigation (fire-and-forget)."""
    try:
        res = _client(ctx.obj["api"]).launch_run(inv_id)
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    console.print(f"launched: {res}")


@research.command("show")
@click.argument("inv_id", type=int)
@click.pass_context
def research_show(ctx: click.Context, inv_id: int) -> None:
    """Show an investigation: summary, runs, search shapes, diagrams."""
    c = _client(ctx.obj["api"])
    try:
        inv = c.get_investigation(inv_id)
        summ = c.investigation_summary(inv_id)
        yields = c.query_yields(inv_id)
        overview = c.artifacts_overview(inv_id)
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    console.print(f"[bold]#{inv.get('id')} {inv.get('title')}[/bold] "
                  f"({inv.get('status', '?')})")
    console.print(str(summ.get("summary") or summ)[:2000])
    shapes = yields.get("shapes") or yields.get("items") or []
    if shapes:
        t = _table(f"web-search shapes ({len(shapes)})",
                   ["shape", "attempts", "found", "kept"])
        for s in shapes[:20]:
            t.add_row(str(s.get("shape"))[:60],
                      str(s.get("attempts", "?")),
                      str(s.get("found", "?")), str(s.get("kept", "?")))
        console.print(t)
    counts = overview.get("counts") or overview
    console.print(f"artifacts: {counts}")


@main.group()
def diagrams() -> None:
    """Mermaid diagrams: ASCII render or save the .mmd source."""


def _diagram_sources(client: AkMClient, scope: str, ref: int) -> list:
    """Collect ``(key, source)`` fences for an investigation or run."""
    out: list[tuple[str, str]] = []
    if scope == "investigation":
        for a in client.list_assessments(ref):
            stored = a.get("diagrams") or {}
            if isinstance(stored, dict):
                out.extend((str(k), str(v)) for k, v in stored.items())
            md = a.get("markdown") or ""
            out.extend(extract_fences(md))
    elif scope == "run":
        report = client.manager_report(ref)
        for d in report.get("diagrams") or []:
            if isinstance(d, dict) and d.get("source"):
                out.append((str(d.get("key", f"diagram-{len(out) + 1}")),
                            str(d["source"])))
        out.extend(extract_fences(report.get("markdown") or ""))
    return out


@diagrams.command("show")
@click.argument("scope", type=click.Choice(["investigation", "run"]))
@click.argument("ref", type=int)
@click.option("--index", "-i", type=int, default=0,
              help="Which diagram to render.")
@click.option("--save", type=click.Path(), default=None,
              help="Also save the .mmd source to this path.")
@click.pass_context
def diagrams_show(ctx: click.Context, scope: str, ref: int, index: int,
                  save: str | None) -> None:
    """Render one diagram as ASCII (falls back to source)."""
    c = _client(ctx.obj["api"])
    try:
        sources = _diagram_sources(c, scope, ref)
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    if not sources:
        console.print("no mermaid diagrams found")
        return
    key, src = sources[index % len(sources)]
    console.print(f"[bold]{key}[/bold] ({diagram_kind(src)}; "
                  f"{index % len(sources) + 1}/{len(sources)})")
    art = render_ascii(src)
    if art is None:
        console.print(Syntax(src, "text"))
    else:
        console.print(art)
    if save:
        console.print(f"saved {save_mmd(src, save)}")


@main.group()
def manager() -> None:
    """Agentic manager: parse, launch, watch, compile."""


@manager.command("list")
@click.option("--limit", type=int, default=20)
@click.pass_context
def manager_list(ctx: click.Context, limit: int) -> None:
    """List manager runs (same rows as the web app)."""
    try:
        rows = _client(ctx.obj["api"]).manager_runs(limit)
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    t = _table(f"manager runs ({len(rows)})",
               ["id", "status", "compiled", "command"])
    for r in rows:
        t.add_row(str(r.get("id")), str(r.get("status")),
                  str(r.get("compiled")),
                  str(r.get("command") or "")[:70])
    console.print(t)


@manager.command("launch")
@click.argument("command_text")
@click.option("--no-research", is_flag=True, default=False)
@click.option("--no-assessment", is_flag=True, default=False)
@click.pass_context
def manager_launch(ctx: click.Context, command_text: str,
                   no_research: bool, no_assessment: bool) -> None:
    """Parse a command and launch the run (visible in the web app)."""
    c = _client(ctx.obj["api"])
    try:
        plan = c.manager_parse(command_text)
        run = c.manager_run(plan, command_text, {
            "research": not no_research,
            "assessment": not no_assessment})
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    console.print(f"launched run #{run.get('id')} "
                  f"({len(plan.get('topics', []))} topics)")


@manager.command("timeline")
@click.argument("run_id", type=int)
@click.pass_context
def manager_timeline(ctx: click.Context, run_id: int) -> None:
    """Show the run timeline flow (command/plan/topics/.../summary)."""
    try:
        tl = _client(ctx.obj["api"]).manager_timeline(run_id)
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    flow = tl.get("flow") or []
    console.print("flow: " + " > ".join(str(f) for f in flow))
    t = _table(f"timeline ({len(tl.get('events', []))} events)",
               ["lane", "stage", "message"])
    for e in (tl.get("events") or [])[-40:]:
        t.add_row(str(e.get("lane")), str(e.get("stage")),
                  str(e.get("message"))[:80])
    console.print(t)


@manager.command("compile")
@click.argument("run_id", type=int)
@click.pass_context
def manager_compile(ctx: click.Context, run_id: int) -> None:
    """Compile a finished run (long call; 20 min budget)."""
    try:
        res = _client(ctx.obj["api"]).manager_compile(run_id)
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    console.print(f"compiled: artifact #{res.get('artifact_id')} "
                  f"(existing={res.get('existing', False)})")


@manager.command("report")
@click.argument("run_id", type=int)
@click.option("--save", type=click.Path(), default=None)
@click.pass_context
def manager_report(ctx: click.Context, run_id: int,
                   save: str | None) -> None:
    """Fetch the compiled markdown report, optionally saving it."""
    try:
        md = _client(ctx.obj["api"]).manager_report_markdown(run_id)
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    if save:
        with open(save, "w") as f:
            f.write(md)
        console.print(f"saved {len(md)} chars to {save}")
    else:
        console.print(md[:6000])


@main.group()
def ops() -> None:
    """Runtime: swarm, searches, activity, ledger, logs."""


@ops.command("swarm")
@click.pass_context
def ops_swarm(ctx: click.Context) -> None:
    """Agent-run swarm statuses."""
    try:
        rows = _client(ctx.obj["api"]).list_runs()
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    t = _table(f"agent runs ({len(rows)})",
               ["id", "inv", "trigger", "status", "started", "finished"])
    for r in rows[:40]:
        t.add_row(str(r.get("id")), str(r.get("investigation_id")),
                  str(r.get("trigger")), str(r.get("status")),
                  str(r.get("started_at") or "")[:16],
                  str(r.get("finished_at") or "")[:16])
    console.print(t)


@ops.command("searches")
@click.argument("inv_id", type=int)
@click.pass_context
def ops_searches(ctx: click.Context, inv_id: int) -> None:
    """Web-search history shapes for an investigation."""
    try:
        data = _client(ctx.obj["api"]).query_yields(inv_id)
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    shapes = data.get("shapes") or data.get("items") or []
    t = _table(f"search shapes ({len(shapes)})",
               ["shape", "attempts", "found", "kept", "llm_calls"])
    for s in shapes:
        t.add_row(str(s.get("shape"))[:64],
                  str(s.get("attempts", "?")),
                  str(s.get("found", "?")), str(s.get("kept", "?")),
                  str(s.get("llm_calls", "?")))
    console.print(t)


@ops.command("activity")
@click.option("--limit", type=int, default=30)
@click.pass_context
def ops_activity(ctx: click.Context, limit: int) -> None:
    """Ledger activity tail (agent/llm/mcp calls with verdicts)."""
    try:
        rows = _client(ctx.obj["api"]).ledger_timeline(limit)
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    t = _table(f"activity ({len(rows)})",
               ["ts", "actor", "kind", "verdict", "intent"])
    for r in rows[-limit:]:
        t.add_row(str(r.get("ts") or "")[:19],
                  f"{r.get('actor_type')}:{r.get('actor')}",
                  str(r.get("kind")), str(r.get("verdict")),
                  str(r.get("intent") or "")[:60])
    console.print(t)


@ops.command("logs")
@click.option("--log-file", default=None,
              help="Tail a local server log file (e.g. uvicorn output).")
@click.option("--lines", "-n", type=int, default=30)
@click.pass_context
def ops_logs(ctx: click.Context, log_file: str | None,
             lines: int) -> None:
    """Runtime logs: ledger audit-drops plus an optional log-file tail."""
    c = _client(ctx.obj["api"])
    try:
        drops = c.ledger_audit_drops()
        pending = c.approvals_pending()
    except (ApiError, Exception) as e:
        raise click.ClickException(str(e)) from e
    if drops:
        t = _table(f"audit drops ({len(drops)})",
                   ["run", "actor", "error"])
        for d in drops[-20:]:
            t.add_row(str(d.get("run_id")), str(d.get("actor")),
                      str(d.get("error") or "")[:80])
        console.print(t)
    else:
        console.print("no audit drops")
    if pending:
        console.print(f"{len(pending)} approval(s) pending")
    if log_file:
        try:
            with open(log_file) as f:
                tail = f.readlines()[-lines:]
        except OSError as e:
            raise click.ClickException(str(e)) from e
        console.print(Syntax("".join(tail), "text"))
