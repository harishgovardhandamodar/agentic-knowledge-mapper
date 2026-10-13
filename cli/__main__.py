"""Entry point: ``python -m cli ...`` (``tui`` opens the dashboard)."""

from __future__ import annotations

import os
import sys

import click

from cli.client import AkMClient
from cli.commands import main as commands


def entry(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["tui"]:
        from cli.tui import Dashboard
        log_file = None
        rest = args[1:]
        if "--log-file" in rest:
            i = rest.index("--log-file")
            if i + 1 < len(rest):
                log_file = rest[i + 1]
        api = os.environ.get("AKM_API_URL")
        return Dashboard(AkMClient(base_url=api),
                         log_file=log_file).run()
    if args[:1] == ["chat"]:
        from cli.chat import Chat
        api = os.environ.get("AKM_API_URL")
        return Chat(AkMClient(base_url=api)).run()
    try:
        commands.main(args, standalone_mode=False)
    except click.ClickException as e:
        e.show()
        return 1
    except click.exceptions.Exit as e:
        return e.exit_code
    return 0


if __name__ == "__main__":
    raise SystemExit(entry())
