"""Agentic-workflows CLI: operate the knowledge mapper from a terminal.

The CLI is a thin client of the running web app's HTTP API (same backend,
same database), so every investigation, run, or artifact created here is
immediately viewable in the web GUI, and vice versa.

Layout
------
``client.py``   -- typed httpx wrapper over the endpoints the CLI needs.
``mermaid.py``  -- ```` ```mermaid ```` fence extraction + ASCII renderers.
``commands.py`` -- scriptable ``click`` commands (``python -m cli health``).
``tui.py``      -- interactive tabbed dashboard (``python -m cli tui``).

Only dependency-free stdlib plus ``httpx`` / ``rich`` / ``click``, which the
environment already provides; no new requirements.
"""

CLI_VERSION = "0.1.0"

DEFAULT_API_URL = "http://127.0.0.1:8204"
