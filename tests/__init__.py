"""Test package bootstrap: pin the database to a throwaway file.

Every test module here used to choose its own database with
``os.environ.setdefault("AKM_DATABASE_URL", ...)``. That is not a guard, it is a
race: ``tests/test_drift.py``, ``test_grounding.py``, ``test_llm_json.py`` and
``test_report_grounding.py`` set nothing at all, so whichever module imported
``app.database`` first decided the path for the whole run -- and the default is
``data/akm.db``, which inside the container is the live application volume. A
plain ``unittest discover`` could therefore create investigations, security
assessments, agent runs, explanations and graph nodes in the production
database; four such rows survived in the live store (security assessments
#7, #8, #17 and #18, named "Gate Test Product", "Gate Override Test" and "0").

So the environment variable is set here, once, before any test module can
import the app, and unconditionally: importing ``tests.<anything>`` always
initialises the package first. A caller may still point the suite at a specific
file, but never at the live one.
"""
import os
import sys
import tempfile

_APP_DB = os.path.join("data", "akm.db")


def _is_live_db(url: str) -> bool:
    """True when ``url`` resolves to the application database."""
    if not url:
        return False
    path = url
    for prefix in ("sqlite:///", "sqlite:///"):
        if path.startswith(prefix):
            path = path[len(prefix):]
            break
    else:
        return False
    try:
        real = os.path.realpath(os.path.abspath(path))
        live = os.path.realpath(os.path.abspath(_APP_DB))
    except OSError:
        return False
    return real == live or os.path.basename(real) == "akm.db"


def _install() -> str:
    url = os.environ.get("AKM_DATABASE_URL") or ""
    if _is_live_db(url):
        print("REFUSING to run tests against the live database "
              f"({url}); using a temporary one instead.", file=sys.stderr)
        url = ""
    if not url:
        d = tempfile.mkdtemp(prefix="akm-tests-")
        url = "sqlite:///" + os.path.join(d, "test.db")
        os.environ["AKM_DATABASE_URL"] = url
    elif _is_live_db(url):
        raise RuntimeError("AKM_DATABASE_URL points at the live database")
    return url


_install()
