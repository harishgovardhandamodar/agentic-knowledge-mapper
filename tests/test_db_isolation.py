"""The test suite must never be able to write to the application database.

The default database is ``data/akm.db``, and inside the container that path is
the live application volume. Every test module therefore has to pin
``AKM_DATABASE_URL`` to a throwaway file *before* it imports anything from
``app``. This was not true: four modules set nothing at all, so whichever
module imported ``app.database`` first decided the path for the whole run, and
a plain ``unittest discover`` created investigations, security assessments,
agent runs and explanations in the production store (assessments #7, #8, #17
and #18 survive there, named "Gate Test Product", "Gate Override Test" and
"0").

So this module checks the property rather than trusting a convention: every
sibling test module sets the variable, and sets it before its first ``app``
import. A new test file that forgets fails here instead of quietly polluting
the database.
"""
import ast
import os
import pathlib
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="akm-dbpin-test-"), "test.db"))

HERE = pathlib.Path(__file__).resolve().parent


def _first_app_import_lineno(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mod = getattr(node, "module", None) or ""
            names = [a.name for a in getattr(node, "names", [])]
            if mod == "app" or mod.startswith("app.") or any(
                    n == "app" or n.startswith("app.") for n in names):
                return node.lineno
    return None


class TestDatabaseIsolation(unittest.TestCase):
    def modules(self):
        return sorted(p for p in HERE.glob("test_*.py")
                      if p.name != pathlib.Path(__file__).name)

    def test_suite_is_not_empty(self):
        self.assertGreaterEqual(len(self.modules()), 10)

    def test_every_module_pins_the_database(self):
        missing = []
        for p in self.modules():
            tree = ast.parse(p.read_text())
            pins = [n for n in ast.walk(tree)
                    if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Subscript)
                            and isinstance(t.value, ast.Attribute)
                            and t.value.attr == "environ"
                            and isinstance(t.slice, ast.Constant)
                            and t.slice.value == "AKM_DATABASE_URL"
                            for t in n.targets)]
            if not pins:
                missing.append(p.name)
        self.assertEqual(missing, [],
                         "these test modules can inherit the live database: "
                         + ", ".join(missing))

    def test_every_module_pins_before_importing_app(self):
        late = []
        for p in self.modules():
            tree = ast.parse(p.read_text())
            app_line = _first_app_import_lineno(tree)
            if app_line is None:
                continue  # no app import at all: cannot reach the database
            pin_lines = [n.lineno for n in ast.walk(tree)
                         if isinstance(n, ast.Assign)
                         and any(isinstance(t, ast.Subscript)
                                 and isinstance(t.value, ast.Attribute)
                                 and t.value.attr == "environ"
                                 and isinstance(t.slice, ast.Constant)
                                 and t.slice.value == "AKM_DATABASE_URL"
                                 for t in n.targets)]
            if not pin_lines or min(pin_lines) > app_line:
                late.append(f"{p.name} (pin {pin_lines or 'none'} vs app "
                            f"import line {app_line})")
        self.assertEqual(late, [],
                         "database pinned after the app import, so it has no "
                         "effect: " + "; ".join(late))

    def test_no_module_uses_the_setdefault_form(self):
        """``setdefault`` honours an already-exported AKM_DATABASE_URL, which is
        exactly how a production value leaks into a test run -- it must not be
        used to pin the database."""
        bad = [p.name for p in self.modules()
               if 'setdefault("AKM_DATABASE_URL"' in p.read_text()]
        self.assertEqual(bad, [])

    def test_the_suite_is_not_currently_on_the_live_database(self):
        url = os.environ.get("AKM_DATABASE_URL", "")
        self.assertNotIn("akm.db", os.path.basename(url.replace("sqlite:///", "")),
                         "this run is pointed at the application database")


if __name__ == "__main__":
    unittest.main()
