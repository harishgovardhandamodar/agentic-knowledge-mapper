"""Startup recovery: a restart must not leave work stuck as "running".

Background work runs on bare threads that do not survive a restart. The
AgentRun sweep already marks interrupted runs, but explanations were missed --
a restart mid-answer left the row `running` with no worker to finish it, and
the UI polled it forever. This pins that a `running` explanation is marked
interrupted on the next startup.
"""
import os
import tempfile
import unittest

os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(
        tempfile.mkdtemp(prefix="akm-startup-"), "test.db"))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.models import Explanation, Investigation  # noqa: E402


class StartupRecoveryCase(unittest.TestCase):
    def test_a_running_explanation_is_interrupted_on_startup(self):
        init_db()
        db = SessionLocal()
        db.query(Explanation).delete()
        inv = Investigation(title="startup recovery")
        db.add(inv)
        db.commit()
        e = Explanation(investigation_id=inv.id, question="q", status="running")
        db.add(e)
        db.commit()
        eid = e.id
        db.close()

        # Entering the TestClient runs on_start(), the startup sweep.
        with TestClient(app):
            pass

        db = SessionLocal()
        got = db.query(Explanation).filter(Explanation.id == eid).first()
        self.assertEqual(got.status, "error")
        self.assertIn("interrupted by server restart", got.error or "")
        self.assertIsNotNone(got.finished_at)
        db.close()


if __name__ == "__main__":
    unittest.main()