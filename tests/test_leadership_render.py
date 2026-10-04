"""The leadership board's render path, checked without a browser.

The board is the largest template-string surface in the app and nothing in the
Python suite can see it: a typo in an ``onclick`` handler or a chart primitive
raises only when a reader clicks, which is the worst moment to find out. This
seeds a database with the shapes the board has to survive -- four tiers, a
snoozed and an acknowledged alert, an expired exception, a superseded row, an
unquantified blast radius, an empty tier -- then renders each resulting
``/api/leadership/board`` payload through the *real* JavaScript from
``static/index.html`` in Node against a DOM shim.

Skipped, not failed, when Node is absent: the Python behaviour is still covered
by ``test_leadership.py`` and failing a Python test because a JS runtime is
missing would be a lie about what is broken.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

# Pinned before the app import, by assignment: app.database reads the URL at
# import time and the repo forbids setdefault here, because setdefault would let
# an exported production AKM_DATABASE_URL win over the test file.
os.environ["AKM_DATABASE_URL"] = os.environ.get("AKM_TEST_DB") or (
    "sqlite:///" + os.path.join(tempfile.gettempdir(),
                                 "akm_test_leadership_render.db"))

from app import assurance as A                    # noqa: E402
from app.database import SessionLocal, init_db   # noqa: E402
from app.ledger_models import LeadershipAlertState, LedgerEvent, LedgerRun  # noqa: E402
from app.models import (AgentRun, Artifact, Explanation, Investigation,  # noqa: E402
                        SecurityAssessment)

HERE = os.path.dirname(os.path.abspath(__file__))
SMOKE = os.path.join(HERE, "js", "leadership_render_smoke.js")
NOW = datetime.now(timezone.utc)


def _assurance(residual, confidence, **over) -> dict:
    base = {
        "assessed": True,
        "evidence_confidence": confidence,
        "verified": {"residual_pct": residual, "headline": "verified"},
        "headline_layer": "verified",
        "control_attestation": {
            "MDR-AI-001": {"status": "evidenced", "evidence_ids": [1]},
            "MDR-AI-014": {"status": "declared", "evidence_ids": []},
            "MDR-AI-022": {"status": "unknown", "evidence_ids": []},
        },
        "architecture_gate": {"gate_blocked_applied": False, "banner": "",
                              "open_items": []},
        "forensics": {"reconstructable": True, "score": 80.0, "band": "strong"},
        "blast_radius": {"quantified": False, "summary": "not quantified"},
        "gates_open": ["evidence_threshold"],
        "decision": {"decision": A.DECISION_ACCEPT, "headline": "Accept"},
        "pending_evidence": {"share_of_credit_pct": 0},
        "threats": [],
    }
    base.update(over)
    return base


class LeadershipRenderCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")

    def setUp(self):
        if not self.node:
            self.skipTest("node is not on PATH; the JS render path is unchecked")
        init_db()
        self.db = SessionLocal()
        for m in (SecurityAssessment, Artifact, AgentRun, Explanation,
                  Investigation, LeadershipAlertState):
            self.db.query(m).delete()
        for m in (LedgerEvent, LedgerRun):
            self.db.query(m).delete()
        self.db.commit()
        self.inv = Investigation(title="Render Check Co", keywords="k",
                                 description="d", sources="web")
        self.db.add(self.inv)
        self.db.commit()
        self.db.refresh(self.inv)

    def tearDown(self):
        try:
            for m in (SecurityAssessment, Artifact, AgentRun, Explanation):
                self.db.query(m).filter(
                    m.investigation_id == self.inv.id).delete()
            self.db.query(Investigation).filter(
                Investigation.id == self.inv.id).delete()
            self.db.query(LeadershipAlertState).delete()
            self.db.commit()
        except Exception:
            self.db.rollback()
        self.db.close()

    def _row(self, name, tier, residual, confidence, days_ago=3, run_id=1,
             **assurance_over):
        rec = SecurityAssessment(
            investigation_id=self.inv.id, run_id=run_id, product_name=name,
            product_family=name.lower(), exposure=tier, inherent_pct=100.0,
            residual_pct=residual, overall_pct=residual,
            evidence_confidence=confidence,
            assurance_json=json.dumps(
                _assurance(residual, confidence, **assurance_over)),
            scoring_json=json.dumps({"assessment_path": "standard"}),
            markdown="# stub", threat_pack_version="2024.1",
            created_at=NOW - timedelta(days=days_ago),
        )
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        return rec

    def _render(self, payload, label):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "board.json")
            with open(p, "w") as f:
                json.dump(payload, f)
            r = subprocess.run([self.node, SMOKE, p], capture_output=True,
                               text=True, timeout=120)
        self.assertEqual(r.returncode, 0,
                         f"{label} did not render clean:\n{r.stdout}\n{r.stderr}")
        return r.stdout

    def _board(self, **params):
        from fastapi.testclient import TestClient
        from app.main import app
        with TestClient(app) as c:
            q = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
            r = c.get("/api/leadership/board" + (f"?{q}" if q else ""))
            self.assertEqual(r.status_code, 200, r.text[:400])
            return r.json()

    # ---- the cases ---------------------------------------------------------

    def test_a_full_board_renders_without_crashing_or_printing_undefined(self):
        self._row("claims intake agent", "restricted_data", 62.7, 0.31,
                  days_ago=40, run_id=1,
                  architecture_gate={"gate_blocked_applied": True,
                                     "banner": "Scoring returned to inherent",
                                     "open_items": ["no-logging", "no-retention"]})
        self._row("confidential agent", "confidential_data", 44.0, 0.55,
                  days_ago=20, run_id=2,
                  blast_radius={"quantified": True, "summary": "9 confidential / 180 privileged",
                                "records_at_risk": 250000, "privileged_users": 180,
                                "max_payload_mb": 512})
        self._row("internal wiki", "internal", 21.0, 0.8, days_ago=6, run_id=3)
        self._row("public faq", "public", 9.0, 0.9, days_ago=2, run_id=4)
        out = self._render(self._board(), "full board")
        self.assertIn("PASS", out)

    def test_an_empty_portfolio_renders_rather_than_throwing(self):
        # The worst case for a template: every array is empty, every number is
        # None. A chart that divides by the number of points dies here.
        out = self._render(self._board(), "empty board")
        self.assertIn("PASS", out)

    def test_a_row_with_no_residual_and_no_confidence_renders(self):
        # A partially-scored row is normal right after a run; the board must not
        # print NaN where a figure belongs.
        self._row("half scored", "internal", 0.0, 0.0, assurance_over={
            "assessed": True, "verified": {}, "evidence_confidence": None})
        out = self._render(self._board(), "half-scored row")
        self.assertIn("PASS", out)

    def test_a_tier_filtered_board_renders_with_one_tier(self):
        self._row("claims intake agent", "restricted_data", 62.7, 0.31, run_id=1)
        self._row("public faq", "public", 9.0, 0.9, run_id=2)
        payload = self._board(exposure="restricted_data")
        self.assertEqual([t["tier"] for t in payload["risk_position"]["tiers"]],
                         ["restricted_data"])
        self.assertIn("PASS", self._render(payload, "tier-filtered board"))

    def test_an_acknowledged_and_a_snoozed_alert_both_render(self):
        from app import leadership as LD
        self._row("gate blocked", "restricted_data", 70.0, 0.2, run_id=1,
                  architecture_gate={"gate_blocked_applied": True,
                                     "banner": "gate held",
                                     "open_items": ["no-logging"]})
        alerts = LD.alerts(self.db)["alerts"]
        self.assertTrue(alerts, "fixture should produce at least one alert")
        first = alerts[0]
        LD.acknowledge_alert(self.db, first["id"], actor="qa",
                             status="acknowledged",
                             finding_hash=first.get("finding_hash"))
        self.db.commit()
        payload = self._board(include_acknowledged="true")
        # The acknowledged row has to render in its dimmed, attributed form --
        # an alert card that silently drops the acknowledgement would let a
        # reader believe it is still unanswered.
        out = self._render(payload, "board with an ack")
        self.assertIn("PASS", out)

    def test_a_snoozed_alert_is_absent_from_the_board_until_it_expires(self):
        from app import leadership as LD
        self._row("gate blocked", "restricted_data", 70.0, 0.2, run_id=1,
                  architecture_gate={"gate_blocked_applied": True,
                                     "banner": "gate held",
                                     "open_items": ["no-logging"]})
        alerts = LD.alerts(self.db)["alerts"]
        self.assertTrue(alerts)
        first = alerts[0]
        LD.acknowledge_alert(self.db, first["id"], actor="qa", status="snoozed",
                             snooze_days=7, finding_hash=first.get("finding_hash"))
        self.db.commit()
        # Default board: a live snooze suppresses the alert.
        default = self._board()
        self.assertNotIn(first["id"], {a["id"] for a in default["alerts"]["alerts"]},
                         "a snoozed alert must not be listed until it expires")
        self.assertIn("PASS", self._render(default, "board with a snooze"))
        # Asking for suppressed alerts brings it back, marked as snoozed with its
        # end date -- suppressed, not deleted, and never silently unanswered.
        shown = self._board(include_acknowledged="true")
        rows = {a["id"]: a for a in shown["alerts"]["alerts"]}
        self.assertIn(first["id"], rows)
        self.assertTrue(rows[first["id"]]["snoozed"])
        self.assertTrue(rows[first["id"]]["snoozed_until"])
        self.assertIn("PASS", self._render(shown, "board with a snooze shown"))

    def test_every_status_the_ui_can_send_is_one_the_backend_accepts(self):
        """The alert buttons are literal strings in a template.

        ``acknowledge_alert`` validates its status against a fixed vocabulary and
        raises on anything else, so a button wired to a status the backend does
        not accept is a 422 discovered by clicking it. Reading the literals out
        of the page and matching them against the real function source catches
        the typo at test time instead.
        """
        import re
        from app import leadership as LD
        import inspect
        src = inspect.getsource(LD.acknowledge_alert)
        m = re.search(r'if status not in \(([^)]*)\)', src)
        self.assertIsNotNone(m, "acknowledge_alert no longer declares a vocabulary")
        accepted = set(re.findall(r'"([a-z_]+)"', m.group(1)))
        self.assertTrue(accepted)
        html = open(os.path.join(HERE, "..", "static", "index.html")).read()
        # `[^,]*` rather than `[^)]*`: the alert id argument is an interpolated
        # expression that itself contains a closing paren.
        sent = set(re.findall(r"secLeadAck\([^,]*,\s*'([a-z_]+)'\)", html))
        self.assertTrue(sent, "no alert status literals found in the page")
        self.assertEqual(sent - accepted, set(),
                         "the UI sends a status the backend refuses")

    def test_the_board_renders_for_every_persona_lens(self):
        self._row("claims intake agent", "restricted_data", 62.7, 0.31, run_id=1)
        for lens in ("executive", "ciso", "dpo", "legal", "audit",
                     "security_engineering"):
            payload = self._board(persona=lens)
            self.assertIn("PASS", self._render(payload, f"{lens} lens"))