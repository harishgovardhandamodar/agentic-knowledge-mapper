"""Run the full manager pipeline on the TGNN/SWIFT question, in-process.

The manager's research and assessment workers are threads, so the driving
process must stay alive until they finish. ``--resume`` re-attaches to an
existing plan instead of creating a second copy: the queue rows are durable
but the threads that claimed them are not, so a killed process leaves jobs
leased and nothing draining them.

Usage: python3 run_council_live.py [db_path] [--resume]
"""
import json
import os
import sys
import time

DB = "data/council-live.db"
resume = "--resume" in sys.argv
for a in sys.argv[1:]:
    if not a.startswith("--"):
        DB = a
os.environ["AKM_DATABASE_URL"] = "sqlite:///" + os.path.abspath(DB)

from app import database, jobqueue  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.manager import run_plan  # noqa: E402
from app.models import Investigation, SecurityAssessment  # noqa: E402

QUESTION = (
    "Run detailed security investigations on Temporal Graph Neural networks "
    "too be used in the context of Autoregressive auto encoder network for "
    "synthetic data generation in financial messages in Swift network, to what "
    "level of memorization by these network is plausible, what would be the "
    "closest reconstruction plausible ? is it possible to use this synthetic "
    "data by a party who has major share in data trained to reconstruct other "
    "party's data sample or population? what are the methods to evaluate the "
    "yield of synthetic data with respect to Privacy, Utility and fidelity?"
)

SUBJECT = ("Temporal Graph Neural Network autoregressive autoencoder for "
           "synthetic financial messaging data on SWIFT")

USE_CASE = (
    "A temporal graph neural network feeds an autoregressive autoencoder that "
    "generates synthetic SWIFT financial messages for a consortium of "
    "institutions holding uneven shares of the underlying payment-message "
    "corpus. " + QUESTION
)

FOCUS = [
    "temporal graph neural network",
    "autoregressive autoencoder",
    "synthetic financial messaging",
    "SWIFT",
    "memorization",
    "membership inference",
    "reconstruction attack",
    "collaborative training",
    "privacy utility fidelity",
]

EXPECTED = {"model", "model_adversarial", "model_hypothesis"}


def assessment_rows(db, inv_id):
    out = {}
    for r in (db.query(SecurityAssessment)
              .filter(SecurityAssessment.investigation_id == inv_id).all()):
        try:
            path = ((json.loads(r.scoring_json or "{}") or {})
                    .get("assessment_path") or "standard")
        except Exception:
            path = "standard"
        out[path] = r
    return out


def main() -> int:
    database.init_db()
    db = SessionLocal()

    if resume:
        inv_id = 1
        print(f"resuming topic investigation #{inv_id}", flush=True)
    else:
        plan = {
            "domain": "AI security / privacy",
            "exposure": "confidential_data",
            "topics": [{
                "title": ("TGNN + autoregressive autoencoder: synthetic SWIFT "
                          "messaging - memorization, reconstruction, "
                          "consortium privacy leakage"),
                "subject": SUBJECT,
                "description": USE_CASE,
                "keywords": ", ".join(FOCUS),
                "focus": FOCUS,
            }],
            "summary": {
                "title": "TGNN / SWIFT synthetic-data council review",
                "description": QUESTION,
            },
        }
        row = run_plan(db, plan, command=QUESTION)
        inv_id = row["topics"][0]["investigation_id"]
        print(f"manager run #{row['id']}  topic investigation #{inv_id}",
              flush=True)

    # Re-ensure the workers: a resumed process is precisely the case where the
    # previous ones died holding leases.
    from app import security_agent as _sa
    _sa._ensure_worker()

    deadline = time.time() + 60 * 50
    last = None
    while time.time() < deadline:
        seen = assessment_rows(db, inv_id)
        pending = jobqueue.pending_count(db)
        state = json.dumps({"assessments": sorted(seen),
                            "queued": pending}, sort_keys=True)
        if state != last:
            print(f"  [{time.strftime('%H:%M:%S')}] {state}", flush=True)
            last = state
        if EXPECTED.issubset(seen) and pending == 0:
            print("all three model assessments stored.", flush=True)
            break
        db.expire_all()
        time.sleep(5)
    else:
        print("TIMED OUT waiting for assessments.", flush=True)

    for path, r in sorted(assessment_rows(db, inv_id).items()):
        print(f"  assessment #{r.id} path={path} score={r.overall_pct} "
              f"posture={r.posture}")
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    print(f"investigation #{inv_id}: {inv.title}")
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
