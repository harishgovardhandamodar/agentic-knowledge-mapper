"""Re-run the hypothesis council over the complete evidence base.

The manager queues the third flow last so it reads the STORED rows of the
first two. In this run the adversarial job's worker died holding a lease, the
third flow proceeded anyway (it must, or it would block forever), and the
council therefore reviewed a model profile plus internals findings with no
misuse scenarios to cross-reference. That is a legitimate result and the flow
says so -- but it is not the review the question deserves, and the manager's
own ordering is the thing being tested.

Re-runs the synthesis against what is now stored. The earlier row is kept:
it is the record of what the pipeline actually did, and overwriting it would
destroy the evidence that the ordering matters.
"""
from __future__ import annotations

import json
import os
import sys

os.environ.setdefault("AKM_DATABASE_URL",
                      "sqlite:///" + os.path.abspath("data/council-live.db"))

from app import database  # noqa: E402
from app import security as sec
from app.database import SessionLocal  # noqa: E402
from app.models import SecurityAssessment  # noqa: E402

INV = int(sys.argv[1]) if len(sys.argv) > 1 else 1

SUBJECT = ("Temporal Graph Neural Network autoregressive autoencoder for "
          "synthetic financial messaging data on SWIFT")

USE_CASE = (
    "A temporal graph neural network feeds an autoregressive autoencoder that "
    "generates synthetic SWIFT financial messages for a consortium of "
    "institutions holding uneven shares of the underlying payment-message "
    "corpus. Assess memorization, closest plausible reconstruction, whether a "
    "major-share holder can use the synthetic data to reconstruct a minority "
    "holder's sample, and the methods for evaluating yield on privacy, "
    "utility and fidelity.")

FOCUS = ["temporal graph neural network", "autoregressive autoencoder",
         "synthetic financial messaging", "SWIFT", "memorization",
         "membership inference", "reconstruction attack",
         "collaborative training", "privacy utility fidelity"]


def main() -> int:
    database.init_db()
    db = SessionLocal()
    t, a = sec._load_prior_model_rows(db, INV)
    print(f"stored rows: target={len(t)} adversarial={len(a)}")
    if not (t and a):
        print("refusing: the council reviews both prior flows; running it on "
              "one would produce a claim set about half the evidence base.")
        return 1

    result = sec.build_assessment(
        product_name=SUBJECT,
        product_url="",
        exposure="confidential_data",
        use_case=("A temporal graph neural network feeds an autoregressive "
                  "autoencoder that generates synthetic SWIFT financial "
                  "messages for a consortium of institutions holding uneven "
                  "shares of the underlying payment-message corpus. "
                  "Assess memorization, closest plausible reconstruction, "
                  "whether a major-share holder can use the synthetic data to "
                  "reconstruct a minority holder's sample, and the methods for "
                  "evaluating yield on privacy, utility and fidelity."),
        focus=FOCUS,
        db=db, investigation_id=INV, declared_controls=[],
        assessment_mode="hypothesis")

    rec = SecurityAssessment(
        investigation_id=INV, product_name=SUBJECT,
        product_url="", exposure="confidential_data",
        use_case=USE_CASE, focus_json=json.dumps(FOCUS),
        overall_pct=result["overall_pct"], inherent_pct=result["inherent_pct"],
        residual_pct=result["residual_pct"],
        scoring_json=json.dumps(result["scoring"]),
        threats_json=json.dumps(result["threats"]),
        markdown=result["markdown"],
        diagrams_json=json.dumps(result["diagrams"]),
        a2a_trace_json=json.dumps({
            "task_id": result.get("a2a_task_id", ""),
            "trace": result.get("a2a_trace", []),
            "council": result.get("council") or {}}))
    db.add(rec)
    db.commit()
    print(f"stored full-base council assessment #{rec.id}  "
          f"confidence={result['scoring']['confidence_pct']}")
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
