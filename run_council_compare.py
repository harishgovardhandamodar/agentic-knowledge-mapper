"""Before/after comparison of hypothesis generation, same inputs both sides.

Runs the stored rows of an investigation's two prior model assessments through
BOTH drafting paths and diffs the result:

  BEFORE  one voice. A single LLM call at temperature 0.1 with one
          research-lead prompt, and (this is the part that matters) its output
          REPLACES the deterministic rules -- so a working gateway produces
          strictly fewer claims than a broken one. Scoring is arithmetic over
          the rows a claim cites: cited-row count, cross-flow flag, falsifier
          present or not, and the drafter's own impact number.

  AFTER   the council. Six disciplinary seats draft independently, every claim
          is attacked by the seats that do not own it, refutation tests are
          graded rather than presence-checked, stakes are capped by the
          attack classes a claim actually traces to, and a claim nobody
          objected to scores zero on peer scrutiny.

The old implementation is loaded from git rather than reimplemented, so the
"before" is the code that actually shipped and not a reconstruction of it.
"""
from __future__ import annotations

import json
import subprocess
import sys
import types
from typing import Any


def load_before_module(path: str, name: str, ref: str) -> types.ModuleType:
    """Import one pre-council module from git as a standalone module.

    Loaded from git rather than reimplemented: a hand-written "before" would
    be the version I remember, which is exactly the version whose bugs I am
    trying to measure.
    """
    src = subprocess.run(["git", "show", f"{ref}:{path}"],
                         capture_output=True, text=True, check=True).stdout
    import app  # noqa: F401  -- ensure the package is importable first
    mod = types.ModuleType(name)
    mod.__dict__["__file__"] = f"<git:{ref}:{path}>"
    # Relative imports inside the module (``from . import security``) resolve
    # through __package__, so it must be "app" and the module must be exec'd
    # with that package bound.
    mod.__dict__["__package__"] = "app"
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)  # noqa: S102
    sys.modules[name] = mod
    return mod


def load_before(ref: str = "eac4177~1"):
    """The pre-council agents AND scorer.

    Both, deliberately. Scoring the old claims with the new scorer would
    charge "before" for a ``peer_scrutiny`` dimension that did not exist when
    it ran -- it would default to the zero baseline and read as a defect of
    the old drafting rather than a property of the new scoring. Each era is
    measured on its own arithmetic, which is the only way the two confidence
    numbers mean anything.
    """
    before_agents = load_before_module("app/agents.py", "agents_before", ref)
    before_security = load_before_module("app/security.py", "security_before",
                                         ref)
    return before_agents, before_security


def summarise(claims: list[dict[str, Any]], *, label: str) -> dict[str, Any]:
    """The numbers a reader can actually compare between the two runs."""
    total = len(claims)
    with_falsifier = sum(
        1 for c in claims if str(c.get("falsifier") or "").strip())
    distinct_classes: set[str] = set()
    seats: set[str] = set()
    for c in claims:
        for a in (c.get("council") or {}).get("attack_classes") or []:
            distinct_classes.add(str(a))
        seat = str(c.get("seat")
                   or (c.get("provenance") or {}).get("seat") or "")
        if seat:
            seats.add(seat)
    kinds: dict[str, int] = {}
    for c in claims:
        for ch in (c.get("council") or {}).get("challenges") or []:
            g = str(ch.get("ground") or "objection")
            kinds[g] = kinds.get(g, 0) + 1
    return {
        "label": label,
        "claims": total,
        "claims_with_falsifier": with_falsifier,
        "pct_falsifiable": round(100.0 * with_falsifier / total, 1) if total else 0.0,
        "distinct_attack_classes": len(distinct_classes),
        "attack_classes": sorted(distinct_classes),
        "seats_filing_claims": len(seats),
        "seats": sorted(seats),
        "claims_contested": sum(1 for c in claims if c.get("peer_reviewed")),
        "challenge_grounds": dict(sorted(kinds.items())),
        "mean_confidence": (
            round(sum(float(c.get("confidence", 0)) for c in claims) / total, 1)
            if total else 0.0),
    }


def compare(inv_id: int, db_path: str) -> dict[str, Any]:
    import os
    os.environ["AKM_DATABASE_URL"] = "sqlite:///" + os.path.abspath(db_path)
    from app import database  # noqa: E402
    from app import security as sec
    from app.database import SessionLocal  # noqa: E402
    from app.models import Investigation  # noqa: E402
    database.init_db()
    db = SessionLocal()
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if inv is None:
        raise SystemExit(f"no investigation {inv_id}")
    target_rows, adv_rows = sec._load_prior_model_rows(db, inv_id)
    if not target_rows or not adv_rows:
        raise SystemExit(
            f"investigation {inv_id} has no stored prior rows "
            f"(target={len(target_rows)}, adversarial={len(adv_rows)})")
    profile = sec.profile_model_subject(inv.title, inv.description or "", [])

    before_mod, before_sec = load_before()
    import app.agents as after_mod

    env_payload = {
        "product_name": inv.title,
        "use_case": inv.description or "",
        "profile": profile,
        "target_rows": target_rows,
        "adversarial_rows": adv_rows,
    }

    before_hyps = before_mod.hypothesis_analyst_handle(
        {"payload": dict(env_payload), "task_id": "cmp", "trace": []},
    )["payload"]["hypotheses"]
    before_verified = before_mod.hypothesis_verifier_handle(
        {"payload": {"hypotheses": before_hyps,
                     "target_rows": target_rows,
                     "adversarial_rows": adv_rows},
         "task_id": "cmp", "trace": []})["payload"]["verified"]

    after_hyps = after_mod.hypothesis_analyst_handle(
        {"payload": dict(env_payload), "task_id": "cmp", "trace": []},
    )["payload"]["hypotheses"]
    after_verified = after_mod.hypothesis_verifier_handle(
        {"payload": {"hypotheses": after_hyps,
                     "target_rows": target_rows,
                     "adversarial_rows": adv_rows},
         "task_id": "cmp", "trace": []})["payload"]

    before_scoring = before_sec.score_hypotheses(
        before_mod._hypothesis_dimension_inputs(before_verified))
    after_scoring = sec.score_hypotheses(
        after_mod._hypothesis_dimension_inputs(after_verified["verified"]))

    return {
        "investigation": inv_id,
        "title": inv.title,
        "input_rows": {"target": len(target_rows), "adversarial": len(adv_rows)},
        "before": summarise(before_verified, label="before (single voice)"),
        "after": summarise(after_verified["verified"], label="after (council)"),
        "before_method": before_scoring.get("method"),
        "after_method": after_scoring.get("method"),
        "before_confidence": before_scoring.get("confidence_pct"),
        "after_confidence": after_scoring.get("confidence_pct"),
        "before_dimensions": {d["id"]: d["score"]
                              for d in before_scoring.get("dimensions", [])},
        "after_dimensions": {d["id"]: d["score"]
                             for d in after_scoring.get("dimensions", [])},
        "after_coverage": (after_verified.get("council", {})
                           .get("coverage", {}).get("coverage_pct")),
        "after_unexamined_classes": [
            e["class"] for e in
            (after_verified.get("council", {}).get("coverage", {})
             .get("unexamined") or [])],
        "_before_claims": before_verified,
        "_after_claims": after_verified["verified"],
    }


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: run_council_compare.py <inv_id> <db_path> [--dump]",
              file=sys.stderr)
        return 2
    out = compare(int(sys.argv[1]), sys.argv[2])
    dump = "--dump" in sys.argv
    claims = {"_before_claims", "_after_claims"}
    if not dump:
        out = {k: v for k, v in out.items() if k not in claims}
    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
