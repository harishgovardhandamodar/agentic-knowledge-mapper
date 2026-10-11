"""Render the before/after comparison as a readable report."""
from __future__ import annotations

import os
import sys

os.environ.setdefault("AKM_DATABASE_URL",
                      "sqlite:///" + os.path.abspath("data/council-live.db"))


def table(rows: list[tuple[str, str, str]], head: tuple[str, str, str]) -> str:
    out = [f"| {head[0]} | {head[1]} | {head[2]} |",
           "|---|---|---|"]
    for a, b, note in rows:
        out.append(f"| {a} | {b} | {note} |")
    return "\n".join(out)


def main() -> int:
    import run_council_compare as C
    inv_id = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    db = sys.argv[2] if len(sys.argv) > 2 else "data/council-live.db"
    r = C.compare(inv_id, db)
    b, a = r["before"], r["after"]

    L: list[str] = []
    L.append(f"# Before / after: hypothesis generation on investigation "
             f"#{r['investigation']}")
    L.append("")
    L.append(f"**Subject.** {r['title']}")
    L.append("")
    L.append(f"Both sides were handed the *same* stored evidence: "
             f"{r['input_rows']['target']} internals finding(s) and "
             f"{r['input_rows']['adversarial']} misuse scenario(s). The "
             f"pre-council code is loaded from git at `eac4177~1`, not "
             f"reimplemented, and each era is scored with its own arithmetic "
             f"— scoring the old claims with the new scorer would charge "
             f"\"before\" for a dimension that did not exist when it ran.")
    L.append("")
    L.append("## Headline")
    L.append("")
    L.append(table([
        ("Claims drafted", f"**{b['claims']}**", f"**{a['claims']}**"),
        ("Attack classes reached", f"{b['distinct_attack_classes']}",
         f"**{a['distinct_attack_classes']}**"),
        ("Reviewer seats filing claims", f"{b['seats_filing_claims']}",
         f"**{a['seats_filing_claims']}**"),
        ("Claims contested by a non-author", f"{b['claims_contested']}",
         f"**{a['claims_contested']}**"),
        ("Claims with a refutable test", f"{b['pct_falsifiable']:g}%",
         f"{a['pct_falsifiable']:g}%"),
        ("Scoring method", f"`{r['before_method']}`",
         f"`{r['after_method']}`"),
        ("Confidence aggregate", f"{r['before_confidence']}/100",
         f"{r['after_confidence']}/100"),
    ], ("Measure", "Before (single voice)", "After (council)")))
    L.append("")
    L.append("## Verdict dimensions")
    L.append("")
    L.append("Each era on its own weight table, so the columns are not "
             "directly comparable row-for-row; what is comparable is whether "
             "a dimension exists at all and what it measures.")
    L.append("")
    keys = sorted(set(r["before_dimensions"]) | set(r["after_dimensions"]))
    L.append(table([
        (f"`{k}`",
         f"{r['before_dimensions'].get(k, '— (dimension did not exist)'):g}"
         if k in r["before_dimensions"] else "— (dimension did not exist)",
         f"{r['after_dimensions'].get(k, 0):g}")
        for k in keys
    ], ("Dimension", "Before", "After")))
    L.append("")
    L.append("`peer_scrutiny` is the difference that matters: it asks whether "
             "a reviewer who did *not* propose a claim tried to break it. "
             "Before, that question had nowhere to go.")
    L.append("")
    L.append("## What each side actually claimed")
    L.append("")
    L.append("**Before — 1 claim:**")
    L.append("")
    for c in r["_before_claims"]:
        L.append(f"- `{c.get('id')}` {c.get('claim')}")
    L.append("")
    L.append("The single claim is the *gap marker* — the flow's way of "
             "saying it had nothing to cross-reference. Not a hypothesis.")
    L.append("")
    L.append(f"**After — {a['claims']} claims from {a['seats_filing_claims']} "
             f"seats:**")
    L.append("")
    for c in r["_after_claims"]:
        seat = (c.get("council") or {}).get("seat") or "—"
        L.append(f"- `{c.get('hypothesis_id')}` **[{seat}]** {c.get('claim')}")
        L.append(f"  - stakes if true {c.get('impact')}/5, confidence "
                 f"{c.get('confidence')}/100, refutation test "
                 f"{(c.get('council') or {}).get('falsifier_audit', {}).get('grade')}")
        L.append(f"  - refuted by: {c.get('falsifier')}")
    L.append("")
    if a["challenge_grounds"]:
        L.append("## Objections the council raised")
        L.append("")
        for g, n in sorted(a["challenge_grounds"].items(),
                           key=lambda kv: -kv[1]):
            L.append(f"- **{g}** — {n}")
        L.append("")
    L.append("## What neither side could reach")
    L.append("")
    L.append(f"Attack-class coverage **{r['after_coverage']:g}%** of the "
             f"classes the stored corpus actually speaks to. Classes where "
             f"the corpus is silent are reported separately and are **not** "
             f"evidence of absence:")
    L.append("")
    L.append(f"- unexamined (evidence exists, no seat claimed it): "
             f"{r['after_unexamined_classes'] or 'none'}")
    L.append("")
    print("\n".join(L))
    return 0


if __name__ == "__main__":
    sys.exit(main())
