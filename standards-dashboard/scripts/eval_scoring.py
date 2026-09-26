"""Single source of truth for eval response scoring.

Shared by scripts/eval-governance.py (offline 500-query harness) and
benchmark-api/app.py (per-prompt rerun endpoint) so the substring-hit +
citation heuristic cannot drift between the two.

Scoring: 70% framework-hit rate + 30% citation present. Pass = score >= 0.5.
"""
import json
import re

_FW_NAME = {}


def load_framework_names(frameworks_path):
    """Load {framework id -> name} aliases from data/frameworks.json (best effort)."""
    global _FW_NAME
    try:
        with open(frameworks_path) as f:
            _FW_NAME = {fw["id"]: fw["name"] for fw in json.load(f)["frameworks"]}
    except Exception:
        _FW_NAME = {}


def _hit_for_expect(low, exp):
    exp_l = exp.lower()
    if exp_l in low:
        return True
    name = _FW_NAME.get(exp, "").lower()
    if name and name[:30] in low:  # e.g. "eu artificial intelligence act" prefix
        return True
    # id with hyphen vs spaces: eu-ai-act <-> eu ai act
    if exp_l.replace("-", " ") in low or exp_l.replace("-", "") in low:
        return True
    return bool(re.search(r"\b" + re.escape(exp_l) + r"\b", low))


def evaluate_response(resp, expects):
    low = resp.lower()
    hits = [e for e in expects if _hit_for_expect(low, e)]
    has_cite = bool(re.search(r"https?://|source|eur-lex|nist\.gov|iso\.org|owasp\.org", low))
    score = (len(hits) / max(1, len(expects))) * 0.7 + (0.3 if has_cite else 0)
    return {"hit_count": len(hits), "hits": hits, "has_citation": has_cite, "score": round(score, 3)}


_SUFFIX_MARKER = re.compile(r"\s*\((?:case|context|query|scenario|variant)\s*\d+\)\s*$", re.I)


def distinct_query_count(queries):
    """Number of genuinely distinct prompts once cyclic '(variant N)' markers are stripped."""
    return len({_SUFFIX_MARKER.sub("", q["query"]) for q in queries})