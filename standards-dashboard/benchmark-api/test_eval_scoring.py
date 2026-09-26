import importlib.util
import json
import os
import sys

SCRIPT_DIR = os.path.join(os.path.dirname(__file__), "..", "scripts")
sys.path.insert(0, SCRIPT_DIR)

from eval_scoring import distinct_query_count, evaluate_response, load_framework_names  # noqa: E402

spec = importlib.util.spec_from_file_location("eval_governance", os.path.join(SCRIPT_DIR, "eval-governance.py"))
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)  # (does not run main())


def test_scoring_hit_and_citation():
    ev = evaluate_response("answer mentions eu-ai-act and cites eur-lex", ["eu-ai-act"])
    assert ev["hit_count"] == 1
    assert ev["has_citation"] is True
    assert ev["score"] == 1.0


def test_scoring_miss_gets_zero():
    ev = evaluate_response("nothing relevant here", ["eu-ai-act", "nist-ai-rmf"])
    assert ev["hit_count"] == 0
    assert ev["score"] == 0.0


def test_alias_matching(tmp_path):
    p = tmp_path / "frameworks.json"
    p.write_text(json.dumps({"frameworks": [{"id": "eu-ai-act", "name": "EU Artificial Intelligence Act"}]}))
    load_framework_names(str(p))
    assert evaluate_response("we follow the EU Artificial Intelligence Act", ["eu-ai-act"])["hit_count"] == 1
    assert evaluate_response("per the eu ai act", ["eu-ai-act"])["hit_count"] == 1


def test_harness_has_five_hundred_queries_but_far_fewer_distinct():
    queries = harness.build_queries()
    assert len(queries) == 500
    distinct = distinct_query_count(queries)
    assert 20 <= distinct < 500
    assert all({"id", "query", "expects", "category"} <= q.keys() for q in queries)