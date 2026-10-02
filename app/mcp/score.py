"""mcp-score — score_risk, score_portfolio, fingerprint (thin wrapper over risk_scoring.py)."""

from __future__ import annotations

from typing import Any

from .. import risk_scoring as rs


def score_risk(row: dict[str, Any]) -> dict[str, Any]:
    return rs.score_risk(row)


def score_portfolio(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return rs.portfolio_aggregates(rows)


def fingerprint() -> dict[str, str]:
    return {"method": rs.RISK_SCORING_METHOD, "version": rs.RISK_SCORING_VERSION, "fingerprint": rs.risk_scoring_fingerprint()}
