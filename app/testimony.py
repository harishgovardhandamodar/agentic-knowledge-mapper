"""Diarized testimony: transcript parsing plus heuristic scoring for
first-person accounts (interviews, whistleblower testimony) from AI labs."""

from __future__ import annotations

import re
from typing import Any

_TS = r"(?:(\d{1,3}):)?([0-5]?\d):([0-5]\d)"
_TS_LINE = re.compile(rf"^\s*\[?{_TS}\]?\s*[-–—:|\]]?\s*(.*)$")
_TS_SPEAKER_LINE = re.compile(
    rf"^\s*\[?{_TS}\]?\s*(?:[-–—:|\]]\s*)?([^:]{{1,40}}):\s+(.*)$")
_ROLE_SINGLE = re.compile(
    r"^(INTERVIEWER|HOST|MODERATOR|QUESTION|NARRATOR)$", re.IGNORECASE)
_NAMEISH = re.compile(r"^([A-Z][A-Za-z'.-]+ ?){1,3}$")
_LABELED_LINE = re.compile(
    r"^\s*(SPEAKER[_ ]\d+|INTERVIEWER|HOST|QUESTION|MODERATOR"
    r"|[A-Z][A-Z0-9 .'\-]{1,29})\s*:\s*(.*)$")
_BOLD_LINE = re.compile(r"^\s*\*\*([^*]{1,60})\*\*\s*:?\s*(.*)$")
_NAME_LINE = re.compile(r"^\s*([A-Z][a-z]+(?: [A-Z][a-z'.-]+)+)\s*:\s+(.*)$")

ETHICS_TERMS = (
    "ethic", "moral", "values", "align", "harm", "safe", "conscience",
    "whistleblow", "right to warn", "duty", "responsib", "decept",
    "honest", "integrity", "cover-up", "coverup", "retaliat",
)
POLICY_TERMS = (
    "polic", "regulat", "govern", "oversight", "congress", "senate",
    "law", "legislat", "compliance", "audit", "transparen", "warn",
    "disclos", "moratorium", "liab",
)
AGI_TERMS = (
    "agi", "superintelligence", "super-intelligence", "existential",
    "transformative", "takeoff", "take-off", "scaling", "singularity",
    "power-seeking", "mesa", "emergen",
)
ROLE_TERMS = (
    "research", "scientist", "engineer", "policy", "fellow", "professor",
    "phd", "postdoc", "alignment", "safety",
)


def _to_seconds(h: str | None, m: str, s: str) -> int:
    return (int(h or 0) * 3600) + int(m) * 60 + int(s)


def _clean_speaker(raw: str) -> str:
    name = re.sub(r"\s+", " ", (raw or "").strip().strip("*_ "))[:60]
    name = name.strip().rstrip(":").strip()
    if re.fullmatch(r"SPEAKER[_ ]?\d+", name, re.IGNORECASE):
        return name.upper().replace(" ", "_")
    return name


def _looks_like_speaker(raw: str) -> bool:
    name = (raw or "").strip().rstrip(":").strip()
    if not name or len(name) > 40:
        return False
    if re.fullmatch(r"SPEAKER[_ ]?\d+", name, re.IGNORECASE):
        return True
    if _ROLE_SINGLE.match(name):
        return True
    if re.fullmatch(r"[A-Z][A-Z0-9 .'\-]{1,29}", name):
        return True
    return (" " in name) and bool(_NAMEISH.match(name))


def parse_transcript(text: str | None) -> dict[str, Any]:
    try:
        lines = (text or "").splitlines()
    except Exception:
        lines = []
    segments: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    saw_ts = False
    saw_labels = False

    def flush() -> None:
        if cur and (cur.get("text") or "").strip():
            cur["text"] = cur["text"].strip()
            segments.append(cur)

    def new_turn(speaker: str, start: int | None, first: str) -> None:
        nonlocal cur
        flush()
        cur = {"speaker": speaker or "UNKNOWN", "start_s": start,
               "end_s": None, "text": (first or "").strip()}

    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            continue
        m = _TS_SPEAKER_LINE.match(line)
        if m and m.group(4) is not None and _looks_like_speaker(m.group(4)):
            saw_ts = True
            saw_labels = True
            new_turn(_clean_speaker(m.group(4)),
                     _to_seconds(m.group(1), m.group(2), m.group(3)),
                     m.group(5))
            continue
        m = _LABELED_LINE.match(line)
        if m and _looks_like_speaker(m.group(1)):
            saw_labels = True
            new_turn(_clean_speaker(m.group(1)), None, m.group(2))
            continue
        m = _BOLD_LINE.match(line)
        if m and _looks_like_speaker(m.group(1)):
            saw_labels = True
            new_turn(_clean_speaker(m.group(1)), None, m.group(2))
            continue
        m = _NAME_LINE.match(line)
        if m:
            saw_labels = True
            new_turn(_clean_speaker(m.group(1)), None, m.group(2))
            continue
        m = _TS_LINE.match(line)
        body = m.group(4).strip() if m else ""
        if m and (body or _to_seconds(m.group(1), m.group(2), m.group(3))):
            saw_ts = True
            if cur is None:
                new_turn("UNKNOWN",
                         _to_seconds(m.group(1), m.group(2), m.group(3)),
                         body)
            elif body:
                cur["text"] = ((cur.get("text") or "") + "\n" + body).strip()
            if cur is not None and cur.get("start_s") is None:
                cur["start_s"] = _to_seconds(m.group(1), m.group(2),
                                             m.group(3))
            continue
        if cur is None:
            new_turn("UNKNOWN", None, line.strip())
        else:
            cur["text"] = ((cur.get("text") or "") + "\n" + line.strip()).strip()
    flush()
    prev_ts: int | None = None
    for seg in reversed(segments):
        if seg.get("end_s") is None:
            seg["end_s"] = prev_ts
        if isinstance(seg.get("start_s"), int):
            prev_ts = seg["start_s"]
    speakers: list[str] = []
    for seg in segments:
        if seg["speaker"] not in speakers:
            speakers.append(seg["speaker"])
    if not segments:
        fmt = "empty"
    elif saw_labels and saw_ts:
        fmt = "diarized"
    elif saw_labels:
        fmt = "labeled"
    elif saw_ts:
        fmt = "timestamped"
    else:
        fmt = "paragraphs"
    return {"segments": segments, "speakers": speakers, "format": fmt,
            "segment_count": len(segments)}


def _density(hay: str, terms: tuple[str, ...]) -> float:
    if not hay:
        return 0.0
    hits = sum(hay.count(t) for t in terms)
    return round(min(1.0, hits / 10.0), 2)


def score_testimony(meta: dict[str, Any] | None,
                    segments: list[dict[str, Any]] | None,
                    n_corroborating: int = 0,
                    n_inbound: int = 0) -> dict[str, Any]:
    meta = meta or {}
    segments = segments or []
    hay = " ".join([
        str(meta.get("author") or ""),
        str(meta.get("tags") or ""),
        str(meta.get("description") or ""),
        " ".join(str(s.get("text") or "") for s in segments[:60]),
    ]).lower()
    named = bool((meta.get("author") or "").strip()) and \
        "anonymous" not in str(meta.get("author") or "").lower()
    credibility = 0.25
    if named:
        credibility += 0.30
    if any(t in hay for t in ROLE_TERMS):
        credibility += 0.20
    if meta.get("url"):
        credibility += 0.15
    credibility += min(0.30, 0.10 * max(0, n_corroborating))
    credibility = round(min(1.0, credibility), 2)
    try:
        rel = float(meta.get("relevance") or 0.0)
    except (TypeError, ValueError):
        rel = 0.0
    n_out = int(meta.get("n_outbound") or 0)
    influence = round(min(1.0, 0.10 + 0.30 * max(0.0, min(1.0, rel))
                          + min(0.45, 0.15 * max(0, n_inbound))
                          + min(0.15, 0.05 * max(0, n_out))), 2)
    ethics = _density(hay, ETHICS_TERMS)
    policy = _density(hay, POLICY_TERMS)
    agi = _density(hay, AGI_TERMS)
    overall = round(0.40 * credibility + 0.30 * influence
                    + 0.30 * (ethics + policy + agi) / 3.0, 2)
    return {"credibility": credibility, "influence": influence,
            "ethics": ethics, "policy": policy, "agi": agi,
            "overall": overall, "method": "heuristic-v1"}
