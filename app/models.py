from datetime import datetime, timezone
from sqlalchemy import (Column, Integer, String, Text, Float, DateTime, ForeignKey,
                        UniqueConstraint, Index, text)
from sqlalchemy.orm import relationship

from .database import Base


def _now():
    return datetime.now(timezone.utc)


class Investigation(Base):
    """A user-defined collection brief: keywords + description drive the agent."""
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(300), nullable=False)
    keywords = Column(String(1000), nullable=False, default="")  # comma-separated
    description = Column(Text, nullable=False, default="")  # user brief: what to collect
    sources = Column(String(200), nullable=False, default="rss,arxiv,web")  # csv subset
    status = Column(String(30), nullable=False, default="draft")  # draft|running|ready
    hidden = Column(Integer, nullable=False, default=0)  # 0|1 — hidden from the list, not deleted
    created_at = Column(DateTime, default=_now)
    updated_at = Column(DateTime, default=_now, onupdate=_now)
    # Scheduler: run the agent on a cron timetable.
    schedule_enabled = Column(Integer, nullable=False, default=0)  # 0|1
    schedule_cron = Column(String(100), nullable=True)  # e.g. "0 4 * * *"
    schedule_max_items = Column(Integer, nullable=False, default=25)
    schedule_rounds = Column(Integer, nullable=False, default=2)
    last_scheduled_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    # Search tuning.
    preferred_domains = Column(String(500), nullable=False, default="")  # comma-separated
    auto_save_explanations = Column(Integer, nullable=False, default=1)  # 0|1

    artifacts = relationship("Artifact", back_populates="investigation",
                             cascade="all, delete-orphan")
    runs = relationship("AgentRun", back_populates="investigation",
                        cascade="all, delete-orphan")
    cve_findings = relationship("CveFinding", back_populates="investigation",
                                cascade="all, delete-orphan")


class Artifact(Base):
    """Collected item scoped to one investigation."""
    __tablename__ = "artifacts"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    title = Column(String(500), nullable=False)
    artifact_type = Column(String(50), nullable=False, default="news")  # news|paper|essay|research|tweet|interview|book|projection
    url = Column(String(1000), nullable=True)
    description = Column(Text, nullable=True)
    content = Column(Text, nullable=True)
    source = Column(String(200), nullable=True)
    author = Column(String(200), nullable=True)
    date_published = Column(DateTime, nullable=True)
    tags = Column(String(500), nullable=True)
    sentiment = Column(Float, nullable=True)
    relevance = Column(Float, nullable=True)  # 0..1 agent score
    relevance_reason = Column(String(500), nullable=True)
    review = Column(String(20), nullable=False, default="pending")  # pending|accepted|rejected
    drift = Column(Integer, nullable=False, default=0)  # 0|1 — off-brief topic; kept but flagged
    origin = Column(String(20), nullable=False, default="agent")  # agent|manual
    run_id = Column(Integer, ForeignKey("agent_runs.id", ondelete="SET NULL"),
                    nullable=True, index=True)  # collecting run, if any
    created_at = Column(DateTime, default=_now)

    investigation = relationship("Investigation", back_populates="artifacts")


class Relationship(Base):
    __tablename__ = "relationships"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    source_id = Column(Integer, ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(Integer, ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False)
    relationship_type = Column(String(50), nullable=False, default="similar_to")
    description = Column(String(500), nullable=True)
    origin = Column(String(20), nullable=False, default="agent")  # agent|manual
    run_id = Column(Integer, ForeignKey("agent_runs.id", ondelete="SET NULL"),
                    nullable=True, index=True)
    created_at = Column(DateTime, default=_now)


class CveFinding(Base):
    """A known CVE surfaced for an investigation, with its current standing.

    The graph node itself is a lightweight ``Artifact`` of type ``cve`` (so the
    whole graph pipeline -- colors, legend, filters -- works unchanged); this
    row is the structured record behind the Known Issues tab: when it was
    published, what it says, whether it is still live, and how bad it is.

    ``status`` is the vendor/database standing (e.g. NVD's ``Analyzed``) when
    enrichment succeeded, else ``unknown`` -- never a guess. ``impact`` is the
    short blast description (CIA triad when CVSS data exists, else the opening
    of the description), because "critical" alone does not tell an operator
    what breaks.
    """
    __tablename__ = "cve_findings"
    __table_args__ = (UniqueConstraint("investigation_id", "cve_id",
                                       name="uq_cve_finding"),)

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    cve_id = Column(String(30), nullable=False, index=True)  # CVE-YYYY-NNNNN
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    published_date = Column(DateTime, nullable=True)
    status = Column(String(50), nullable=False, default="unknown")
    severity = Column(String(20), nullable=False, default="unknown")
    # critical|high|medium|low|unknown
    cvss = Column(Float, nullable=True)
    impact = Column(Text, nullable=True)
    source_url = Column(String(1000), nullable=True)
    artifact_id = Column(Integer, ForeignKey("artifacts.id", ondelete="SET NULL"),
                         nullable=True)  # the graph node, if created
    created_at = Column(DateTime, default=_now)

    investigation = relationship("Investigation", back_populates="cve_findings")


class AgentRun(Base):
    __tablename__ = "agent_runs"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    status = Column(String(20), nullable=False, default="running")  # running|done|error
    trigger = Column(String(20), nullable=False, default="manual")  # manual|schedule
    plan = Column(Text, nullable=True)  # JSON
    stats = Column(Text, nullable=True)  # JSON
    error = Column(Text, nullable=True)
    started_at = Column(DateTime, default=_now)
    finished_at = Column(DateTime, nullable=True)

    investigation = relationship("Investigation", back_populates="runs")
    events = relationship("AgentEvent", back_populates="run", cascade="all, delete-orphan")


class AgentEvent(Base):
    __tablename__ = "agent_events"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("agent_runs.id", ondelete="CASCADE"),
                    nullable=False, index=True)
    stage = Column(String(30), nullable=False)  # plan|search|analyze|map|summary
    message = Column(Text, nullable=False)
    data = Column(Text, nullable=True)  # JSON blob
    created_at = Column(DateTime, default=_now)

    run = relationship("AgentRun", back_populates="events")


class Explanation(Base):
    """Agentic explainer output: researched, illustrated answer to a question."""
    __tablename__ = "explanations"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    question = Column(String(1000), nullable=False)
    answer = Column(Text, nullable=True)  # JSON: summary/sections/key_points/sources
    status = Column(String(20), nullable=False, default="running")  # running|done|error
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=_now)
    finished_at = Column(DateTime, nullable=True)
    trace = Column(Text, nullable=True)  # JSON research provenance
    mode = Column(String(20), nullable=True, default="explain")
    depth = Column(String(20), nullable=True, default="balanced")
    audience = Column(String(20), nullable=True, default="intermediate")
    max_pages = Column(Integer, nullable=True, default=6)
    hops = Column(Integer, nullable=True, default=0)
    meta = Column(Text, nullable=True)  # JSON misc
    parent_id = Column(Integer, ForeignKey("explanations.id", ondelete="SET NULL"),
                       nullable=True, index=True)  # follow-up thread parent
    thread_id = Column(Integer, nullable=True, index=True)  # root explanation of the thread
    quiz = Column(Text, nullable=True)  # JSON: interactive quiz items
    bookmarked = Column(Integer, nullable=False, default=0)  # 0|1 saved to bookmarks
    watched = Column(Integer, nullable=False, default=0)  # 0|1 auto re-answer on drift


class CorpusPage(Base):
    """Cached copy of a fetched web page, searchable across explanations."""
    __tablename__ = "corpus_pages"
    __table_args__ = (UniqueConstraint("investigation_id", "url",
                                       name="uq_corpus_inv_url"),)

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    url = Column(String(1000), nullable=False)
    title = Column(String(500), nullable=True)
    domain = Column(String(200), nullable=True)
    text = Column(Text, nullable=True)
    published = Column(String(40), nullable=True)  # ISO-ish date string, best effort
    images = Column(Text, nullable=True)  # JSON list
    fetched_at = Column(DateTime, default=_now)


class SecurityAssessment(Base):
    """AI Security Engineering & Evaluation Agent output, scoped to an investigation."""
    __tablename__ = "security_assessments"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    run_id = Column(Integer, ForeignKey("agent_runs.id", ondelete="SET NULL"),
                    nullable=True, index=True)
    product_name = Column(String(500), nullable=False)
    product_url = Column(String(1000), nullable=True)
    exposure = Column(String(100), nullable=False, default="confidential_data")
    use_case = Column(Text, nullable=True)
    workflow_text = Column(Text, nullable=True)
    doc_urls_json = Column(Text, nullable=True)  # JSON: documentation URLs supplied at run time
    focus_json = Column(Text, nullable=True)  # JSON: focus areas supplied at run time
    require_approval = Column(Integer, nullable=True, default=0)
    overall_pct = Column(Float, nullable=False, default=0)
    inherent_pct = Column(Float, nullable=True)  # pre-control score
    residual_pct = Column(Float, nullable=True)  # post-control score (headline)
    controls_json = Column(Text, nullable=True)  # JSON: active controls + control plan
    scoring_json = Column(Text, nullable=True)  # JSON: breakdown/distribution/breakdown
    perspectives_json = Column(Text, nullable=True)  # JSON: per-audience highlight panels
    posture = Column(String(500), nullable=True)
    markdown = Column(Text, nullable=False)
    diagrams_json = Column(Text, nullable=True)  # JSON-encoded mermaid sources
    threats_json = Column(Text, nullable=True)  # JSON-encoded threat list
    evidence_json = Column(Text, nullable=True)  # JSON: evidence/queries/known_exploits/scope
    a2a_trace_json = Column(Text, nullable=True)  # JSON: task_id + hop trace
    # Which threat pack produced these numbers. Without it, an assessment
    # re-read after a catalog edit is two different results wearing one id.
    threat_pack_version = Column(String(20), nullable=True)
    threat_pack_fingerprint = Column(String(20), nullable=True)
    created_at = Column(DateTime, default=_now)


class ManagerRun(Base):
    """Agentic Manager fan-out: one command -> N investigations + a summary.

    Children statuses are derived live from their own tables on every read;
    this row only anchors the command, the validated plan, and the summary
    investigation. ``status`` moves running -> compiled when the summary
    compiles; readiness itself is derived, never written by a watcher.
    """
    __tablename__ = "manager_runs"

    id = Column(Integer, primary_key=True, index=True)
    command = Column(Text, nullable=False, default="")
    plan_json = Column(Text, nullable=False, default="{}")
    status = Column(String(20), nullable=False, default="running")
    summary_investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="SET NULL"),
                                      nullable=True)
    created_at = Column(DateTime, default=_now)
    updated_at = Column(DateTime, default=_now, onupdate=_now)


class QueryShapeYield(Base):
    """What one *shape* of search query has cost and returned, per investigation.

    The agent re-plans follow-up queries every round from scratch, with no
    memory of which shapes have paid off. A brief about frontier-model
    interpretability can therefore spend a round searching "AI safety policy
    2023" every single time -- the same dead shape, over and over, at full
    analysis cost -- because the planner has no way to know it has already
    failed.

    Keyed on the *shape*, not the literal string, because what matters is the
    kind of question, not its exact wording: "alignment tax" and "tax of
    alignment" are one row. Cumulative, because a shape that has produced 0
    keeps from 3 of 6 attempts says something a single round cannot.
    """
    __tablename__ = "query_shape_yields"
    __table_args__ = (UniqueConstraint("investigation_id", "shape",
                                       name="uq_query_shape_yield"),)

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    shape = Column(String(200), nullable=False, index=True)
    example = Column(String(500), nullable=True)   # a literal query of this shape
    attempts = Column(Integer, nullable=False, default=0)
    found = Column(Integer, nullable=False, default=0)     # candidates the search returned
    kept = Column(Integer, nullable=False, default=0)      # artifacts that survived analysis
    llm_calls = Column(Integer, nullable=False, default=0)  # analysis cost paid
    last_seen_at = Column(DateTime, default=_now)


class Job(Base):
    """A unit of background work, persisted so a restart does not lose it.

    Work used to start as a bare ``threading.Thread(daemon=True)``. The run row
    was written first, so the work looked like it existed, but the only record
    of the job itself lived in the thread's memory: restart the process and the
    job is gone while its ``AgentRun`` sits at "running" forever, with no error
    and nothing to retry. A queue row is the missing record.

    Three properties this buys, each of which a thread does not have:

    * **Idempotency.** ``key`` is unique, so a double-submitted form or a
      retried request re-attaches to the existing job instead of running the
      assessment twice and billing the model calls twice.
    * **Retry.** ``attempts`` and ``next_attempt_at`` survive the process, so a
      transient failure is retried with backoff instead of being lost.
    * **Recovery.** A job left ``running`` by a crash has an expired lease;
      :func:`app.jobqueue.recover_orphans` re-queues it at startup rather than
      leaving it stuck forever.

    ``lease_expires_at`` is what makes recovery safe: a job is only re-claimed
    once nobody could still be working on it, so a long assessment is not
    duplicated just because it outran a lease.
    """
    __tablename__ = "jobs"
    # Uniqueness is over *live* jobs, not over the key. A key names a unit of
    # work, and the same key legitimately comes back later: a run parked at an
    # approval gate is re-queued under its original key once approved. A plain
    # UNIQUE(key) would refuse that second enqueue forever; this index instead
    # permits the history while making double-submit impossible.
    __table_args__ = (
        Index("uq_jobs_live_key", "key", unique=True,
              sqlite_where=text("status IN ('pending','retry','running')")),
    )

    id = Column(Integer, primary_key=True, index=True)
    # Not unique on its own -- see __table_args__.
    key = Column(String(200), nullable=True, index=True)
    kind = Column(String(50), nullable=False, index=True)
    payload_json = Column(Text, nullable=True)          # JSON
    status = Column(String(20), nullable=False, default="pending", index=True)
    attempts = Column(Integer, nullable=False, default=0)
    max_attempts = Column(Integer, nullable=False, default=3)
    last_error = Column(Text, nullable=True)
    run_id = Column(Integer, ForeignKey("agent_runs.id", ondelete="SET NULL"),
                    nullable=True, index=True)
    next_attempt_at = Column(DateTime, default=_now, index=True)
    lease_expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_now)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
