from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey, UniqueConstraint
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
