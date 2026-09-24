from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey
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


class AgentRun(Base):
    __tablename__ = "agent_runs"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    status = Column(String(20), nullable=False, default="running")  # running|done|error
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
