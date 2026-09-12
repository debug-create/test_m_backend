"""SQLAlchemy ORM models."""

from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import relationship

from database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Entity(Base):
    __tablename__ = "entities"

    id = Column(Integer, primary_key=True, index=True)
    display_name = Column(String(128), nullable=False, unique=True)
    role = Column(String(64), nullable=False)
    department = Column(String(64), nullable=False)
    hire_date = Column(DateTime, nullable=False)
    # Read-only regime latch for change-point detector (Task 2)
    regime_state = Column(String(16), nullable=False, default="nominal")
    regime_feature = Column(String(64), nullable=True, default="overall_deviation")
    # Supporting state needed to resume a latched detector across requests.
    regime_baseline = Column(Float, nullable=True)
    regime_last_evaluated_at = Column(DateTime, nullable=True)

    events = relationship("Event", back_populates="actor")
    context_entries = relationship("ContextLedgerEntry", back_populates="actor")
    cases = relationship("Case", back_populates="actor")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    actor_id = Column(Integer, ForeignKey("entities.id"), nullable=False, index=True)
    device_id = Column(String(64), nullable=False)
    action = Column(String(32), nullable=False)
    resource_id = Column(String(128), nullable=True)
    resource_classification = Column(String(32), nullable=True)
    destination = Column(String(128), nullable=True)
    volume = Column(Integer, nullable=True)
    result = Column(String(16), nullable=False, default="success")

    actor = relationship("Entity", back_populates="events")


class ContextLedgerEntry(Base):
    __tablename__ = "context_ledger"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("entities.id"), nullable=False, index=True)
    reason = Column(String(32), nullable=False)
    valid_from = Column(DateTime, nullable=False)
    valid_until = Column(DateTime, nullable=False)
    allowed_resources = Column(JSON, nullable=False, default=list)
    allowed_actions = Column(JSON, nullable=False, default=list)
    approved_destinations = Column(JSON, nullable=True)
    approved_by = Column(String(128), nullable=False)

    actor = relationship("Entity", back_populates="context_entries")


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("entities.id"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    status = Column(String(32), nullable=False, default="open")
    # Persisted snapshots — recomputed on every detail fetch from live modules
    raw_deviation = Column(Float, nullable=False, default=0.0)
    context_coverage = Column(Float, nullable=False, default=0.0)
    residual_risk = Column(Float, nullable=False, default=0.0)
    confidence = Column(String(16), nullable=False, default="moderate")
    data_quality = Column(String(16), nullable=False, default="sufficient")
    residual_unresolved_count = Column(Integer, nullable=False, default=0)
    primary_cause = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=False, default=list)
    matched_context_ids = Column(JSON, nullable=False, default=list)
    unmatched_behavior = Column(JSON, nullable=False, default=list)
    # Supporting JSON for API detail (event ids, breakdown, weights, etc.)
    event_ids = Column(JSON, nullable=False, default=list)
    change_point_timestamps = Column(JSON, nullable=False, default=list)
    explanation_breakdown = Column(JSON, nullable=False, default=list)
    baseline_weights = Column(JSON, nullable=False, default=dict)
    feature_snapshot = Column(JSON, nullable=False, default=dict)

    actor = relationship("Entity", back_populates="cases")
    feedback = relationship("AnalystFeedback", back_populates="case")


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    verdict = Column(String(32), nullable=False)
    notes = Column(Text, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=utcnow)

    case = relationship("Case", back_populates="feedback")


class CohortThreshold(Base):
    """Adjustable per-role ranking threshold (not a model retrain)."""

    __tablename__ = "cohort_thresholds"

    id = Column(Integer, primary_key=True, index=True)
    role = Column(String(64), nullable=False, unique=True, index=True)
    threshold = Column(Float, nullable=False, default=40.0)
    updated_at = Column(DateTime, nullable=False, default=utcnow)
