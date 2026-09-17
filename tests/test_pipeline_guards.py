"""Deterministic correctness guards for context, narratives, and time boundaries."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from engine.context import check_auto_reopen, evaluate_context_compatibility
from engine.fusion import compute_risk_for_events
from engine.narrative import VerdictLanguageError, assert_no_verdict_language
from models.db_models import Case, ContextLedgerEntry, Entity, Event


def _session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _event(actor_id, timestamp, *, resource="eng-repo", classification="internal"):
    return Event(
        actor_id=actor_id,
        timestamp=timestamp,
        device_id="device-1",
        action="file_access",
        resource_id=resource,
        resource_classification=classification,
        result="success",
    )


def test_indeterminate_is_separate_and_data_quality_is_sparse():
    db = _session()
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    actor = Entity(
        display_name="New Actor", role="engineering", department="Engineering",
        hire_date=start,
    )
    db.add(actor)
    db.flush()
    event = _event(actor.id, start + timedelta(days=2), classification=None)
    db.add(event)
    db.commit()

    risk = compute_risk_for_events(db, actor.id, [event], as_of=event.timestamp)
    assert risk["explanation_breakdown"][0]["status"] == "indeterminate"
    assert risk["residual_unresolved_count"] == 1
    assert risk["data_quality"] == "sparse"
    # Indeterminate evidence remains in raw-risk computation; uncertainty is
    # represented as zero coverage instead of disappearing from the model.
    assert risk["fusion_components"]["A_t"] > 0.0
    assert risk["context_coverage"] == 0.0


def test_narrative_verdict_language_guard():
    assert assert_no_verdict_language("Observed access sequence on a critical asset")
    with pytest.raises(VerdictLanguageError):
        assert_no_verdict_language("This was a suspicious access sequence")
    with pytest.raises(VerdictLanguageError):
        assert_no_verdict_language("The user is safe")


def test_as_of_prevents_future_event_leakage():
    db = _session()
    start = datetime(2026, 2, 1, tzinfo=timezone.utc)
    actor = Entity(
        display_name="Temporal Actor", role="engineering", department="Engineering",
        hire_date=start - timedelta(days=100),
    )
    db.add(actor)
    db.flush()
    for day in range(20):
        db.add(_event(actor.id, start + timedelta(days=day)))
    db.commit()
    cutoff = start + timedelta(days=19, hours=1)
    case_events = db.query(Event).filter(Event.actor_id == actor.id).all()
    before = compute_risk_for_events(db, actor.id, case_events, as_of=cutoff)

    future = Event(
        actor_id=actor.id,
        timestamp=cutoff + timedelta(days=2),
        device_id="future-device",
        action="external_upload",
        resource_id="future-critical",
        resource_classification="critical",
        destination="https://future.example/upload",
        volume=9000,
        result="success",
    )
    db.add(future)
    db.commit()
    after = compute_risk_for_events(db, actor.id, case_events + [future], as_of=cutoff)
    assert before["raw_deviation"] == after["raw_deviation"]
    assert before["residual_risk"] == after["residual_risk"]
    assert before["explanation_breakdown"] == after["explanation_breakdown"]


def test_resolved_case_reopens_for_event_outside_matched_grant():
    db = _session()
    start = datetime(2026, 3, 1, tzinfo=timezone.utc)
    actor = Entity(
        display_name="Reopen Actor", role="engineering", department="Engineering",
        hire_date=start - timedelta(days=100),
    )
    db.add(actor)
    db.flush()
    context = ContextLedgerEntry(
        actor_id=actor.id,
        reason="project",
        valid_from=start,
        valid_until=start + timedelta(days=30),
        allowed_resources=["project-repo"],
        allowed_actions=["file_access"],
        approved_destinations=None,
        approved_by="manager",
    )
    db.add(context)
    db.flush()
    case = Case(
        actor_id=actor.id,
        created_at=start,
        status="resolved",
        matched_context_ids=[context.id],
    )
    db.add(case)
    outside = _event(
        actor.id, start + timedelta(days=2), resource="finance-archive",
        classification="critical",
    )
    db.add(outside)
    db.commit()

    reopened = check_auto_reopen(db, actor.id, [outside])
    assert [item.id for item in reopened] == [case.id]
    assert case.status == "reopened"
