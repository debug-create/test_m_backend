"""Wide-range arithmetic, uncertainty, and temporal provenance guards."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from engine.case_builder import create_or_update_case
from engine.context import evaluate_context_compatibility
from engine.fusion import fuse
from models.db_models import CaseAssessment, ContextLedgerEntry, Entity, Event


@pytest.mark.parametrize("seed", range(101))
def test_residual_risk_identity_across_wide_input_range(seed):
    # Deterministic wide sweep in lieu of an optional property-test dependency.
    signals = [((seed * factor) % 101) / 100 for factor in (3, 7, 11, 17, 23)]
    coverage = seed / 100
    result = fuse(*signals, coverage)
    assert result["residual_risk"] == round(result["raw_deviation"] * (1.0 - coverage), 4)
    if coverage == 0:
        assert result["residual_risk"] == result["raw_deviation"]
    if coverage == 1:
        assert result["residual_risk"] == 0.0


def test_indeterminate_stays_in_coverage_denominator_and_unresolved_count():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    now = datetime(2026, 9, 15, tzinfo=timezone.utc)
    actor = Entity(display_name="Coverage Actor", role="engineering", department="Engineering", hire_date=now-timedelta(days=100))
    db.add(actor)
    db.flush()
    ctx = ContextLedgerEntry(actor_id=actor.id, reason="project", valid_from=now-timedelta(days=1), valid_until=now+timedelta(days=1), allowed_resources=["repo"], allowed_actions=["file_access"], approved_destinations=None, approved_by="manager")
    explained = Event(actor_id=actor.id, timestamp=now, device_id="d", action="file_access", resource_id="repo", resource_classification="internal", result="success")
    indeterminate = Event(actor_id=actor.id, timestamp=now, device_id="d", action="file_access", resource_id="unknown", resource_classification=None, result="success")
    db.add_all([ctx, explained, indeterminate])
    db.commit()
    result = evaluate_context_compatibility(db, actor.id, [explained, indeterminate], as_of=now)
    assert result["counts"] == {"explained": 1, "partially_explained": 0, "unexplained": 0, "indeterminate": 1, "total": 2}
    assert result["C_t"] == 0.5
    assert result["residual_unresolved_count"] == 1
    db.close()


def test_future_event_is_absent_from_case_and_assessment_inputs():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    cutoff = datetime(2026, 9, 15, tzinfo=timezone.utc)
    actor = Entity(display_name="Temporal Case", role="engineering", department="Engineering", hire_date=cutoff-timedelta(days=100))
    db.add(actor)
    db.flush()
    past = Event(actor_id=actor.id, timestamp=cutoff-timedelta(hours=1), device_id="d", action="file_access", resource_id="repo", resource_classification="internal", result="success")
    future = Event(actor_id=actor.id, timestamp=cutoff+timedelta(days=2), device_id="future", action="external_upload", resource_id="critical", resource_classification="critical", destination="https://outside", result="success")
    db.add_all([past, future])
    db.commit()
    case = create_or_update_case(db, actor.id, [past, future], [], as_of=cutoff)
    assessment = db.query(CaseAssessment).filter(CaseAssessment.id == case.current_assessment_id).one()
    assert case.event_ids == [past.id]
    assert assessment.input_event_ids == [past.id]
    assert future.id not in assessment.result.get("event_ids", [])
    db.close()
