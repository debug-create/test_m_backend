"""FastAPI route handlers — REST API only."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from engine.case_builder import (
    apply_feedback,
    build_shift_map,
    detect_and_build_cases,
    rank_cases,
    recompute_case,
)
from engine.context import check_auto_reopen
from engine.fusion import counterfactual_breakdown as fusion_counterfactual
from models.db_models import Case, ContextLedgerEntry, Entity, Event
from models.schemas import (
    CaseDetail,
    CaseSummary,
    ContextLedgerEntryCreate,
    ContextLedgerEntryOut,
    CounterfactualComponent,
    CounterfactualOut,
    EntityOut,
    EventCreate,
    EventExplanation,
    EventOut,
    FeedbackCreate,
    FeedbackOut,
    ShiftMapData,
)

router = APIRouter()


@router.get("/entities", response_model=list[EntityOut], tags=["entities"])
def list_entities(db: Session = Depends(get_db)):
    return db.query(Entity).order_by(Entity.id).all()


@router.get("/entities/{entity_id}", response_model=EntityOut, tags=["entities"])
def get_entity(entity_id: int, db: Session = Depends(get_db)):
    entity = db.query(Entity).filter(Entity.id == entity_id).first()
    if not entity:
        raise HTTPException(404, "Entity not found")
    return entity


@router.get(
    "/entities/{entity_id}/events",
    response_model=list[EventOut],
    tags=["entities"],
)
def list_entity_events(entity_id: int, db: Session = Depends(get_db)):
    entity = db.query(Entity).filter(Entity.id == entity_id).first()
    if not entity:
        raise HTTPException(404, "Entity not found")
    return (
        db.query(Event)
        .filter(Event.actor_id == entity_id)
        .order_by(Event.timestamp.asc())
        .all()
    )


@router.post(
    "/entities/{entity_id}/events",
    response_model=EventOut,
    status_code=201,
    tags=["entities"],
)
def ingest_entity_event(
    entity_id: int,
    body: EventCreate,
    db: Session = Depends(get_db),
):
    """Ingest one event, evaluate reopen rules, and advance detection state."""
    entity = db.query(Entity).filter(Entity.id == entity_id).first()
    if not entity:
        raise HTTPException(404, "Entity not found")

    event = Event(
        actor_id=entity_id,
        timestamp=body.timestamp,
        device_id=body.device_id,
        action=body.action.value,
        resource_id=body.resource_id,
        resource_classification=(
            body.resource_classification.value if body.resource_classification else None
        ),
        destination=body.destination,
        volume=body.volume,
        result=body.result.value,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    reopened = check_auto_reopen(db, entity_id, [event])
    for case in reopened:
        ids = list(case.event_ids or [])
        if event.id not in ids:
            ids.append(event.id)
            case.event_ids = ids
        recompute_case(db, case)

    if not reopened:
        detect_and_build_cases(db, entity_id, as_of=body.timestamp)
    return event


@router.get(
    "/entities/{entity_id}/context",
    response_model=list[ContextLedgerEntryOut],
    tags=["entities"],
)
def list_entity_context(entity_id: int, db: Session = Depends(get_db)):
    entity = db.query(Entity).filter(Entity.id == entity_id).first()
    if not entity:
        raise HTTPException(404, "Entity not found")
    return (
        db.query(ContextLedgerEntry)
        .filter(ContextLedgerEntry.actor_id == entity_id)
        .order_by(ContextLedgerEntry.valid_from.asc())
        .all()
    )


@router.post(
    "/entities/{entity_id}/context",
    response_model=ContextLedgerEntryOut,
    tags=["entities"],
)
def upsert_entity_context(
    entity_id: int,
    body: ContextLedgerEntryCreate,
    db: Session = Depends(get_db),
):
    """Add or edit a context ledger entry (live demo / judge Q&A)."""
    entity = db.query(Entity).filter(Entity.id == entity_id).first()
    if not entity:
        raise HTTPException(404, "Entity not found")

    if body.id is not None:
        entry = (
            db.query(ContextLedgerEntry)
            .filter(
                ContextLedgerEntry.id == body.id,
                ContextLedgerEntry.actor_id == entity_id,
            )
            .first()
        )
        if not entry:
            raise HTTPException(404, "Context entry not found")
        entry.reason = body.reason.value
        entry.valid_from = body.valid_from
        entry.valid_until = body.valid_until
        entry.allowed_resources = body.allowed_resources
        entry.allowed_actions = body.allowed_actions
        entry.approved_destinations = body.approved_destinations
        entry.approved_by = body.approved_by
    else:
        entry = ContextLedgerEntry(
            actor_id=entity_id,
            reason=body.reason.value,
            valid_from=body.valid_from,
            valid_until=body.valid_until,
            allowed_resources=body.allowed_resources,
            allowed_actions=body.allowed_actions,
            approved_destinations=body.approved_destinations,
            approved_by=body.approved_by,
        )
        db.add(entry)

    db.commit()
    db.refresh(entry)

    # Recompute any open cases for this actor so numbers update immediately
    cases = db.query(Case).filter(Case.actor_id == entity_id).all()
    for case in cases:
        recompute_case(db, case)

    return entry


def _case_to_detail(db: Session, case: Case) -> CaseDetail:
    case = recompute_case(db, case)
    actor = db.query(Entity).filter(Entity.id == case.actor_id).one()

    # Attach live fusion components via a fresh risk compute for transparency
    from engine.fusion import compute_risk_for_events

    events = (
        db.query(Event).filter(Event.id.in_(case.event_ids or [])).all()
        if case.event_ids
        else []
    )
    boundary = (case.feature_snapshot or {}).get("as_of")
    as_of = datetime.fromisoformat(boundary) if boundary else case.created_at
    risk = (
        compute_risk_for_events(db, case.actor_id, events, as_of=as_of)
        if events
        else {}
    )

    breakdown = []
    for b in case.explanation_breakdown or []:
        breakdown.append(
            EventExplanation(
                event_id=b["event_id"],
                timestamp=b["timestamp"],
                action=b["action"],
                resource_id=b.get("resource_id"),
                destination=b.get("destination"),
                status=b["status"],
                matched_context_ids=b.get("matched_context_ids", []),
                match_details=b.get("match_details", {}),
            )
        )

    return CaseDetail(
        id=case.id,
        actor_id=case.actor_id,
        actor_name=actor.display_name,
        created_at=case.created_at,
        status=case.status,
        raw_deviation=case.raw_deviation,
        context_coverage=case.context_coverage,
        residual_risk=case.residual_risk,
        confidence=case.confidence,
        data_quality=case.data_quality,
        residual_unresolved_count=case.residual_unresolved_count,
        primary_cause=case.primary_cause,
        evidence=case.evidence or [],
        matched_context_ids=case.matched_context_ids or [],
        unmatched_behavior=case.unmatched_behavior or [],
        event_ids=case.event_ids or [],
        change_point_timestamps=case.change_point_timestamps or [],
        explanation_breakdown=breakdown,
        baseline_weights=case.baseline_weights or {},
        feature_snapshot=case.feature_snapshot or {},
        fusion_components=risk.get("fusion_components", {}),
    )


@router.get("/cases", response_model=list[CaseSummary], tags=["cases"])
def list_cases(
    max_cases_per_day: Optional[int] = Query(None, ge=1),
    db: Session = Depends(get_db),
):
    ranked = rank_cases(db, max_cases_per_day=max_cases_per_day)
    out = []
    for item in ranked:
        c = item["case"]
        out.append(
            CaseSummary(
                id=c.id,
                actor_id=c.actor_id,
                actor_name=item["actor_name"],
                created_at=c.created_at,
                status=c.status,
                raw_deviation=c.raw_deviation,
                context_coverage=c.context_coverage,
                residual_risk=c.residual_risk,
                confidence=c.confidence,
                data_quality=c.data_quality,
                residual_unresolved_count=c.residual_unresolved_count,
                primary_cause=c.primary_cause,
                hard_rule_flag=item["hard_rule_flag"],
            )
        )
    return out


@router.get("/cases/{case_id}", response_model=CaseDetail, tags=["cases"])
def get_case(case_id: int, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    return _case_to_detail(db, case)


@router.get(
    "/cases/{case_id}/counterfactual",
    response_model=CounterfactualOut,
    tags=["cases"],
)
def get_counterfactual(case_id: int, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    case = recompute_case(db, case)
    events = (
        db.query(Event).filter(Event.id.in_(case.event_ids or [])).all()
        if case.event_ids
        else []
    )
    boundary = (case.feature_snapshot or {}).get("as_of")
    as_of = datetime.fromisoformat(boundary) if boundary else case.created_at
    result = fusion_counterfactual(db, case.actor_id, events, as_of=as_of)
    return CounterfactualOut(
        case_id=case.id,
        residual_risk=result["case_residual_risk"],
        components=[CounterfactualComponent(**c) for c in result["components"]],
    )


@router.post(
    "/cases/{case_id}/feedback",
    response_model=FeedbackOut,
    tags=["cases"],
)
def post_feedback(
    case_id: int, body: FeedbackCreate, db: Session = Depends(get_db)
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    result = apply_feedback(db, case, body.verdict.value, body.notes)
    fb = result["feedback"]
    return FeedbackOut(
        id=fb.id,
        case_id=fb.case_id,
        verdict=fb.verdict,
        notes=fb.notes,
        timestamp=fb.timestamp,
        case_status=result["case_status"],
        cohort_threshold_adjustment=result["cohort_threshold_adjustment"],
    )


@router.get(
    "/cases/{case_id}/shift-map-data",
    response_model=ShiftMapData,
    tags=["cases"],
)
def get_shift_map(case_id: int, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    case = recompute_case(db, case)
    data = build_shift_map(db, case)
    return ShiftMapData(**data)
