"""Authenticated REST routes with immutable context and case history."""

from __future__ import annotations

from datetime import datetime, timezone
from copy import deepcopy
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from engine.case_builder import (
    apply_feedback, build_shift_map, detect_and_build_cases, rank_cases, recompute_case,
)
from engine.context import check_auto_reopen, match_event_against_entry
from engine.fusion import combine_signal_categories, fuse_event_residuals
from engine.response_graph import build_evidence_graph
from engine.response_service import (
    approve_action, create_action, execute_action, preview_action, reject_action,
    rollback_action,
)
from engine.sandbox_enforcement import enforcement_state
from models.db_models import (
    AuditLog, Case, ContextLedgerEntry, Entity, Event, ResponseAction,
)
from models.schemas import (
    CaseDetail, CaseSummary, ContextLedgerEntryCreate, ContextLedgerEntryOut,
    ContextReview, CounterfactualComponent, CounterfactualOut, EntityOut,
    EventCreate, EventExplanation, EventOut, FeedbackCreate, FeedbackOut, ShiftMapData,
    EvidenceGraphOut, ResponseActionDecision, ResponseActionOut,
    ResponseActionPreviewRequest, ResponseActionRequest, ResponsePreviewOut,
)
from security import Principal, require_scope

router = APIRouter(dependencies=[Depends(require_scope("read"))])


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _entity_or_404(db: Session, entity_ref: str) -> Entity:
    entity = db.query(Entity).filter(Entity.pseudonymous_id == entity_ref).first()
    if not entity:
        raise HTTPException(404, "Entity not found")
    return entity


def _entity_out(entity: Entity) -> EntityOut:
    return EntityOut(
        entity_ref=entity.pseudonymous_id, role=entity.role,
        department=entity.department, hire_date=entity.hire_date,
        regime_state=entity.regime_state, regime_feature=entity.regime_feature,
    )


def _event_out(event: Event, actor: Entity) -> EventOut:
    return EventOut(
        id=event.id, timestamp=event.timestamp, actor_ref=actor.pseudonymous_id,
        device_id=event.device_id, action=event.action, resource_id=event.resource_id,
        resource_classification=event.resource_classification,
        destination=event.destination, latitude=event.latitude,
        longitude=event.longitude, volume=event.volume, result=event.result,
    )


def _context_out(entry: ContextLedgerEntry, actor: Entity) -> ContextLedgerEntryOut:
    return ContextLedgerEntryOut(
        id=entry.id, actor_ref=actor.pseudonymous_id, reason=entry.reason,
        valid_from=entry.valid_from, valid_until=entry.valid_until,
        effective_from=entry.effective_from or entry.valid_from,
        effective_until=entry.effective_until or entry.valid_until,
        allowed_resources=entry.allowed_resources or [],
        allowed_actions=entry.allowed_actions or [],
        approved_destinations=entry.approved_destinations,
        approved_by=entry.approved_by, approval_state=entry.approval_state,
        supersedes_id=entry.supersedes_id, proposed_by=entry.proposed_by,
        proposed_at=entry.proposed_at or entry.valid_from,
        reviewed_by=entry.reviewed_by, reviewed_at=entry.reviewed_at,
        review_note=entry.review_note,
        created_at=entry.proposed_at or entry.valid_from,
        approved_at=entry.reviewed_at,
        late_context=bool(entry.late_context),
    )


def _audit(db: Session, principal: Principal, action: str, resource_type: str,
           resource_id: str | int | None, **details) -> None:
    db.add(AuditLog(
        principal=principal.subject, action=action, resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        details=details, succeeded=True,
    ))


def _response_action_out(action: ResponseAction) -> ResponseActionOut:
    return ResponseActionOut(
        action_id=action.action_id, case_id=action.case_id, entity_ref=action.entity_ref,
        action_type=action.action_type, status=action.status, mode=action.mode,
        requested_by=action.requested_by, requested_at=action.requested_at,
        approved_by=action.approved_by, approved_at=action.approved_at,
        executed_at=action.executed_at, expires_at=action.expires_at,
        rolled_back_at=action.rolled_back_at, failed_at=action.failed_at,
        assessment_id=action.assessment_id, scoring_version=action.scoring_version,
        trigger_event_ids=action.trigger_event_ids or [],
        policy_rule_id=action.policy_rule_id, policy_decision=action.policy_decision,
        policy_reasons=action.policy_reasons or [],
        evidence_categories=action.evidence_categories or [],
        target_scope=action.target_scope or {}, blast_radius=action.blast_radius or {},
        approval_required=action.approval_required, automatic=action.automatic,
        idempotency_key=action.idempotency_key,
        execution_result=action.execution_result,
        verification_result=action.verification_result,
        rollback_result=action.rollback_result, failure_reason=action.failure_reason,
        transitions=[{
            "id": row.id, "from_status": row.from_status, "to_status": row.to_status,
            "principal": row.principal, "timestamp": row.timestamp,
            "note": row.note, "details": row.details,
        } for row in action.transitions],
    )


def _action_or_404(db: Session, action_id: str) -> ResponseAction:
    action = db.query(ResponseAction).filter(ResponseAction.action_id == action_id).first()
    if action is None:
        raise HTTPException(404, "Response action not found")
    return action


@router.get("/entities", response_model=list[EntityOut], tags=["entities"])
def list_entities(db: Session = Depends(get_db)):
    return [_entity_out(e) for e in db.query(Entity).order_by(Entity.id).all()]


@router.get("/entities/{entity_ref}", response_model=EntityOut, tags=["entities"])
def get_entity(entity_ref: str, db: Session = Depends(get_db)):
    return _entity_out(_entity_or_404(db, entity_ref))


@router.get("/entities/{entity_ref}/events", response_model=list[EventOut], tags=["entities"])
def list_entity_events(entity_ref: str, db: Session = Depends(get_db)):
    actor = _entity_or_404(db, entity_ref)
    events = db.query(Event).filter(Event.actor_id == actor.id).order_by(Event.timestamp).all()
    return [_event_out(event, actor) for event in events]


@router.post("/entities/{entity_ref}/events", response_model=EventOut, status_code=201, tags=["entities"])
def ingest_entity_event(
    entity_ref: str, body: EventCreate, db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("events:write")),
):
    actor = _entity_or_404(db, entity_ref)
    event = Event(
        actor_id=actor.id, timestamp=body.timestamp, device_id=body.device_id,
        action=body.action.value, resource_id=body.resource_id,
        resource_classification=body.resource_classification.value if body.resource_classification else None,
        destination=body.destination, latitude=body.latitude, longitude=body.longitude,
        volume=body.volume, result=body.result.value,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    reopened = check_auto_reopen(db, actor.id, [event])
    for case in reopened:
        ids = list(case.event_ids or [])
        if event.id not in ids:
            ids.append(event.id)
            case.event_ids = ids
        recompute_case(db, case, trigger="event_ingested")
    if not reopened:
        detect_and_build_cases(db, actor.id, as_of=body.timestamp)
    from access_control.monitoring import monitor_event_against_active_grants
    monitor_event_against_active_grants(
        db, event, actor.pseudonymous_id, principal.tenant_id
    )
    _audit(db, principal, "event.ingest", "event", event.id, actor_ref=entity_ref)
    db.commit()
    return _event_out(event, actor)


@router.get("/entities/{entity_ref}/context", response_model=list[ContextLedgerEntryOut], tags=["entities"])
def list_entity_context(entity_ref: str, db: Session = Depends(get_db)):
    actor = _entity_or_404(db, entity_ref)
    entries = db.query(ContextLedgerEntry).filter(
        ContextLedgerEntry.actor_id == actor.id
    ).order_by(ContextLedgerEntry.proposed_at, ContextLedgerEntry.id).all()
    return [_context_out(entry, actor) for entry in entries]


@router.post("/entities/{entity_ref}/context", response_model=ContextLedgerEntryOut, status_code=202, tags=["entities"])
def propose_entity_context(
    entity_ref: str, body: ContextLedgerEntryCreate, db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("context:propose")),
):
    """Append a pending proposal. It cannot affect assessments before approval."""
    actor = _entity_or_404(db, entity_ref)
    if body.effective_until <= body.effective_from:
        raise HTTPException(422, "effective_until must be after effective_from")
    if body.supersedes_id is not None:
        previous = db.query(ContextLedgerEntry).filter(
            ContextLedgerEntry.id == body.supersedes_id,
            ContextLedgerEntry.actor_id == actor.id,
            ContextLedgerEntry.approval_state == "approved",
        ).first()
        if previous is None:
            raise HTTPException(409, "supersedes_id must identify an approved entry for this entity")
    entry = ContextLedgerEntry(
        actor_id=actor.id, reason=body.reason.value,
        valid_from=body.effective_from, valid_until=body.effective_until,
        effective_from=body.effective_from, effective_until=body.effective_until,
        allowed_resources=list(body.allowed_resources),
        allowed_actions=list(body.allowed_actions),
        approved_destinations=body.approved_destinations, approved_by="pending",
        approval_state="pending", supersedes_id=body.supersedes_id,
        proposed_by=principal.subject, proposed_at=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.flush()
    _audit(db, principal, "context.propose", "context", entry.id,
           actor_ref=entity_ref, supersedes_id=body.supersedes_id)
    db.commit()
    db.refresh(entry)
    return _context_out(entry, actor)


@router.post("/context/{entry_id}/review", response_model=ContextLedgerEntryOut, tags=["context"])
def review_context(
    entry_id: int, body: ContextReview, db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("context:approve")),
):
    entry = db.query(ContextLedgerEntry).filter(ContextLedgerEntry.id == entry_id).first()
    if entry is None:
        raise HTTPException(404, "Context proposal not found")
    if entry.approval_state != "pending":
        raise HTTPException(409, "Context proposal has already been reviewed")
    if entry.proposed_by == principal.subject:
        raise HTTPException(403, "A proposer cannot approve their own context change")
    entry.approval_state = body.decision
    entry.reviewed_by = principal.subject
    entry.reviewed_at = datetime.now(timezone.utc)
    entry.review_note = body.note
    actor = db.query(Entity).filter(Entity.id == entry.actor_id).one()
    if body.decision == "approved":
        entry.approved_by = principal.subject
        approved_at = datetime.now(timezone.utc)
        entry.reviewed_at = approved_at
        effective_start = entry.effective_from or entry.valid_from
        effective_end = entry.effective_until or entry.valid_until
        potentially_covered = db.query(Event).filter(
            Event.actor_id == entry.actor_id,
            Event.timestamp >= effective_start,
            Event.timestamp <= effective_end,
            Event.timestamp < approved_at,
        ).all()
        entry.late_context = any(
            match_event_against_entry(event, entry)["status"]
            in {"explained", "partially_explained"}
            for event in potentially_covered
        )
        affected_ranges = [(effective_start, effective_end)]
        if entry.supersedes_id is not None:
            previous = db.query(ContextLedgerEntry).filter(
                ContextLedgerEntry.id == entry.supersedes_id,
                ContextLedgerEntry.actor_id == entry.actor_id,
                ContextLedgerEntry.approval_state == "approved",
            ).first()
            if previous is None:
                raise HTTPException(409, "The entry being superseded is no longer active")
            affected_ranges.append((previous.effective_from or previous.valid_from,
                                    previous.effective_until or previous.valid_until))
            previous.approval_state = "superseded"
        db.flush()
        for case in db.query(Case).filter(Case.actor_id == entry.actor_id).all():
            events = [link.event for link in case.event_links]
            if not events and case.event_ids:
                events = db.query(Event).filter(Event.id.in_(case.event_ids)).all()
            if any(
                _aware(start) <= _aware(event.timestamp) <= _aware(end)
                for event in events for start, end in affected_ranges
            ):
                coverage_before = case.context_coverage
                recompute_case(db, case, trigger="context_approved", commit=False)
                if entry.late_context and case.context_coverage - coverage_before >= 0.25:
                    case.retroactive_justification_review = True
    _audit(db, principal, f"context.{body.decision}", "context", entry.id,
           actor_ref=actor.pseudonymous_id, note=body.note)
    db.commit()
    db.refresh(entry)
    return _context_out(entry, actor)


def _case_to_detail(db: Session, case: Case) -> CaseDetail:
    actor = db.query(Entity).filter(Entity.id == case.actor_id).one()
    breakdown = [EventExplanation(**b) for b in (case.explanation_breakdown or [])]
    assessments = sorted(case.assessments, key=lambda item: (item.created_at, item.id))

    def assessment_view(item):
        if item is None:
            return {}
        return {
            "id": item.id, "created_at": item.created_at, "trigger": item.trigger,
            "input_event_ids": item.input_event_ids,
            "context_entry_ids": item.context_entry_ids, **(item.result or {}),
        }

    return CaseDetail(
        id=case.id, actor_ref=actor.pseudonymous_id, created_at=case.created_at,
        status=case.status, raw_deviation=case.raw_deviation,
        context_coverage=case.context_coverage, residual_risk=case.residual_risk,
        confidence=case.confidence, data_quality=case.data_quality,
        residual_unresolved_count=case.residual_unresolved_count,
        primary_cause=case.primary_cause, evidence=case.evidence or [],
        matched_context_ids=case.matched_context_ids or [],
        unmatched_behavior=case.unmatched_behavior or [], event_ids=case.event_ids or [],
        change_point_timestamps=case.change_point_timestamps or [],
        explanation_breakdown=breakdown, baseline_weights=case.baseline_weights or {},
        feature_snapshot=case.feature_snapshot or {}, fusion_components=case.fusion_components or {},
        event_risk_breakdown=case.event_risk_breakdown or [],
        retroactive_justification_review=bool(case.retroactive_justification_review),
        original_assessment=assessment_view(assessments[0] if assessments else None),
        current_assessment=assessment_view(assessments[-1] if assessments else None),
    )


@router.get("/cases", response_model=list[CaseSummary], tags=["cases"])
def list_cases(max_cases_per_day: Optional[int] = Query(None, ge=1), db: Session = Depends(get_db)):
    return [CaseSummary(
        id=item["case"].id, actor_ref=item["actor_ref"],
        created_at=item["case"].created_at, status=item["case"].status,
        raw_deviation=item["case"].raw_deviation,
        context_coverage=item["case"].context_coverage,
        residual_risk=item["case"].residual_risk,
        confidence=item["case"].confidence, data_quality=item["case"].data_quality,
        residual_unresolved_count=item["case"].residual_unresolved_count,
        primary_cause=item["case"].primary_cause, hard_rule_flag=item["hard_rule_flag"],
    ) for item in rank_cases(db, max_cases_per_day=max_cases_per_day)]


@router.get("/cases/{case_id}", response_model=CaseDetail, tags=["cases"])
def get_case(case_id: int, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    return _case_to_detail(db, case)


@router.get("/cases/{case_id}/counterfactual", response_model=CounterfactualOut, tags=["cases"])
def get_counterfactual(case_id: int, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    labels = {
        "privilege_escalation": ("Identity/privilege constituent removed", "privilege", "identity_privilege_signal"),
        "sensitive_access": ("Asset-sensitivity constituent removed", "resource_access", "asset_sensitivity"),
        "suspicious_sequence": ("Sequence constituent removed", "temporal_sequence", "sequence_strength"),
        "self_deviation": ("Self-baseline constituent removed", "resource_access", "personal_deviation"),
        "peer_deviation": ("Peer-baseline constituent removed", "resource_access", "cluster_deviation"),
        "behavior_anomaly_model": ("Offline Isolation Forest constituent removed", "identity", "behavior_anomaly_model"),
        "login_risk": ("Login-risk constituent removed", "identity", "login_risk"),
        "context": ("Evidence coverage removed (raw path)", None, None),
    }
    components = []
    for name, (description, category_name, signal_name) in labels.items():
        event_inputs = []
        for row in case.event_risk_breakdown or []:
            categories = deepcopy(row.get("categories") or {})
            credit = 0.0 if name == "context" else float(row.get("context_credit", 0.0))
            if category_name in categories:
                categories[category_name].setdefault("signals", {})[signal_name] = 0.0
            event_inputs.append({
                "event_id": row["event_id"],
                "raw_risk": combine_signal_categories(categories),
                "context_credit": credit,
                "critical_reasons": row.get("critical_reasons", []),
                "categories": categories,
            })
        result = fuse_event_residuals(event_inputs)
        components.append(CounterfactualComponent(
            component=name, description=description,
            residual_risk_without=result["residual_risk"],
            delta=round(case.residual_risk - result["residual_risk"], 4),
        ))
    return CounterfactualOut(case_id=case.id, residual_risk=case.residual_risk, components=components)


@router.post("/cases/{case_id}/feedback", response_model=FeedbackOut, tags=["cases"])
def post_feedback(
    case_id: int, body: FeedbackCreate, db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("feedback:write")),
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    result = apply_feedback(db, case, body.verdict.value, body.notes)
    _audit(db, principal, "case.feedback", "case", case_id, verdict=body.verdict.value)
    db.commit()
    fb = result["feedback"]
    return FeedbackOut(id=fb.id, case_id=fb.case_id, verdict=fb.verdict, notes=fb.notes,
                       timestamp=fb.timestamp, case_status=result["case_status"],
                       cohort_threshold_adjustment=result["cohort_threshold_adjustment"])


@router.get("/cases/{case_id}/shift-map-data", response_model=ShiftMapData, tags=["cases"])
def get_shift_map(case_id: int, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    return ShiftMapData(**build_shift_map(db, case))


@router.get(
    "/cases/{case_id}/response-actions", response_model=list[ResponseActionOut],
    tags=["response"],
)
def list_response_actions(case_id: int, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    return [_response_action_out(item) for item in db.query(ResponseAction).filter(
        ResponseAction.case_id == case_id
    ).order_by(ResponseAction.requested_at, ResponseAction.action_id).all()]


@router.post(
    "/cases/{case_id}/response-actions/preview", response_model=ResponsePreviewOut,
    tags=["response"],
)
def preview_response_action(
    case_id: int, body: ResponseActionPreviewRequest, db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("response:preview")),
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    try:
        return ResponsePreviewOut(**preview_action(
            db, case, body.action_type.value, body.target_scope
        ))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post(
    "/cases/{case_id}/response-actions", response_model=ResponseActionOut,
    status_code=201, tags=["response"],
)
def request_response_action(
    case_id: int, body: ResponseActionRequest, db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("response:request")),
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    try:
        action = create_action(
            db, case, body.action_type.value, body.target_scope,
            body.idempotency_key, principal.subject, note=body.note,
        )
        db.commit()
        db.refresh(action)
        return _response_action_out(action)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc


@router.post(
    "/response-actions/{action_id}/approve", response_model=ResponseActionOut,
    tags=["response"],
)
def approve_response_action(
    action_id: str, body: ResponseActionDecision, db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("response:approve")),
):
    action = _action_or_404(db, action_id)
    try:
        approve_action(db, action, principal.subject, body.note)
        db.commit()
        db.refresh(action)
        return _response_action_out(action)
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc


@router.post(
    "/response-actions/{action_id}/reject", response_model=ResponseActionOut,
    tags=["response"],
)
def reject_response_action(
    action_id: str, body: ResponseActionDecision, db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("response:approve")),
):
    action = _action_or_404(db, action_id)
    try:
        reject_action(db, action, principal.subject, body.note)
        db.commit()
        db.refresh(action)
        return _response_action_out(action)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc


@router.post(
    "/response-actions/{action_id}/execute", response_model=ResponseActionOut,
    tags=["response"],
)
def execute_response_action(
    action_id: str, db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("response:execute")),
):
    action = _action_or_404(db, action_id)
    if action.status not in {"auto_authorized", "approved", "executing", "active"}:
        raise HTTPException(409, f"Action cannot execute from status {action.status}")
    try:
        execute_action(db, action, principal.subject)
        db.commit()
        db.refresh(action)
        return _response_action_out(action)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc


@router.post(
    "/response-actions/{action_id}/rollback", response_model=ResponseActionOut,
    tags=["response"],
)
def rollback_response_action(
    action_id: str, body: ResponseActionDecision, db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("response:rollback")),
):
    action = _action_or_404(db, action_id)
    try:
        rollback_action(db, action, principal.subject, note=body.note)
        db.commit()
        db.refresh(action)
        return _response_action_out(action)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc


@router.get(
    "/cases/{case_id}/evidence-graph", response_model=EvidenceGraphOut,
    tags=["response"],
)
def get_evidence_graph(case_id: int, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    return EvidenceGraphOut(**build_evidence_graph(db, case))


@router.get("/admin/enforcement-state", tags=["admin", "response"])
def get_enforcement_state(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("enforcement:read")),
):
    return {"mode": "sandbox", "simulated": True, "controls": enforcement_state(db)}


@router.get("/admin/audit", tags=["admin"])
def list_audit_log(
    limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("audit:read")),
):
    rows = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()
    return [{"id": r.id, "timestamp": r.timestamp, "principal": r.principal,
             "action": r.action, "resource_type": r.resource_type,
             "resource_id": r.resource_id, "details": r.details} for r in rows]


@router.post("/admin/reseed", tags=["admin"])
def reseed(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_scope("admin:reseed")),
):
    if os.getenv("FABLE_ENABLE_RESEED", "").lower() not in {"1", "true", "yes"}:
        raise HTTPException(404, "Not found")
    from seed.scenarios import clear_all, run_seed
    clear_all(db, preserve_audit=True)
    run_seed(db)
    _audit(db, principal, "admin.reseed", "database", None)
    db.commit()
    return {"status": "reseeded"}
