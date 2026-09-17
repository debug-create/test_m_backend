"""Case construction, ranking, and recomputation from live modules."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from config import PH_DELTA, WINDOW_24H
from engine.baseline import compute_baseline_deviation
from engine.changepoint import detect_change_points
from engine.context import check_auto_reopen, evaluate_context_compatibility
from engine.fusion import compute_risk_for_events, counterfactual_breakdown
from models.db_models import Case, CaseAssessment, CaseEvent, CohortThreshold, Entity, Event
from models.enums import CaseStatus


def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def build_deviation_series(
    db: Session, actor_id: int, as_of: datetime, days: int = 30, step_hours: int = 12
) -> tuple[list[float], list[datetime]]:
    """Rolling overall_deviation scores for Page-Hinkley input."""
    values: list[float] = []
    timestamps: list[datetime] = []
    start = as_of - timedelta(days=days)
    t = start
    while t <= as_of:
        has = (
            db.query(Event.id)
            .filter(Event.actor_id == actor_id, Event.timestamp <= t)
            .first()
        )
        if has:
            try:
                bas = compute_baseline_deviation(db, actor_id, as_of=t)
                values.append(float(bas["overall_deviation"]))
                timestamps.append(t)
            except Exception:
                pass
        t += timedelta(hours=step_hours)
    return values, timestamps


def collect_transition_events(
    db: Session,
    actor_id: int,
    change_point: datetime,
    window_hours: int = 48,
    as_of: Optional[datetime] = None,
) -> list[Event]:
    """Bundle correlated events around a detected change point."""
    start = change_point - timedelta(hours=6)
    end = change_point + timedelta(hours=window_hours)
    if as_of is not None:
        end = min(end, _ensure_aware(as_of))
    return (
        db.query(Event)
        .filter(
            Event.actor_id == actor_id,
            Event.timestamp >= start,
            Event.timestamp <= end,
        )
        .order_by(Event.timestamp.asc())
        .all()
    )


def select_unusual_events(events: list[Event], lookback: list[Event]) -> list[Event]:
    """Prefer events that look unusual vs prior history; fall back to all."""
    known_devices = {e.device_id for e in lookback}
    known_resources = {e.resource_id for e in lookback if e.resource_id}
    known_dests = {e.destination for e in lookback if e.destination}

    unusual = []
    for e in events:
        is_unusual = False
        if e.device_id not in known_devices:
            is_unusual = True
        if e.resource_id and e.resource_id not in known_resources:
            is_unusual = True
        if e.destination and e.destination not in known_dests:
            is_unusual = True
        if e.action in ("privilege_change", "external_upload"):
            is_unusual = True
        if (e.resource_classification or "") in ("restricted", "critical"):
            is_unusual = True
        if e.action in ("file_download",) and (e.volume or 0) > 500:
            is_unusual = True
        if is_unusual:
            unusual.append(e)
    return unusual or list(events)


HARD_RULE_CRITICAL_NO_CONTEXT = "critical_access_zero_context"


def hard_rule_flag(case: Case, breakdown: list[dict], events: list[Event]) -> bool:
    """Deterministic hard rule: an unexplained event on a critical resource."""
    return hard_rule_from_events(events, breakdown)


def hard_rule_from_events(events: list[Event], breakdown: list[dict]) -> bool:
    unexplained_ids = {
        b["event_id"] for b in breakdown if b.get("status") == "unexplained"
    }
    for e in events:
        if e.id in unexplained_ids and (e.resource_classification or "") == "critical":
            return True
    return False


def create_or_update_case(
    db: Session,
    actor_id: int,
    events: list[Event],
    change_points: list[str],
    as_of: Optional[datetime] = None,
) -> Case:
    """Run modules 4–6 and persist a Case with live-computed scores."""
    as_of = _ensure_aware(as_of or datetime.now(timezone.utc))
    events = [event for event in events if _ensure_aware(event.timestamp) <= as_of]
    risk = compute_risk_for_events(db, actor_id, events, as_of=as_of)

    # Find existing open/reopened/reviewing case for this actor to update
    existing = (
        db.query(Case)
        .filter(
            Case.actor_id == actor_id,
            Case.status.in_(["open", "reopened", "reviewing"]),
        )
        .order_by(Case.created_at.desc())
        .first()
    )

    payload = dict(
        raw_deviation=risk["raw_deviation"],
        context_coverage=risk["context_coverage"],
        residual_risk=risk["residual_risk"],
        confidence=risk["confidence"],
        data_quality=risk["data_quality"],
        residual_unresolved_count=risk["residual_unresolved_count"],
        primary_cause=risk["primary_cause"],
        evidence=risk["evidence"],
        matched_context_ids=risk["matched_context_ids"],
        unmatched_behavior=risk["unmatched_behavior"],
        event_ids=[e.id for e in events],
        change_point_timestamps=change_points,
        explanation_breakdown=risk["explanation_breakdown"],
        baseline_weights=risk["baseline_weights"],
        feature_snapshot=risk["feature_snapshot"],
        fusion_components=risk["fusion_components"],
        event_risk_breakdown=risk["event_risk_breakdown"],
    )

    if existing:
        for k, v in payload.items():
            setattr(existing, k, v)
        case = existing
    else:
        case = Case(actor_id=actor_id, status="open", created_at=as_of, **payload)
        db.add(case)
    db.flush()
    _record_assessment(db, case, risk, events, trigger="detection")
    db.commit()
    db.refresh(case)
    return case


def _record_assessment(
    db: Session, case: Case, risk: dict[str, Any], events: list[Event], trigger: str
) -> None:
    """Append an immutable assessment and synchronize relational evidence links."""
    event_id_set = {e.id for e in events if e.id is not None}
    event_ids = sorted(event_id_set)
    existing_ids = {link.event_id for link in case.event_links}
    for event_id in event_id_set - existing_ids:
        db.add(CaseEvent(case_id=case.id, event_id=event_id))
    for link in list(case.event_links):
        if link.event_id not in event_id_set:
            db.delete(link)

    result = {
        key: risk[key]
        for key in (
            "raw_deviation", "context_coverage", "residual_risk", "confidence",
            "data_quality", "residual_unresolved_count", "primary_cause", "evidence",
            "matched_context_ids", "unmatched_behavior", "explanation_breakdown",
            "baseline_weights", "feature_snapshot", "fusion_components",
            "event_risk_breakdown",
        )
    }
    assessment = CaseAssessment(
        case_id=case.id,
        trigger=trigger,
        input_event_ids=event_ids,
        context_entry_ids=risk["context"]["considered_context_ids"],
        result=result,
    )
    db.add(assessment)
    db.flush()
    case.current_assessment_id = assessment.id


def recompute_case(
    db: Session, case: Case, *, trigger: str = "explicit_recompute", commit: bool = True
) -> Case:
    """
    Re-run modules 2–6 after an authorized input-state transition and append
    a versioned assessment. Read handlers never call this function.
    """
    events = (
        db.query(Event).filter(Event.id.in_(case.event_ids or [])).all()
        if case.event_ids
        else []
    )
    if not events:
        # Fall back to recent events around case creation
        start = _ensure_aware(case.created_at) - timedelta(hours=48)
        end = _ensure_aware(case.created_at) + timedelta(hours=48)
        events = (
            db.query(Event)
            .filter(
                Event.actor_id == case.actor_id,
                Event.timestamp >= start,
                Event.timestamp <= end,
            )
            .all()
        )

    as_of = max(
        [_ensure_aware(case.created_at)]
        + [_ensure_aware(e.timestamp) for e in events]
    )
    risk = compute_risk_for_events(db, case.actor_id, events, as_of=as_of)

    case.raw_deviation = risk["raw_deviation"]
    case.context_coverage = risk["context_coverage"]
    case.residual_risk = risk["residual_risk"]
    case.confidence = risk["confidence"]
    case.data_quality = risk["data_quality"]
    case.residual_unresolved_count = risk["residual_unresolved_count"]
    case.primary_cause = risk["primary_cause"]
    case.evidence = risk["evidence"]
    case.matched_context_ids = risk["matched_context_ids"]
    case.unmatched_behavior = risk["unmatched_behavior"]
    case.event_ids = [e.id for e in events]
    case.explanation_breakdown = risk["explanation_breakdown"]
    case.baseline_weights = risk["baseline_weights"]
    case.feature_snapshot = risk["feature_snapshot"]
    case.fusion_components = risk["fusion_components"]
    case.event_risk_breakdown = risk["event_risk_breakdown"]

    _record_assessment(db, case, risk, events, trigger=trigger)

    if commit:
        db.commit()
    else:
        db.flush()
    db.refresh(case)
    return case


def detect_and_build_cases(
    db: Session, actor_id: int, as_of: Optional[datetime] = None
) -> Optional[Case]:
    """Full pipeline for one actor: series → Page-Hinkley → events → fusion → Case."""
    as_of = _ensure_aware(as_of or datetime.now(timezone.utc))
    actor = db.query(Entity).filter(Entity.id == actor_id).one()
    values, timestamps = build_deviation_series(db, actor_id, as_of)
    if len(values) < 5:
        return None

    # A persisted latch suppresses repeated detections on the same plateau.
    # Five consecutive samples near the stored pre-shift baseline re-arm it.
    if actor.regime_state == "latched":
        baseline = float(actor.regime_baseline or values[0])
        tolerance = max(PH_DELTA * 3.0, abs(baseline) * 0.25 + 0.1)
        recent = values[-5:]
        if len(recent) >= 5 and all(abs(v - baseline) <= tolerance for v in recent):
            actor.regime_state = "nominal"
            actor.regime_last_evaluated_at = as_of
            db.commit()
        else:
            actor.regime_last_evaluated_at = as_of
            db.commit()
        return None

    # After a re-arm, only evaluate samples from the new nominal regime.
    if actor.regime_last_evaluated_at is not None:
        cutoff = _ensure_aware(actor.regime_last_evaluated_at)
        fresh = [(v, t) for v, t in zip(values, timestamps) if _ensure_aware(t) > cutoff]
        values = [v for v, _ in fresh]
        timestamps = [t for _, t in fresh]
        if len(values) < 5:
            return None

    ph = detect_change_points(values, timestamps=timestamps)
    cp_ts = ph["change_point_timestamps"]

    if not cp_ts:
        # Still build a case if recent residual risk would be high:
        # use the last 48h of unusual events as a candidate transition
        window_start = as_of - timedelta(hours=48)
        recent = (
            db.query(Event)
            .filter(
                Event.actor_id == actor_id,
                Event.timestamp >= window_start,
                Event.timestamp <= as_of,
            )
            .all()
        )
        lookback = (
            db.query(Event)
            .filter(
                Event.actor_id == actor_id,
                Event.timestamp < window_start,
            )
            .all()
        )
        unusual = select_unusual_events(recent, lookback)
        if not unusual:
            return None
        risk_probe = compute_risk_for_events(db, actor_id, unusual, as_of=as_of)
        if risk_probe["raw_deviation"] < 35:
            return None
        return create_or_update_case(db, actor_id, unusual, [], as_of=as_of)

    # Use the latest change point
    last_cp = _ensure_aware(datetime.fromisoformat(cp_ts[-1]))
    cp_index = ph["change_point_indices"][-1]
    prior = values[max(0, cp_index - 5):cp_index]
    actor.regime_state = "latched"
    actor.regime_feature = ph["feature_key"]
    actor.regime_baseline = sum(prior) / len(prior) if prior else values[0]
    actor.regime_last_evaluated_at = as_of
    db.commit()

    bundled = collect_transition_events(db, actor_id, last_cp, as_of=as_of)
    lookback = (
        db.query(Event)
        .filter(
            Event.actor_id == actor_id,
            Event.timestamp < last_cp - timedelta(hours=6),
        )
        .all()
    )
    unusual = select_unusual_events(bundled, lookback)
    return create_or_update_case(db, actor_id, unusual, cp_ts, as_of=as_of)


def rank_cases(
    db: Session, max_cases_per_day: Optional[int] = None
) -> list[dict[str, Any]]:
    """
    Alert-budget ranking: top-N by residual_risk, always including hard-rule flags.
    """
    cases = (
        db.query(Case)
        .filter(Case.status.in_(["open", "reopened", "reviewing"]))
        .all()
    )

    # Ranking is a read: use the latest committed immutable assessment snapshot.
    enriched = []
    for case in cases:
        events = [link.event for link in case.event_links]
        if not events and case.event_ids:
            events = db.query(Event).filter(Event.id.in_(case.event_ids)).all()
        breakdown = case.explanation_breakdown or []
        flagged = hard_rule_from_events(events, breakdown)
        actor = db.query(Entity).filter(Entity.id == case.actor_id).one()
        thr = (
            db.query(CohortThreshold)
            .filter(CohortThreshold.role == actor.role)
            .first()
        )
        threshold = thr.threshold if thr else 40.0
        enriched.append(
            {
                "case": case,
                "actor_ref": actor.pseudonymous_id,
                "hard_rule_flag": flagged,
                "cohort_threshold": threshold,
                "above_threshold": case.residual_risk >= threshold,
            }
        )

    # Sort by residual_risk desc
    enriched.sort(key=lambda x: x["case"].residual_risk, reverse=True)

    if max_cases_per_day is None:
        selected = enriched
    else:
        top = enriched[:max_cases_per_day]
        top_ids = {x["case"].id for x in top}
        # Always include hard-rule flags
        for x in enriched:
            if x["hard_rule_flag"] and x["case"].id not in top_ids:
                top.append(x)
                top_ids.add(x["case"].id)
        selected = top

    return selected


def apply_feedback(
    db: Session, case: Case, verdict: str, notes: Optional[str] = None
) -> dict[str, Any]:
    """
    Update case status from verdict and nudge the per-role cohort threshold.
    This is NOT a model retrain — only a stored adjustable numeric threshold.
    """
    from models.db_models import AnalystFeedback

    status_map = {
        "authorized": "resolved",
        "benign_unusual": "resolved",
        "policy_violation": "reviewing",
        "compromised": "reviewing",
        "insufficient_evidence": "open",
    }
    case.status = status_map.get(verdict, case.status)

    actor = db.query(Entity).filter(Entity.id == case.actor_id).one()
    thr = (
        db.query(CohortThreshold)
        .filter(CohortThreshold.role == actor.role)
        .first()
    )
    if thr is None:
        thr = CohortThreshold(role=actor.role, threshold=40.0)
        db.add(thr)
        db.flush()

    old = thr.threshold
    # Authorized / benign → raise threshold slightly (fewer future alerts for cohort)
    # Compromised / policy → lower threshold (more sensitive)
    adjustment = 0.0
    if verdict in ("authorized", "benign_unusual"):
        adjustment = 2.0
    elif verdict in ("compromised", "policy_violation"):
        adjustment = -3.0
    elif verdict == "insufficient_evidence":
        adjustment = 0.5

    thr.threshold = max(10.0, min(90.0, thr.threshold + adjustment))
    thr.updated_at = datetime.now(timezone.utc)

    fb = AnalystFeedback(
        case_id=case.id,
        verdict=verdict,
        notes=notes,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(fb)
    db.commit()
    db.refresh(fb)
    db.refresh(case)

    return {
        "feedback": fb,
        "case_status": case.status,
        "cohort_threshold_adjustment": {
            "role": actor.role,
            "previous_threshold": old,
            "new_threshold": thr.threshold,
            "delta": thr.threshold - old,
            "note": (
                "Per-role-cohort ranking threshold adjusted. "
                "This is NOT a model retrain — only a stored numeric threshold "
                "used when ranking/filtering future cases for this role cohort."
            ),
        },
    }


def build_shift_map(db: Session, case: Case) -> dict[str, Any]:
    events = [link.event for link in case.event_links]
    if not events and case.event_ids:
        events = db.query(Event).filter(Event.id.in_(case.event_ids)).all()
    actor = db.query(Entity).filter(Entity.id == case.actor_id).one()
    breakdown = {b["event_id"]: b for b in (case.explanation_breakdown or [])}

    nodes: dict[str, dict] = {}
    edges = []
    domains = set()

    entity_node = f"entity:{actor.id}"
    nodes[entity_node] = {
        "id": entity_node,
        "type": "entity",
        "label": actor.pseudonymous_id,
        "meta": {"role": actor.role, "department": actor.department},
    }
    domains.add(actor.department)

    for e in events:
        status = breakdown.get(e.id, {}).get("status", "unexplained")
        if e.device_id:
            did = f"device:{e.device_id}"
            nodes[did] = {
                "id": did,
                "type": "device",
                "label": e.device_id,
                "meta": {},
            }
            edges.append(
                {
                    "id": f"e{e.id}-device",
                    "source": entity_node,
                    "target": did,
                    "timestamp": _ensure_aware(e.timestamp),
                    "action": e.action,
                    "explanation_status": status,
                    "event_id": e.id,
                }
            )
        if e.resource_id:
            rid = f"resource:{e.resource_id}"
            nodes[rid] = {
                "id": rid,
                "type": "resource",
                "label": e.resource_id,
                "meta": {"classification": e.resource_classification},
            }
            domains.add(e.resource_classification or "unknown")
            edges.append(
                {
                    "id": f"e{e.id}-resource",
                    "source": entity_node,
                    "target": rid,
                    "timestamp": _ensure_aware(e.timestamp),
                    "action": e.action,
                    "explanation_status": status,
                    "event_id": e.id,
                }
            )
        if e.destination:
            dest = f"destination:{e.destination}"
            nodes[dest] = {
                "id": dest,
                "type": "destination",
                "label": e.destination,
                "meta": {},
            }
            edges.append(
                {
                    "id": f"e{e.id}-dest",
                    "source": entity_node,
                    "target": dest,
                    "timestamp": _ensure_aware(e.timestamp),
                    "action": e.action,
                    "explanation_status": status,
                    "event_id": e.id,
                }
            )

    return {
        "case_id": case.id,
        "actor_ref": actor.pseudonymous_id,
        "change_point_timestamps": case.change_point_timestamps or [],
        "nodes": list(nodes.values()),
        "edges": edges,
        "domains": sorted(domains),
    }
