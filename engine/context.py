"""Module 5 — Context compatibility (per-event explained / partial / unexplained / indeterminate).

Matching is generic: the same function resolves every event independently against
the actor's ContextLedgerEntry records. No named-scenario special cases.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from sqlalchemy.orm import Session

from config import MIN_PERSONAL_HISTORY_DAYS
from models.db_models import Case, ContextLedgerEntry, Event
from models.enums import ExplanationStatus


def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _time_match(event: Event, entry: ContextLedgerEntry) -> bool:
    ts = _ensure_aware(event.timestamp)
    return _ensure_aware(entry.valid_from) <= ts <= _ensure_aware(entry.valid_until)


def _resource_match(event: Event, entry: ContextLedgerEntry) -> Optional[bool]:
    """None = N/A (event has no resource); True/False = match result."""
    if not event.resource_id:
        return None
    allowed = entry.allowed_resources or []
    if not allowed:
        return None  # entry does not constrain resources
    return event.resource_id in allowed


def _action_match(event: Event, entry: ContextLedgerEntry) -> Optional[bool]:
    allowed = entry.allowed_actions or []
    if not allowed:
        return None
    return event.action in allowed


def _destination_match(event: Event, entry: ContextLedgerEntry) -> Optional[bool]:
    if not event.destination:
        return None
    # Only apply destination constraint for actions that use destinations
    if event.action not in ("external_upload", "file_download"):
        return None
    approved = entry.approved_destinations
    if approved is None:
        return None  # no destination constraint on this entry
    if len(approved) == 0:
        return False  # explicitly empty list = nothing approved
    return event.destination in approved


def _indeterminate_result(
    event: Event, reason: str, match_details: Optional[dict] = None
) -> dict[str, Any]:
    details = {"reason": reason}
    if match_details:
        details.update(match_details)
    return {
        "event_id": event.id,
        "timestamp": _ensure_aware(event.timestamp).isoformat(),
        "action": event.action,
        "resource_id": event.resource_id,
        "destination": event.destination,
        "status": ExplanationStatus.indeterminate.value,
        "matched_context_ids": [],
        "match_details": details,
        "best_score": 0.0,
    }


def match_event_against_entry(
    event: Event, entry: ContextLedgerEntry
) -> dict[str, Any]:
    """
    Score one event against one ledger entry. Pure function.

    Hard constraints: when an entry lists allowed_resources / allowed_actions,
    a miss on those is a hard failure for that entry (unexplained via this entry).
    Destination misses after resource+action succeed → partially_explained.
    """
    time_ok = _time_match(event, entry)
    res = _resource_match(event, entry)
    act = _action_match(event, entry)
    dest = _destination_match(event, entry)

    applicable = []
    matched = []
    for name, val in [
        ("time", time_ok),
        ("resource", res),
        ("action", act),
        ("destination", dest),
    ]:
        if name == "time":
            applicable.append(name)
            if val:
                matched.append(name)
        elif val is not None:
            applicable.append(name)
            if val:
                matched.append(name)

    # Time is mandatory — without a time match, entry is irrelevant
    if not time_ok:
        status = ExplanationStatus.unexplained
        score = 0.0
    else:
        # Hard fails: explicit resource/action allow-lists that reject this event
        hard_fail = (res is False) or (act is False)
        if hard_fail:
            status = ExplanationStatus.unexplained
            score = 0.0
        elif dest is False and (res is True or res is None) and (act is True or act is None):
            # Core identity of the access is allowed, but destination is not
            status = ExplanationStatus.partially_explained
            score = 0.5
        else:
            constraints = [c for c in applicable if c != "time"]
            if not constraints:
                status = ExplanationStatus.explained
                score = 1.0
            else:
                hits = sum(1 for c in constraints if c in matched)
                ratio = hits / len(constraints)
                if ratio >= 1.0:
                    status = ExplanationStatus.explained
                    score = 1.0
                elif ratio > 0.0:
                    status = ExplanationStatus.partially_explained
                    score = ratio
                else:
                    status = ExplanationStatus.unexplained
                    score = 0.0

    return {
        "entry_id": entry.id,
        "time_match": time_ok,
        "resource_match": res,
        "action_match": act,
        "destination_match": dest,
        "applicable": applicable,
        "matched": matched,
        "status": status.value,
        "score": score,
    }


def classify_event(
    event: Event,
    entries: Sequence[ContextLedgerEntry],
    *,
    history_days: float = 30.0,
) -> dict[str, Any]:
    """
    Classify a single event against all context entries.
    Takes the best-matching entry; status is explained / partially_explained /
    unexplained / indeterminate for THAT event alone.
    """
    # Missing required matching field → indeterminate (not guilt, not coverage)
    if event.resource_id and not event.resource_classification:
        return _indeterminate_result(
            event,
            "missing_resource_classification",
            {"resource_id": event.resource_id},
        )

    # Sort entries canonically for stable iteration
    sorted_entries = sorted(
        entries,
        key=lambda e: (_ensure_aware(e.valid_from), e.id or 0),
    )

    applicable = [e for e in sorted_entries if _time_match(event, e)]

    # Short history + no applicable context → indeterminate
    if history_days < MIN_PERSONAL_HISTORY_DAYS and not applicable:
        return _indeterminate_result(
            event,
            "insufficient_history_no_applicable_context",
            {
                "history_days": round(history_days, 2),
                "min_required_days": MIN_PERSONAL_HISTORY_DAYS,
            },
        )

    if not sorted_entries:
        return {
            "event_id": event.id,
            "timestamp": _ensure_aware(event.timestamp).isoformat(),
            "action": event.action,
            "resource_id": event.resource_id,
            "destination": event.destination,
            "status": ExplanationStatus.unexplained.value,
            "matched_context_ids": [],
            "match_details": {"reason": "no_context_entries"},
            "best_score": 0.0,
        }

    evaluations = [match_event_against_entry(event, e) for e in sorted_entries]
    # Prefer highest score; ties broken by explained > partial > unexplained
    rank = {
        "explained": 3,
        "partially_explained": 2,
        "unexplained": 1,
        "indeterminate": 0,
    }
    best = max(
        evaluations,
        key=lambda ev: (ev["score"], rank.get(ev["status"], 0), -ev["entry_id"]),
    )

    matched_ids = sorted(
        ev["entry_id"]
        for ev in evaluations
        if ev["status"] in ("explained", "partially_explained")
    )

    return {
        "event_id": event.id,
        "timestamp": _ensure_aware(event.timestamp).isoformat(),
        "action": event.action,
        "resource_id": event.resource_id,
        "destination": event.destination,
        "status": best["status"],
        "matched_context_ids": matched_ids,
        "match_details": best,
        "best_score": best["score"],
    }


CLASSIFICATION_WEIGHT = {
    "public": 0.2,
    "internal": 0.4,
    "restricted": 0.75,
    "critical": 1.0,
}


def _actor_history_days_at(
    db: Session, actor_id: int, as_of: datetime
) -> float:
    first = (
        db.query(Event)
        .filter(Event.actor_id == actor_id, Event.timestamp <= as_of)
        .order_by(Event.timestamp.asc(), Event.id.asc())
        .first()
    )
    if not first:
        return 0.0
    return (_ensure_aware(as_of) - _ensure_aware(first.timestamp)).total_seconds() / 86400.0


def evaluate_context_compatibility(
    db: Session,
    actor_id: int,
    events: list[Event],
    as_of: Optional[datetime] = None,
) -> dict[str, Any]:
    """
    Per-event breakdown for a set of unusual / case events.
    Returns buckets + aggregate coverage metrics.

    Temporal guard: only events with timestamp <= as_of are considered.
    C_t is severity-weighted over explained/partial/unexplained only —
    indeterminate events sit outside both risk and coverage.
    """
    as_of_aware = _ensure_aware(as_of) if as_of is not None else None

    # Do not mutate caller list — filter into a new ordered sequence
    scoped = [
        e
        for e in events
        if as_of_aware is None or _ensure_aware(e.timestamp) <= as_of_aware
    ]
    scoped = sorted(scoped, key=lambda e: (_ensure_aware(e.timestamp), e.id or 0))

    eval_as_of = as_of_aware or (
        max((_ensure_aware(e.timestamp) for e in scoped), default=datetime.now(timezone.utc))
    )

    entries = (
        db.query(ContextLedgerEntry)
        .filter(
            ContextLedgerEntry.actor_id == actor_id,
            ContextLedgerEntry.valid_from <= eval_as_of,
        )
        .order_by(ContextLedgerEntry.valid_from.asc(), ContextLedgerEntry.id.asc())
        .all()
    )

    history_days = _actor_history_days_at(db, actor_id, eval_as_of)
    breakdown = [
        classify_event(e, entries, history_days=history_days) for e in scoped
    ]
    event_by_id = {e.id: e for e in scoped}

    explained = [b for b in breakdown if b["status"] == "explained"]
    partial = [b for b in breakdown if b["status"] == "partially_explained"]
    unexplained = [b for b in breakdown if b["status"] == "unexplained"]
    indeterminate = [b for b in breakdown if b["status"] == "indeterminate"]

    # Severity-weighted C_t — indeterminate excluded from numerator and denominator
    score_map = {
        "explained": 1.0,
        "partially_explained": 0.5,
        "unexplained": 0.0,
    }
    weighted_sum = 0.0
    weight_total = 0.0
    for b in breakdown:
        if b["status"] == "indeterminate":
            continue
        ev = event_by_id.get(b["event_id"])
        w = CLASSIFICATION_WEIGHT.get(
            (ev.resource_classification if ev else None) or "internal", 0.4
        )
        if ev and ev.action == "external_upload":
            w = max(w, 0.9)
        weighted_sum += score_map.get(b["status"], 0.0) * w
        weight_total += w
    c_t = weighted_sum / weight_total if weight_total > 0 else 0.0

    matched_context_ids = sorted(
        {cid for b in breakdown for cid in b["matched_context_ids"]}
    )

    unmatched_behavior = [
        f"{b['action']} on {b['resource_id'] or b['destination'] or 'unknown'} "
        f"at {b['timestamp']}"
        for b in unexplained
    ]

    return {
        "breakdown": breakdown,
        "explained_event_ids": [b["event_id"] for b in explained],
        "partial_event_ids": [b["event_id"] for b in partial],
        "unexplained_event_ids": [b["event_id"] for b in unexplained],
        "indeterminate_event_ids": [b["event_id"] for b in indeterminate],
        "C_t": round(c_t, 4),
        "matched_context_ids": matched_context_ids,
        "unmatched_behavior": unmatched_behavior,
        "residual_unresolved_count": len(indeterminate),
        "counts": {
            "explained": len(explained),
            "partially_explained": len(partial),
            "unexplained": len(unexplained),
            "indeterminate": len(indeterminate),
            "total": len(breakdown),
        },
        "as_of": eval_as_of.isoformat(),
        "history_days": round(history_days, 2),
    }


def check_auto_reopen(db: Session, actor_id: int, new_events: list[Event]) -> list[Case]:
    """
    If a case was resolved because context explained it, and NEW events fall
    outside the same context entry's allowed resources/actions/destinations,
    set status back to reopened.
    """
    resolved_cases = (
        db.query(Case)
        .filter(Case.actor_id == actor_id, Case.status == "resolved")
        .order_by(Case.id.asc())
        .all()
    )
    if not resolved_cases or not new_events:
        return []

    entries = (
        db.query(ContextLedgerEntry)
        .filter(ContextLedgerEntry.actor_id == actor_id)
        .order_by(ContextLedgerEntry.valid_from.asc(), ContextLedgerEntry.id.asc())
        .all()
    )
    reopened: list[Case] = []
    ordered_new = sorted(
        new_events, key=lambda e: (_ensure_aware(e.timestamp), e.id or 0)
    )
    for case in resolved_cases:
        prior_ids = set(case.matched_context_ids or [])
        relevant = [e for e in entries if e.id in prior_ids] or list(entries)
        # History days for classification — use latest new event time
        as_of = max(_ensure_aware(e.timestamp) for e in ordered_new)
        history_days = _actor_history_days_at(db, actor_id, as_of)
        outside = False
        for ev in ordered_new:
            classification = classify_event(ev, relevant, history_days=history_days)
            if classification["status"] == "unexplained":
                outside = True
                break
        if outside:
            case.status = "reopened"
            reopened.append(case)

    if reopened:
        db.commit()
    return reopened
