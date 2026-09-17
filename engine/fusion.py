"""Module 6 — evidence-preserving constituent fusion.

Raw deviation is an equal-treatment noisy-OR over constituent change-point
signals. Context is measured evidence coverage, never a subtractive score.
Residual risk is exactly ``raw_deviation * (1 - context_coverage)``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from engine.baseline import compute_baseline_deviation
from engine.behavior import compute_login_risk
from engine.context import evaluate_context_compatibility
from engine.ml_signals import behavior_model_metadata, isolation_forest_signal
from engine.narrative import assert_no_verdict_language, sanitize_narrative_list
from models.db_models import ContextLedgerEntry, Event, Entity


CLASSIFICATION_SCORE = {
    "public": 0.25,
    "internal": 0.5,
    "restricted": 0.75,
    "critical": 1.0,
}

CRITICAL_EVENT_FLOOR = 0.25
BULK_DOWNLOAD_THRESHOLD = 1000


def _ensure_aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _assessment_metadata(
    db: Session, actor_id: int, context: dict[str, Any], as_of: datetime
) -> tuple[str, str]:
    """Compute assessment confidence and structural data quality independently."""
    counts = context["counts"]
    usable = counts["total"] - counts["indeterminate"]
    if usable <= 0:
        confidence = "low"
    elif counts["indeterminate"] > 0:
        confidence = "moderate"
    else:
        confidence = "high"

    event_count = (
        db.query(Event.id)
        .filter(Event.actor_id == actor_id, Event.timestamp <= as_of)
        .count()
    )
    context_count = (
        db.query(ContextLedgerEntry.id)
        .filter(
            ContextLedgerEntry.actor_id == actor_id,
            ContextLedgerEntry.valid_from <= as_of,
            ContextLedgerEntry.approval_state == "approved",
        )
        .count()
    )
    history_days = float(context.get("history_days", 0.0))
    if event_count == 0 and context_count == 0:
        data_quality = "insufficient"
    elif history_days < 14.0:
        data_quality = "sparse"
    else:
        data_quality = "sufficient"
    return confidence, data_quality


def _norm01(x: float) -> float:
    """Map a non-negative magnitude monotonically without a tuned scale."""
    value = max(0.0, float(x))
    return value / (1.0 + value)


def compute_asset_sensitivity(events: list[Event]) -> float:
    """Prefer max sensitivity (worst asset touched) with a mild average blend."""
    if not events:
        return 0.0
    scores = [
        CLASSIFICATION_SCORE.get(e.resource_classification or "internal", 0.5)
        for e in events
    ]
    for e in events:
        if e.action == "external_upload":
            scores.append(1.0)
    avg = sum(scores) / len(scores)
    return 0.55 * max(scores) + 0.45 * avg


def compute_identity_risk(features: dict[str, Any], role: str) -> float:
    priv = float(features.get("privilege_change_count", 0.0))
    priv_norm = min(priv / 2.0, 1.0)
    # Job title is not a risk multiplier; identity risk reflects observed
    # privilege-change behavior only.
    return priv_norm


def compute_sequence_risk(features: dict[str, Any]) -> float:
    flag = float(features.get("suspicious_sequence_flag", 0.0))
    mag = float(features.get("suspicious_sequence_magnitude", 0.0))
    return flag * max(mag, 0.3) if flag else 0.0


def _noisy_or(values: list[float]) -> float:
    complement = 1.0
    for value in values:
        complement *= 1.0 - max(0.0, min(1.0, float(value)))
    return 1.0 - complement


def critical_event_reasons(event: Event) -> list[str]:
    reasons = []
    if event.action == "privilege_change":
        reasons.append("privilege_escalation")
    if event.action == "external_upload":
        reasons.append("external_upload")
        if event.destination and not event.destination.lower().startswith(
            ("s3://corp-", "https://corp.", "https://internal.")
        ):
            reasons.append("external_destination")
    if event.action == "file_download" and (event.volume or 0) >= BULK_DOWNLOAD_THRESHOLD:
        reasons.append("bulk_download")
    return reasons


def combine_signal_categories(categories: dict[str, dict[str, Any]]) -> float:
    """Use max within correlated categories and noisy-OR across categories."""
    category_values = []
    for category in categories.values():
        signals = category.get("signals", {})
        combined = max((float(value) for value in signals.values()), default=0.0)
        category["combined"] = round(max(0.0, min(1.0, combined)), 4)
        category_values.append(category["combined"])
    return round(_noisy_or(category_values), 4)


def event_category_risk(
    event: Event, features: dict[str, Any], *, S_t: float, P_t: float, Q_t: float,
    I_t: float, M_t: float, L_t: float,
) -> tuple[float, dict[str, Any]]:
    """Build auditable, decorrelated categories for one event."""
    is_resource = event.action in {"file_access", "repo_access", "file_download", "external_upload"}
    is_sequence = event.action in {"privilege_change", "file_access", "repo_access", "file_download", "external_upload"}
    resource_sensitivity = CLASSIFICATION_SCORE.get(
        event.resource_classification or "public", 0.25
    ) if is_resource else 0.0
    movement = 0.0
    if event.action == "external_upload":
        movement = 1.0
    elif event.action == "file_download":
        movement = min(max(float(event.volume or 0) / BULK_DOWNLOAD_THRESHOLD, 0.0), 1.0)

    categories = {
        "identity": {
            "signals": {
                "behavior_anomaly_model": M_t,
                "login_risk": L_t if event.action == "login" else 0.0,
            },
            "raw_fields": {
                "new_device_count": features.get("new_device_count", 0.0),
                "geo_velocity_risk": features.get("geo_velocity_risk", 0.0),
                "failed_login_burst": features.get("failed_login_burst", 0.0),
            },
            "signal_source": "mixed:offline_isolation_forest_and_login_rules",
        },
        "resource_access": {
            "signals": {
                "asset_sensitivity": resource_sensitivity,
                "personal_deviation": _norm01(S_t) if is_resource else 0.0,
                "cluster_deviation": _norm01(P_t) if is_resource else 0.0,
            },
            "raw_fields": {
                "action": event.action,
                "resource_classification": event.resource_classification,
                "new_resource_count": features.get("new_resource_count", 0.0),
            },
            "signal_source": "mixed:rules_and_kmeans_baseline",
        },
        "privilege": {
            "signals": {
                "observed_privilege_change": 1.0 if event.action == "privilege_change" else 0.0,
                "identity_privilege_signal": I_t if event.action == "privilege_change" else 0.0,
            },
            "raw_fields": {"privilege_change_count": features.get("privilege_change_count", 0.0)},
            "signal_source": "rule_based",
        },
        "data_movement": {
            "signals": {"event_movement": movement},
            "raw_fields": {
                "volume": event.volume,
                "external_destination_novelty": features.get("external_destination_novelty", 0.0),
            },
            "signal_source": "rule_based",
        },
        "temporal_sequence": {
            "signals": {"sequence_strength": Q_t if is_sequence else 0.0},
            "raw_fields": {
                "suspicious_sequence_flag": features.get("suspicious_sequence_flag", 0.0),
                "suspicious_sequence_magnitude": features.get("suspicious_sequence_magnitude", 0.0),
            },
            "signal_source": "rule_based",
        },
    }
    return combine_signal_categories(categories), categories


def fuse_event_residuals(
    event_inputs: list[dict[str, Any]], *, critical_floor: float = CRITICAL_EVENT_FLOOR
) -> dict[str, Any]:
    """Fuse event-level raw risk and context credit into case-level values."""
    rows = []
    raw_values = []
    residual_values = []
    weighted_credit = 0.0
    raw_total = 0.0
    for item in event_inputs:
        raw = max(0.0, min(1.0, float(item["raw_risk"])))
        credit = max(0.0, min(1.0, float(item["context_credit"])))
        before_floor = raw * (1.0 - credit)
        floor = critical_floor if item.get("critical_reasons") else 0.0
        residual = max(before_floor, floor)
        raw_values.append(raw)
        residual_values.append(residual)
        raw_total += raw
        weighted_credit += raw * credit
        rows.append({
            "event_id": int(item["event_id"]),
            "raw_risk": round(raw * 100.0, 4),
            "context_credit": round(credit, 4),
            "residual_before_floor": round(before_floor * 100.0, 4),
            "critical_floor": round(floor * 100.0, 4),
            "critical_reasons": list(item.get("critical_reasons") or []),
            "residual_contribution": round(residual * 100.0, 4),
            "categories": item.get("categories", {}),
        })
    raw_case = _noisy_or(raw_values)
    residual_case = _noisy_or(residual_values)
    coverage = weighted_credit / raw_total if raw_total > 0 else 0.0
    for index, row in enumerate(rows):
        without = _noisy_or(residual_values[:index] + residual_values[index + 1:])
        row["marginal_case_contribution"] = round((residual_case - without) * 100.0, 4)
    return {
        "raw_deviation": round(raw_case * 100.0, 4),
        "context_coverage": round(coverage, 4),
        "residual_risk": round(residual_case * 100.0, 4),
        "event_risk_breakdown": rows,
    }


def fuse(
    S_t: float,
    P_t: float,
    Q_t: float,
    A_t: float,
    I_t: float,
    C_t: float,
    force_C_zero: bool = False,
    M_t: float = 0.0,
    L_t: float = 0.0,
) -> dict[str, Any]:
    """
    Combine constituents symmetrically, then apply observed evidence coverage.

    No manually selected component weights or sigmoid are involved. A fully
    covered assessment has residual risk exactly zero while retaining raw risk.
    """
    # Normalize magnitude features; A/Q/C already roughly [0,1]
    s = _norm01(S_t)
    p = _norm01(P_t)
    q = max(0.0, min(1.0, Q_t))
    a = max(0.0, min(1.0, A_t))
    i = max(0.0, min(1.0, I_t))
    m = max(0.0, min(1.0, M_t))
    login = max(0.0, min(1.0, L_t))
    c = 0.0 if force_C_zero else max(0.0, min(1.0, C_t))

    constituents = (s, p, q, a, i, m, login)
    raw_probability = 1.0
    for signal in constituents:
        raw_probability *= 1.0 - signal
    raw = round(100.0 * (1.0 - raw_probability), 4)
    coverage = c
    residual = round(raw * (1.0 - coverage), 4)

    return {
        "raw_deviation": raw,
        "residual_risk": residual,
        "context_coverage": round(coverage, 4),
        "fusion_method": "unweighted_noisy_or_then_evidence_coverage",
        "C_t_used": c,
        "S_t_norm": round(s, 4),
        "P_t_norm": round(p, 4),
        "Q_t_norm": round(q, 4),
        "A_t_norm": round(a, 4),
        "I_t_norm": round(i, 4),
        "M_t_norm": round(m, 4),
        "L_t_norm": round(login, 4),
    }


def compute_risk_for_events(
    db: Session,
    actor_id: int,
    events: list[Event],
    as_of=None,
    overrides: Optional[dict[str, float]] = None,
) -> dict[str, Any]:
    """
    Full fusion pipeline for a set of events belonging to a transition/case.
    `overrides` lets counterfactual zero out named components.
    """
    overrides = dict(overrides or {})
    effective_as_of = _ensure_aware(
        as_of
        or max(
            (_ensure_aware(e.timestamp) for e in events),
            default=datetime.now(timezone.utc),
        )
    )
    scoped_events = sorted(
        [e for e in events if _ensure_aware(e.timestamp) <= effective_as_of],
        key=lambda e: (_ensure_aware(e.timestamp), e.id or 0),
    )
    actor = db.query(Entity).filter(Entity.id == actor_id).one()

    baseline = compute_baseline_deviation(db, actor_id, as_of=effective_as_of)
    features = baseline["features"]["primary"]

    ctx = evaluate_context_compatibility(
        db, actor_id, scoped_events, as_of=effective_as_of
    )
    # Unknown evidence is not silently removed. It can contribute to raw risk
    # and receives zero context credit until its data-quality issue is resolved.
    risk_events = scoped_events

    S_t = overrides.get("S_t", baseline["S_t"])
    P_t = overrides.get("P_t", baseline["P_t"])
    Q_t = overrides.get("Q_t", compute_sequence_risk(features))
    A_t = overrides.get("A_t", compute_asset_sensitivity(risk_events))
    I_t = overrides.get("I_t", compute_identity_risk(features, actor.role))
    M_t = overrides.get("M_t", isolation_forest_signal(features))
    L_t = overrides.get("L_t", compute_login_risk(features))

    C_t = overrides.get("C_t", ctx["C_t"])

    if overrides.get("privilege_escalation") == 0.0:
        I_t = 0.0
    if overrides.get("sensitive_access") == 0.0:
        A_t = 0.0
    if overrides.get("suspicious_sequence") == 0.0:
        Q_t = 0.0
    if overrides.get("self_deviation") == 0.0:
        S_t = 0.0
    if overrides.get("peer_deviation") == 0.0:
        P_t = 0.0
    if overrides.get("context") == 0.0:
        C_t = 0.0
    if overrides.get("behavior_anomaly_model") == 0.0:
        M_t = 0.0
    if overrides.get("login_risk") == 0.0:
        L_t = 0.0

    fused = fuse(S_t, P_t, Q_t, A_t, I_t, C_t, M_t=M_t, L_t=L_t)

    context_by_event = {row["event_id"]: row for row in ctx["breakdown"]}
    event_inputs = []
    for event in scoped_events:
        event_raw, categories = event_category_risk(
            event, features, S_t=S_t, P_t=P_t, Q_t=Q_t, I_t=I_t,
            M_t=M_t, L_t=L_t,
        )
        event_context = context_by_event.get(event.id, {})
        event_inputs.append({
            "event_id": event.id,
            "raw_risk": event_raw,
            "context_credit": float(event_context.get("best_score", 0.0)),
            "critical_reasons": critical_event_reasons(event),
            "categories": categories,
        })
    event_fused = fuse_event_residuals(event_inputs)

    evidence = []
    if S_t > 0.5:
        evidence.append(f"Self-baseline deviation elevated (S_t={S_t:.2f})")
    if P_t > 0.5:
        evidence.append(f"Peer/cohort deviation elevated (P_t={P_t:.2f})")
    if Q_t > 0.0:
        evidence.append(f"Observed privilege→access→transfer sequence (Q_t={Q_t:.2f})")
    if A_t > 0.5:
        evidence.append(f"High asset sensitivity in involved events (A_t={A_t:.2f})")
    if I_t > 0.3:
        evidence.append(f"Identity/privilege risk signal (I_t={I_t:.2f})")
    if M_t > 0.0:
        evidence.append(f"Offline anomaly-model constituent (M_t={M_t:.2f})")
    if L_t > 0.0:
        evidence.append(f"Login-risk constituent (L_t={L_t:.2f})")
    if C_t > 0.0:
        evidence.append(
            f"Context explains {ctx['counts']['explained']}/{ctx['counts']['total']} "
            f"events (risk-weighted coverage={event_fused['context_coverage']:.2f})"
        )
    for ub in ctx["unmatched_behavior"][:5]:
        evidence.append(f"Unmatched: {ub}")

    contributors = {
        "self-baseline deviation": fused["S_t_norm"],
        "peer-cohort deviation": fused["P_t_norm"],
        "observed access sequence": fused["Q_t_norm"],
        "asset sensitivity": fused["A_t_norm"],
        "identity/privilege risk": fused["I_t_norm"],
        "offline behavior anomaly": fused["M_t_norm"],
        "login risk": fused["L_t_norm"],
    }
    primary_cause = assert_no_verdict_language(max(contributors, key=contributors.get))
    evidence = sanitize_narrative_list(evidence)
    unmatched_behavior = sanitize_narrative_list(ctx["unmatched_behavior"])
    confidence, data_quality = _assessment_metadata(
        db, actor_id, ctx, effective_as_of
    )

    return {
        "raw_deviation": event_fused["raw_deviation"],
        "context_coverage": event_fused["context_coverage"],
        "residual_risk": event_fused["residual_risk"],
        "event_risk_breakdown": event_fused["event_risk_breakdown"],
        "confidence": confidence,
        "data_quality": data_quality,
        "residual_unresolved_count": ctx["residual_unresolved_count"],
        "primary_cause": primary_cause,
        "evidence": evidence,
        "matched_context_ids": ctx["matched_context_ids"],
        "unmatched_behavior": unmatched_behavior,
        "explanation_breakdown": ctx["breakdown"],
        "baseline_weights": risk_baseline_weights(baseline),
        "feature_snapshot": baseline["features"],
        "fusion_components": {
            "S_t": round(S_t, 4),
            "P_t": round(P_t, 4),
            "Q_t": round(Q_t, 4),
            "A_t": round(A_t, 4),
            "I_t": round(I_t, 4),
            "M_t": round(M_t, 4),
            "L_t": round(L_t, 4),
            "C_t": event_fused["context_coverage"],
            "coverage_method": "constituent_event_evidence_coverage",
            "fusion_method": fused["fusion_method"],
            "signal_sources": {
                "S_t": "rule_based:personal_baseline_deviation",
                "P_t": "learned:kmeans_cohort_deviation",
                "Q_t": "rule_based:sequence_detection",
                "A_t": "rule_based:asset_classification",
                "I_t": "rule_based:observed_privilege_change",
                "M_t": behavior_model_metadata()["signal_source"],
                "L_t": "rule_based:login_geo_device_failure",
                "C_t": "rule_based:approved_context_coverage",
            },
            "behavior_model": behavior_model_metadata(),
        },
        "baseline": baseline,
        "context": ctx,
    }


def risk_baseline_weights(baseline: dict) -> dict:
    weights = dict(baseline["weights"])
    if weights.get("rationale") is not None:
        weights["rationale"] = assert_no_verdict_language(weights["rationale"])
    return weights


def counterfactual_breakdown(
    db: Session, actor_id: int, events: list[Event], as_of=None
) -> dict[str, Any]:
    """Recompute residual_risk with each component zeroed one at a time."""
    base = compute_risk_for_events(db, actor_id, events, as_of=as_of)
    residual = base["residual_risk"]

    components = [
        ("privilege_escalation", "Identity/privilege risk (I_t) zeroed"),
        ("sensitive_access", "Asset sensitivity (A_t) zeroed"),
        ("suspicious_sequence", "Sequence risk (Q_t) zeroed"),
        ("self_deviation", "Self-baseline deviation (S_t) zeroed"),
        ("peer_deviation", "Peer/cohort deviation (P_t) zeroed"),
        ("context", "Context credit (C_t) zeroed — equivalent to raw path"),
        ("behavior_anomaly_model", "Offline Isolation Forest signal (M_t) zeroed"),
        ("login_risk", "Login-risk signal (L_t) zeroed"),
    ]

    results = []
    for key, desc in components:
        desc = assert_no_verdict_language(desc)
        alt = compute_risk_for_events(
            db, actor_id, events, as_of=as_of, overrides={key: 0.0}
        )
        results.append(
            {
                "component": key,
                "description": desc,
                "residual_risk_without": alt["residual_risk"],
                "delta": round(residual - alt["residual_risk"], 4),
            }
        )

    return {
        "case_residual_risk": residual,
        "components": results,
        "base_fusion": base["fusion_components"],
    }
