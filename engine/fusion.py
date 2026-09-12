"""Module 6 — Evidence fusion.

R_t = σ(w_s·S_t + w_p·P_t + w_q·Q_t + w_a·A_t + w_i·I_t − w_c·C_t)

All inputs are live outputs of modules 2–5. Weights are named constants in config.py.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from config import W_A, W_C, W_I, W_P, W_Q, W_S
from engine.baseline import compute_baseline_deviation
from engine.context import evaluate_context_compatibility
from engine.narrative import assert_no_verdict_language, sanitize_narrative_list
from models.db_models import ContextLedgerEntry, Event, Entity


# Role sensitivity multipliers (identity risk)
ROLE_SENSITIVITY = {
    "security": 1.2,
    "admin": 1.3,
    "finance": 1.15,
    "engineering": 1.0,
    "hr": 1.05,
    "contractor": 1.1,
}

CLASSIFICATION_SCORE = {
    "public": 0.1,
    "internal": 0.35,
    "restricted": 0.7,
    "critical": 1.0,
}


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


def _norm01(x: float, scale: float = 2.0) -> float:
    """Squash non-negative signals into ~[0, 1] so fusion doesn't saturate."""
    x = max(0.0, float(x))
    return 1.0 - math.exp(-x / max(scale, 1e-6))


def sigmoid_bound(x: float, midpoint: float = 0.35, steepness: float = 6.0) -> float:
    """Map a ~[0,1]-ish linear combo to 0–100 via logistic."""
    s = 1.0 / (1.0 + math.exp(-steepness * (x - midpoint)))
    return max(0.0, min(100.0, s * 100.0))


def compute_asset_sensitivity(events: list[Event]) -> float:
    """Prefer max sensitivity (worst asset touched) with a mild average blend."""
    if not events:
        return 0.0
    scores = [
        CLASSIFICATION_SCORE.get(e.resource_classification or "internal", 0.35)
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
    role_mult = ROLE_SENSITIVITY.get(role.lower(), 1.0)
    return min(priv_norm * role_mult, 1.5)


def compute_sequence_risk(features: dict[str, Any]) -> float:
    flag = float(features.get("suspicious_sequence_flag", 0.0))
    mag = float(features.get("suspicious_sequence_magnitude", 0.0))
    return flag * max(mag, 0.3) if flag else 0.0


def fuse(
    S_t: float,
    P_t: float,
    Q_t: float,
    A_t: float,
    I_t: float,
    C_t: float,
    force_C_zero: bool = False,
) -> dict[str, float]:
    """
    Real arithmetic on module outputs.
    Returns raw_deviation (C=0), residual_risk (with C), context_coverage.
    """
    # Normalize magnitude features; A/Q/C already roughly [0,1]
    s = _norm01(S_t, scale=1.5)
    p = _norm01(P_t, scale=1.5)
    q = max(0.0, min(1.0, Q_t))
    a = max(0.0, min(1.0, A_t))
    i = max(0.0, min(1.0, I_t))
    c = 0.0 if force_C_zero else max(0.0, min(1.0, C_t))

    linear_raw = W_S * s + W_P * p + W_Q * q + W_A * a + W_I * i
    linear = linear_raw - W_C * c

    raw = sigmoid_bound(linear_raw, midpoint=0.30, steepness=7.0)
    residual = sigmoid_bound(linear, midpoint=0.30, steepness=7.0)

    if raw <= 1e-9:
        coverage = 1.0 if c >= 0.99 else 0.0
    else:
        coverage = max(0.0, min(1.0, (raw - residual) / raw))

    return {
        "raw_deviation": round(raw, 4),
        "residual_risk": round(residual, 4),
        "context_coverage": round(coverage, 4),
        "linear_score": round(linear, 4),
        "linear_raw": round(linear_raw, 4),
        "C_t_used": c,
        "S_t_norm": round(s, 4),
        "P_t_norm": round(p, 4),
        "Q_t_norm": round(q, 4),
        "A_t_norm": round(a, 4),
        "I_t_norm": round(i, 4),
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
    indeterminate_ids = set(ctx["indeterminate_event_ids"])
    risk_events = [e for e in scoped_events if e.id not in indeterminate_ids]

    S_t = overrides.get("S_t", baseline["S_t"])
    P_t = overrides.get("P_t", baseline["P_t"])
    Q_t = overrides.get("Q_t", compute_sequence_risk(features))
    A_t = overrides.get("A_t", compute_asset_sensitivity(risk_events))
    I_t = overrides.get("I_t", compute_identity_risk(features, actor.role))

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

    fused = fuse(S_t, P_t, Q_t, A_t, I_t, C_t)

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
    if C_t > 0.0:
        evidence.append(
            f"Context explains {ctx['counts']['explained']}/{ctx['counts']['total']} "
            f"events (C_t={C_t:.2f})"
        )
    for ub in ctx["unmatched_behavior"][:5]:
        evidence.append(f"Unmatched: {ub}")

    contributors = {
        "self-baseline deviation": W_S * fused["S_t_norm"],
        "peer-cohort deviation": W_P * fused["P_t_norm"],
        "observed access sequence": W_Q * fused["Q_t_norm"],
        "asset sensitivity": W_A * fused["A_t_norm"],
        "identity/privilege risk": W_I * fused["I_t_norm"],
    }
    primary_cause = assert_no_verdict_language(max(contributors, key=contributors.get))
    evidence = sanitize_narrative_list(evidence)
    unmatched_behavior = sanitize_narrative_list(ctx["unmatched_behavior"])
    confidence, data_quality = _assessment_metadata(
        db, actor_id, ctx, effective_as_of
    )

    return {
        "raw_deviation": fused["raw_deviation"],
        "context_coverage": fused["context_coverage"],
        "residual_risk": fused["residual_risk"],
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
            "C_t": round(C_t, 4),
            "W_S": W_S,
            "W_P": W_P,
            "W_Q": W_Q,
            "W_A": W_A,
            "W_I": W_I,
            "W_C": W_C,
            "linear_score": fused["linear_score"],
            "linear_raw": fused["linear_raw"],
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
