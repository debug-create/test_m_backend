"""Module 3 — Hierarchical baseline B(u,t) = α·B_personal + β·B_role_cohort + γ·B_resource."""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sqlalchemy.orm import Session

from config import (
    ALPHA_ESTABLISHED,
    ALPHA_NEW,
    BETA_ESTABLISHED,
    BETA_NEW,
    GAMMA_ESTABLISHED,
    GAMMA_NEW,
    MIN_COHORT_SIZE,
    MIN_PERSONAL_HISTORY_DAYS,
    ROLE_CHANGE_BLEND_DAYS,
    WINDOW_24H,
    CLUSTER_EXCLUSION_DAYS,
)
from engine.behavior import FEATURE_KEYS, compute_feature_vector
from models.db_models import ContextLedgerEntry, Entity, Event


def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _zscore(value: float, mean: float, std: float) -> float:
    if std < 1e-9:
        # No variance — any non-zero deviation is notable
        return 0.0 if abs(value - mean) < 1e-9 else (2.0 if value > mean else -2.0)
    return (value - mean) / std


def _mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 1.0
    mean = sum(values) / len(values)
    if len(values) < 2:
        return mean, 1.0
    var = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return mean, math.sqrt(var) if var > 0 else 1.0


def actor_history_days(db: Session, actor_id: int, as_of: datetime) -> float:
    first = (
        db.query(Event)
        .filter(Event.actor_id == actor_id, Event.timestamp <= as_of)
        .order_by(Event.timestamp.asc())
        .first()
    )
    if not first:
        return 0.0
    return (_ensure_aware(as_of) - _ensure_aware(first.timestamp)).total_seconds() / 86400.0


def recent_role_change(
    db: Session, actor_id: int, as_of: datetime
) -> Optional[ContextLedgerEntry]:
    cutoff = as_of - timedelta(days=ROLE_CHANGE_BLEND_DAYS)
    return (
        db.query(ContextLedgerEntry)
        .filter(
            ContextLedgerEntry.actor_id == actor_id,
            ContextLedgerEntry.reason == "role_change",
            ContextLedgerEntry.approval_state == "approved",
            ContextLedgerEntry.effective_from >= cutoff,
            ContextLedgerEntry.effective_from <= as_of,
        )
        .order_by(ContextLedgerEntry.effective_from.desc())
        .first()
    )


def compute_weights(
    db: Session, actor: Entity, as_of: datetime, *, cohort_size: Optional[int] = None,
    cohort_metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Inspectable weight logic for α, β, γ."""
    hist_days = actor_history_days(db, actor.id, as_of)
    role_change = recent_role_change(db, actor.id, as_of)

    cohort_size = cohort_size if cohort_size is not None else 1
    cohort_confidence = "high" if cohort_size >= MIN_COHORT_SIZE else "low"

    if hist_days < MIN_PERSONAL_HISTORY_DAYS:
        alpha, beta, gamma = ALPHA_NEW, BETA_NEW, GAMMA_NEW
        rationale = (
            f"New entity ({hist_days:.1f}d < {MIN_PERSONAL_HISTORY_DAYS}d history): "
            "α low, behavioral-cohort β high"
        )
    elif role_change is not None:
        # Linearly blend personal weight down and cohort weight up during transition
        days_since = (
            _ensure_aware(as_of) - _ensure_aware(role_change.effective_from or role_change.valid_from)
        ).total_seconds() / 86400.0
        t = min(max(days_since / ROLE_CHANGE_BLEND_DAYS, 0.0), 1.0)
        # At t=0 (just changed): more cohort; at t=1: back toward established personal
        alpha = ALPHA_NEW + t * (ALPHA_ESTABLISHED - ALPHA_NEW)
        beta = BETA_NEW + t * (BETA_ESTABLISHED - BETA_NEW)
        gamma = GAMMA_NEW + t * (GAMMA_ESTABLISHED - GAMMA_NEW)
        rationale = (
            f"Role change within {ROLE_CHANGE_BLEND_DAYS}d "
            f"(t={t:.2f} through transition window): blending personal/behavioral-cohort weights"
        )
    else:
        alpha, beta, gamma = ALPHA_ESTABLISHED, BETA_ESTABLISHED, GAMMA_ESTABLISHED
        rationale = "Established entity, no recent role change: personal α high"

    # Widen uncertainty if small cohort
    uncertainty_band = 1.0 if cohort_size >= MIN_COHORT_SIZE else 1.75

    # Normalize to sum 1
    total = alpha + beta + gamma
    alpha, beta, gamma = alpha / total, beta / total, gamma / total

    result = {
        "alpha": round(alpha, 4),
        "beta": round(beta, 4),
        "gamma": round(gamma, 4),
        "history_days": round(hist_days, 2),
        "cohort_size": cohort_size,
        "cohort_confidence": cohort_confidence,
        "uncertainty_band": uncertainty_band,
        "role_change_active": role_change is not None,
        "role_change_entry_id": role_change.id if role_change else None,
        "rationale": rationale,
    }
    result["cohort_model"] = cohort_metadata or {
        "signal_source": "learned:kmeans_behavior_cluster",
        "cluster_id": None,
    }
    return result


def compute_behavioral_cluster(
    db: Session, actor_id: int, as_of: datetime
) -> dict[str, Any]:
    """Assign an entity to a deterministic k-means behavior cohort."""
    assignment_as_of = as_of - timedelta(days=CLUSTER_EXCLUSION_DAYS)
    target = db.query(Entity).filter(Entity.id == actor_id).one()
    actors = (
        db.query(Entity)
        .join(Event, Event.actor_id == Entity.id)
        .filter(Event.timestamp <= assignment_as_of)
        .distinct()
        .order_by(Entity.id)
        .all()
    )
    if not actors:
        role_ids = [row.id for row in db.query(Entity).filter(Entity.role == target.role).all()]
        return {"actor_ids": role_ids or [actor_id], "cluster_id": None, "cluster_count": 0,
                "fallback": "role_group_insufficient_history",
                "assignment_as_of": assignment_as_of.isoformat(),
                "exclusion_days": CLUSTER_EXCLUSION_DAYS,
                "signal_source": "learned:kmeans_behavior_cluster"}

    vectors = []
    ids = []
    for candidate in actors:
        primary = compute_feature_vector(db, candidate.id, as_of=assignment_as_of)["primary"]
        vectors.append([float(primary.get(key, 0.0)) for key in FEATURE_KEYS])
        ids.append(candidate.id)
    matrix = np.asarray(vectors, dtype=float)
    scaled = StandardScaler().fit_transform(matrix)
    unique_count = len(np.unique(scaled, axis=0))
    cluster_count = min(3, max(1, len(ids) // MIN_COHORT_SIZE), unique_count)
    if cluster_count == 1:
        labels = np.zeros(len(ids), dtype=int)
    else:
        labels = KMeans(
            n_clusters=cluster_count, random_state=20260915, n_init=10
        ).fit_predict(scaled)
    if actor_id not in ids:
        role_ids = [row.id for row in db.query(Entity).filter(Entity.role == target.role).all()]
        return {"actor_ids": role_ids or [actor_id], "cluster_id": None,
                "cluster_count": cluster_count, "fallback": "role_group_new_entity",
                "assignment_as_of": assignment_as_of.isoformat(),
                "exclusion_days": CLUSTER_EXCLUSION_DAYS,
                "signal_source": "learned:kmeans_behavior_cluster"}
    actor_index = ids.index(actor_id)
    cluster_id = int(labels[actor_index])
    members = [entity_id for entity_id, label in zip(ids, labels) if int(label) == cluster_id]

    fallback = None
    if len(members) < MIN_COHORT_SIZE:
        members = [row.id for row in db.query(Entity).filter(Entity.role == target.role).all()]
        fallback = "role_group_small_cluster"
    return {
        "actor_ids": members,
        "cluster_id": cluster_id,
        "cluster_count": cluster_count,
        "signal_source": "learned:kmeans_behavior_cluster",
        "feature_order": list(FEATURE_KEYS),
        "fallback": fallback,
        "assignment_as_of": assignment_as_of.isoformat(),
        "exclusion_days": CLUSTER_EXCLUSION_DAYS,
    }


def _feature_distribution_for_actors(
    db: Session,
    actor_ids: list[int],
    as_of: datetime,
    sample_offsets_hours: list[int] | None = None,
) -> dict[str, list[float]]:
    """Collect feature samples across actors at several historical offsets."""
    offsets = sample_offsets_hours or [0, 24, 48, 72, 168]
    dist: dict[str, list[float]] = {k: [] for k in FEATURE_KEYS}
    for aid in actor_ids:
        for oh in offsets:
            t = as_of - timedelta(hours=oh)
            # Skip if actor has no events yet at that time
            exists = (
                db.query(Event.id)
                .filter(Event.actor_id == aid, Event.timestamp <= t)
                .first()
            )
            if not exists:
                continue
            peers = [x for x in actor_ids if x != aid]
            fv = compute_feature_vector(db, aid, as_of=t, peer_actor_ids=peers)
            for k in FEATURE_KEYS:
                dist[k].append(float(fv["primary"].get(k, 0.0)))
    return dist


def _resource_access_rates(
    db: Session, as_of: datetime, lookback_days: int = 30
) -> dict[str, float]:
    """Org-wide: fraction of events touching each resource (rarity signal)."""
    start = as_of - timedelta(days=lookback_days)
    events = (
        db.query(Event)
        .filter(Event.timestamp >= start, Event.timestamp <= as_of)
        .all()
    )
    if not events:
        return {}
    from collections import Counter

    counts = Counter(e.resource_id for e in events if e.resource_id)
    total = sum(counts.values()) or 1
    return {rid: c / total for rid, c in counts.items()}


def compute_baseline_deviation(
    db: Session,
    actor_id: int,
    as_of: Optional[datetime] = None,
    features: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Return per-feature deviation scores (z-scores), combined weighted deviation,
    and the weights actually used.
    """
    as_of = _ensure_aware(as_of or datetime.now(timezone.utc))
    actor = db.query(Entity).filter(Entity.id == actor_id).one()
    cluster = compute_behavioral_cluster(db, actor_id, as_of)
    cohort_ids = cluster["actor_ids"]
    peer_ids = [i for i in cohort_ids if i != actor_id]
    weights = compute_weights(
        db, actor, as_of, cohort_size=len(cohort_ids), cohort_metadata=cluster
    )

    if features is None:
        features = compute_feature_vector(
            db, actor_id, as_of=as_of, peer_actor_ids=peer_ids
        )
    primary = features["primary"]

    # Personal baseline: samples from this actor's past (exclude current window)
    personal_dist = _feature_distribution_for_actors(
        db,
        [actor_id],
        as_of - timedelta(seconds=WINDOW_24H),
        sample_offsets_hours=[0, 24, 48, 72, 96, 120, 144, 168],
    )

    # Learned behavioral-cluster cohort baseline
    cohort_dist = _feature_distribution_for_actors(
        db,
        cohort_ids,
        as_of - timedelta(seconds=WINDOW_24H),
        sample_offsets_hours=[0, 48, 168],
    )

    resource_rates = _resource_access_rates(db, as_of)

    # Resource novelty for current window events
    window_start = as_of - timedelta(seconds=WINDOW_24H)
    recent_events = (
        db.query(Event)
        .filter(
            Event.actor_id == actor_id,
            Event.timestamp >= window_start,
            Event.timestamp <= as_of,
        )
        .all()
    )
    if recent_events and resource_rates:
        rarity_scores = [
            1.0 - resource_rates.get(e.resource_id, 0.0)
            for e in recent_events
            if e.resource_id
        ]
        b_resource_raw = sum(rarity_scores) / len(rarity_scores) if rarity_scores else 0.0
    else:
        b_resource_raw = 0.0

    per_feature: dict[str, Any] = {}
    personal_devs: list[float] = []
    cohort_devs: list[float] = []

    for key in FEATURE_KEYS:
        value = float(primary.get(key, 0.0))
        p_mean, p_std = _mean_std(personal_dist.get(key, []))
        c_mean, c_std = _mean_std(cohort_dist.get(key, []))

        # Widen cohort std when small cohort
        if weights["cohort_size"] < MIN_COHORT_SIZE:
            c_std *= weights["uncertainty_band"]

        z_personal = _zscore(value, p_mean, p_std)
        z_cohort = _zscore(value, c_mean, c_std)

        # Only positive (above-baseline) deviations contribute to risk
        d_personal = max(z_personal, 0.0)
        d_cohort = max(z_cohort, 0.0)

        combined = (
            weights["alpha"] * d_personal
            + weights["beta"] * d_cohort
            + weights["gamma"] * b_resource_raw
        )

        per_feature[key] = {
            "value": value,
            "z_personal": round(z_personal, 4),
            "z_cohort": round(z_cohort, 4),
            "deviation": round(combined, 4),
            "personal_mean": round(p_mean, 4),
            "personal_std": round(p_std, 4),
            "cohort_mean": round(c_mean, 4),
            "cohort_std": round(c_std, 4),
        }
        personal_devs.append(d_personal)
        cohort_devs.append(d_cohort)

    s_t = sum(personal_devs) / max(len(personal_devs), 1)
    p_t = sum(cohort_devs) / max(len(cohort_devs), 1)
    overall = (
        weights["alpha"] * s_t
        + weights["beta"] * p_t
        + weights["gamma"] * b_resource_raw
    )

    confidence = "high"
    if weights["cohort_confidence"] == "low" or weights["history_days"] < MIN_PERSONAL_HISTORY_DAYS:
        confidence = "low"
    elif weights["role_change_active"]:
        confidence = "moderate"

    return {
        "as_of": as_of.isoformat(),
        "weights": weights,
        "per_feature": per_feature,
        "S_t": round(s_t, 4),  # self-baseline deviation
        "P_t": round(p_t, 4),  # peer/cohort deviation
        "resource_component": round(b_resource_raw, 4),
        "overall_deviation": round(overall, 4),
        "confidence": confidence,
        "features": features,
    }
