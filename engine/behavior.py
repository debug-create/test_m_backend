"""Module 2 — Behavior representation: real feature computation from Events."""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from config import (
    DOWNLOAD_ACTIONS,
    SENSITIVE_CLASSIFICATIONS,
    SUSPICIOUS_SEQUENCE_WINDOW_HOURS,
    WINDOW_15M,
    WINDOW_24H,
    WINDOW_7D,
    WINDOW_30D,
)
from models.db_models import Event


def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _entropy(values: list[int]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    ent = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def _stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(var)


def _haversine_km(a: Event, b: Event) -> float:
    if None in (a.latitude, a.longitude, b.latitude, b.longitude):
        return 0.0
    lat1, lon1, lat2, lon2 = map(
        math.radians, (a.latitude, a.longitude, b.latitude, b.longitude)
    )
    dlat, dlon = lat2 - lat1, lon2 - lon1
    value = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 6371.0 * 2 * math.asin(min(1.0, math.sqrt(value)))


def login_risk_features(window_events: list[Event], history: list[Event]) -> dict[str, float]:
    """Geo-velocity, device novelty, and failed-login burst constituents."""
    logins = sorted(
        [event for event in window_events if event.action == "login"],
        key=lambda event: _ensure_aware(event.timestamp),
    )
    max_velocity = 0.0
    located = [event for event in logins if event.latitude is not None and event.longitude is not None]
    for first, second in zip(located, located[1:]):
        hours = (_ensure_aware(second.timestamp) - _ensure_aware(first.timestamp)).total_seconds() / 3600
        if hours > 0:
            max_velocity = max(max_velocity, _haversine_km(first, second) / hours)
    geo_velocity_risk = max(0.0, min(1.0, max_velocity / 900.0))

    known_devices = {event.device_id for event in history if event.action == "login"}
    novel = sum(1 for event in logins if event.device_id not in known_devices)
    device_novelty = novel / len(logins) if logins else 0.0

    failed_times = [_ensure_aware(event.timestamp) for event in logins if event.result == "failure"]
    max_failed_burst = 0
    for start in failed_times:
        max_failed_burst = max(
            max_failed_burst,
            sum(1 for timestamp in failed_times if start <= timestamp <= start + timedelta(minutes=15)),
        )
    failed_burst = max(0.0, min(1.0, max_failed_burst / 5.0))
    return {
        "geo_velocity_risk": round(geo_velocity_risk, 4),
        "login_device_novelty": round(device_novelty, 4),
        "failed_login_burst": round(failed_burst, 4),
    }


def compute_login_risk(features: dict[str, Any]) -> float:
    """Symmetric noisy-OR over the three observable login-risk factors."""
    values = [
        max(0.0, min(1.0, float(features.get(name, 0.0))))
        for name in ("geo_velocity_risk", "login_device_novelty", "failed_login_burst")
    ]
    complement = 1.0
    for value in values:
        complement *= 1.0 - value
    return round(1.0 - complement, 4)


def _events_in_window(
    events: list[Event], end: datetime, window_seconds: int
) -> list[Event]:
    start = end - timedelta(seconds=window_seconds)
    return [e for e in events if start <= _ensure_aware(e.timestamp) <= end]


def _historical_before(events: list[Event], before: datetime) -> list[Event]:
    return [e for e in events if _ensure_aware(e.timestamp) < before]


def login_hour_irregularity(window_events: list[Event], history: list[Event]) -> float:
    """Higher = more irregular vs actor history (combined stddev + entropy signal)."""
    login_hours = [
        _ensure_aware(e.timestamp).hour
        for e in window_events
        if e.action == "login"
    ]
    if not login_hours:
        return 0.0

    hist_hours = [
        _ensure_aware(e.timestamp).hour for e in history if e.action == "login"
    ]
    window_ent = _entropy(login_hours)
    hist_ent = _entropy(hist_hours) if hist_hours else 0.0
    window_std = _stddev([float(h) for h in login_hours])
    hist_std = _stddev([float(h) for h in hist_hours]) if len(hist_hours) > 1 else 1.0

    # Ratio of window irregularity to historical irregularity (floor to avoid /0)
    denom = max(hist_ent + hist_std, 0.5)
    return (window_ent + window_std) / denom


def new_device_count(window_events: list[Event], history: list[Event]) -> int:
    known = {e.device_id for e in history}
    return len({e.device_id for e in window_events if e.device_id not in known})


def new_resource_count(window_events: list[Event], history: list[Event]) -> int:
    known = {e.resource_id for e in history if e.resource_id}
    return len(
        {
            e.resource_id
            for e in window_events
            if e.resource_id and e.resource_id not in known
        }
    )


def sensitive_access_ratio(window_events: list[Event]) -> float:
    if not window_events:
        return 0.0
    sensitive = sum(
        1
        for e in window_events
        if (e.resource_classification or "") in SENSITIVE_CLASSIFICATIONS
    )
    return sensitive / len(window_events)


def download_volume_vs_baseline(
    window_events: list[Event], history: list[Event], window_seconds: int
) -> float:
    window_vol = sum(
        (e.volume or 0)
        for e in window_events
        if e.action in DOWNLOAD_ACTIONS or e.action == "file_download"
    )
    if not history:
        return float(window_vol) if window_vol else 0.0

    # Rolling average volume per equivalent window length over history
    if not history:
        return float(window_vol)

    hist_start = min(_ensure_aware(e.timestamp) for e in history)
    hist_end = max(_ensure_aware(e.timestamp) for e in history)
    span_seconds = max((hist_end - hist_start).total_seconds(), 1.0)
    n_windows = max(span_seconds / max(window_seconds, 1), 1.0)
    hist_vol = sum(
        (e.volume or 0)
        for e in history
        if e.action in DOWNLOAD_ACTIONS or e.action == "file_download"
    )
    baseline = hist_vol / n_windows
    if baseline <= 0:
        return float(window_vol) if window_vol else 0.0
    return window_vol / baseline


def privilege_change_count(window_events: list[Event]) -> int:
    return sum(1 for e in window_events if e.action == "privilege_change")


def external_destination_novelty(
    window_events: list[Event],
    actor_history: list[Event],
    peer_events: list[Event],
) -> float:
    """1.0 if destination never seen by actor or peers; 0.0 if familiar."""
    destinations = {
        e.destination
        for e in window_events
        if e.destination and e.action in ("external_upload", "file_download")
    }
    if not destinations:
        return 0.0

    known = {e.destination for e in actor_history if e.destination}
    known |= {e.destination for e in peer_events if e.destination}
    novel = [d for d in destinations if d not in known]
    return len(novel) / len(destinations)


def suspicious_sequence_flag(
    events: list[Event],
    end: datetime,
    window_hours: int = SUSPICIOUS_SEQUENCE_WINDOW_HOURS,
) -> tuple[bool, float]:
    """
    True if privilege_change → sensitive resource access → download/upload
    occurs within the configurable window. Magnitude reflects how tightly
    clustered and how sensitive the resources are.
    """
    start = end - timedelta(hours=window_hours)
    scoped = sorted(
        [e for e in events if start <= _ensure_aware(e.timestamp) <= end],
        key=lambda e: _ensure_aware(e.timestamp),
    )
    if not scoped:
        return False, 0.0

    priv_times = [
        _ensure_aware(e.timestamp)
        for e in scoped
        if e.action == "privilege_change"
    ]
    sens = [
        e
        for e in scoped
        if e.action in ("file_access", "repo_access", "file_download")
        and (e.resource_classification or "") in SENSITIVE_CLASSIFICATIONS
    ]
    transfers = [
        e
        for e in scoped
        if e.action in ("file_download", "external_upload")
    ]

    best_mag = 0.0
    found = False
    for pt in priv_times:
        later_sens = [e for e in sens if _ensure_aware(e.timestamp) >= pt]
        for s in later_sens:
            st = _ensure_aware(s.timestamp)
            later_xfer = [e for e in transfers if _ensure_aware(e.timestamp) >= st]
            for x in later_xfer:
                xt = _ensure_aware(x.timestamp)
                span_h = (xt - pt).total_seconds() / 3600.0
                if span_h <= window_hours:
                    found = True
                    # Tighter cluster + critical assets → higher magnitude
                    tightness = 1.0 - (span_h / window_hours)
                    crit_boost = (
                        1.0
                        if (s.resource_classification == "critical"
                            or x.resource_classification == "critical")
                        else 0.6
                    )
                    mag = tightness * crit_boost
                    best_mag = max(best_mag, mag)
    return found, best_mag


WINDOWS = {
    "15m": WINDOW_15M,
    "24h": WINDOW_24H,
    "7d": WINDOW_7D,
    "30d": WINDOW_30D,
}


def compute_feature_vector(
    db: Session,
    actor_id: int,
    as_of: Optional[datetime] = None,
    peer_actor_ids: Optional[list[int]] = None,
) -> dict[str, Any]:
    """Compute structured features across four time windows from stored Events."""
    as_of = _ensure_aware(as_of or datetime.now(timezone.utc))

    all_events = (
        db.query(Event)
        .filter(Event.actor_id == actor_id, Event.timestamp <= as_of)
        .order_by(Event.timestamp.asc())
        .all()
    )

    peer_events: list[Event] = []
    if peer_actor_ids:
        peer_events = (
            db.query(Event)
            .filter(Event.actor_id.in_(peer_actor_ids), Event.timestamp <= as_of)
            .all()
        )

    result: dict[str, Any] = {"as_of": as_of.isoformat(), "windows": {}}

    for name, seconds in WINDOWS.items():
        window_events = _events_in_window(all_events, as_of, seconds)
        # History = everything before the window starts
        window_start = as_of - timedelta(seconds=seconds)
        history = _historical_before(all_events, window_start)

        seq_flag, seq_mag = suspicious_sequence_flag(all_events, as_of)

        features = {
            "login_hour_irregularity": login_hour_irregularity(window_events, history),
            "new_device_count": float(new_device_count(window_events, history)),
            "new_resource_count": float(new_resource_count(window_events, history)),
            "sensitive_access_ratio": sensitive_access_ratio(window_events),
            "download_volume_vs_baseline": download_volume_vs_baseline(
                window_events, history, seconds
            ),
            "privilege_change_count": float(privilege_change_count(window_events)),
            "external_destination_novelty": external_destination_novelty(
                window_events, history, peer_events
            ),
            "suspicious_sequence_flag": 1.0 if seq_flag else 0.0,
            "suspicious_sequence_magnitude": seq_mag,
            "event_count": float(len(window_events)),
        }
        features.update(login_risk_features(window_events, history))
        result["windows"][name] = features

    # Primary vector used by baseline/fusion: 24h window (most operationally relevant)
    result["primary"] = result["windows"]["24h"]
    return result


FEATURE_KEYS = [
    "login_hour_irregularity",
    "new_device_count",
    "new_resource_count",
    "sensitive_access_ratio",
    "download_volume_vs_baseline",
    "privilege_change_count",
    "external_destination_novelty",
    "suspicious_sequence_flag",
    "suspicious_sequence_magnitude",
]
