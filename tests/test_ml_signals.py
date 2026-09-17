"""Deterministic isolated checks for learned and login-risk constituents."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from engine.baseline import compute_behavioral_cluster
from engine.behavior import compute_login_risk, login_risk_features
from engine.fusion import combine_signal_categories, fuse
from engine.ml_signals import behavior_model_metadata, isolation_forest_signal, load_behavior_model
from models.db_models import Entity, Event


def test_persisted_isolation_forest_scores_known_anomaly_above_normal():
    normal = {
        "login_hour_irregularity": 0.1, "new_device_count": 0,
        "new_resource_count": 0, "sensitive_access_ratio": 0.05,
        "download_volume_vs_baseline": 1.0, "privilege_change_count": 0,
        "external_destination_novelty": 0, "suspicious_sequence_flag": 0,
        "suspicious_sequence_magnitude": 0,
    }
    anomalous = {
        "login_hour_irregularity": 4, "new_device_count": 4,
        "new_resource_count": 8, "sensitive_access_ratio": 1,
        "download_volume_vs_baseline": 40, "privilege_change_count": 3,
        "external_destination_novelty": 1, "suspicious_sequence_flag": 1,
        "suspicious_sequence_magnitude": 1,
    }
    assert isolation_forest_signal(anomalous) > isolation_forest_signal(normal)
    assert behavior_model_metadata()["signal_source"] == "learned:offline_isolation_forest"
    assert load_behavior_model() is load_behavior_model()


def test_login_risk_combines_geo_velocity_device_novelty_and_failure_burst():
    now = datetime(2026, 9, 15, tzinfo=timezone.utc)
    history = [Event(timestamp=now-timedelta(days=1), actor_id=1, device_id="known", action="login", latitude=12.97, longitude=77.59, result="success")]
    normal = [Event(timestamp=now, actor_id=1, device_id="known", action="login", latitude=12.97, longitude=77.59, result="success")]
    risky = [
        Event(timestamp=now, actor_id=1, device_id="new", action="login", latitude=12.97, longitude=77.59, result="failure"),
        Event(timestamp=now+timedelta(minutes=30), actor_id=1, device_id="new", action="login", latitude=51.50, longitude=-0.12, result="failure"),
    ]
    normal_signal = compute_login_risk(login_risk_features(normal, history))
    risky_signal = compute_login_risk(login_risk_features(risky, history))
    assert risky_signal > normal_signal
    assert 0 <= risky_signal <= 1


def test_each_new_signal_changes_noisy_or_without_bypassing_coverage():
    base = fuse(0.2, 0.1, 0, 0.2, 0, 0.4)
    anomaly = fuse(0.2, 0.1, 0, 0.2, 0, 0.4, M_t=0.8)
    login = fuse(0.2, 0.1, 0, 0.2, 0, 0.4, L_t=0.8)
    assert anomaly["raw_deviation"] > base["raw_deviation"]
    assert login["raw_deviation"] > base["raw_deviation"]
    assert anomaly["residual_risk"] == round(anomaly["raw_deviation"] * 0.6, 4)
    assert login["residual_risk"] == round(login["raw_deviation"] * 0.6, 4)


def test_behavioral_cohort_is_computed_by_deterministic_kmeans():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    now = datetime(2026, 9, 15, tzinfo=timezone.utc)
    actors = []
    for index in range(6):
        actor = Entity(display_name=f"Actor {index}", role="same-role", department="D", hire_date=now-timedelta(days=100))
        db.add(actor); db.flush(); actors.append(actor)
        for hour in range(3):
            db.add(Event(actor_id=actor.id, timestamp=now-timedelta(days=7, hours=12-hour), device_id=f"d-{index if index >= 3 else 0}", action="file_download" if index >= 3 else "login", resource_id=f"r-{index}" if index >= 3 else None, resource_classification="critical" if index >= 3 else None, volume=5000 if index >= 3 else None, result="success"))
    db.commit()
    first = compute_behavioral_cluster(db, actors[0].id, now)
    repeated = compute_behavioral_cluster(db, actors[0].id, now)
    assert first == repeated
    assert first["signal_source"] == "learned:kmeans_behavior_cluster"
    assert first["cluster_count"] >= 2
    db.close()


def test_correlated_signals_use_max_within_category_only():
    categories = {
        "identity": {"signals": {"model": 0.5, "login": 0.5}},
        "resource_access": {"signals": {"asset": 0.5}},
    }
    result = combine_signal_categories(categories)
    assert categories["identity"]["combined"] == 0.5
    assert result == 0.75


def test_recent_drift_does_not_change_own_cluster_assignment():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    now = datetime(2026, 9, 15, tzinfo=timezone.utc)
    actors = []
    for index in range(6):
        actor = Entity(display_name=f"Stable {index}", role="engineering", department="D", hire_date=now-timedelta(days=200))
        db.add(actor); db.flush(); actors.append(actor)
        for hour in range(3):
            db.add(Event(actor_id=actor.id, timestamp=now-timedelta(days=7, hours=12-hour), device_id="stable-a" if index < 3 else "stable-b", action="login" if index < 3 else "file_access", resource_id=None if index < 3 else "repo", resource_classification=None if index < 3 else "internal", result="success"))
    db.commit()
    before = compute_behavioral_cluster(db, actors[0].id, now)
    for hour in range(20):
        db.add(Event(actor_id=actors[0].id, timestamp=now-timedelta(hours=hour), device_id=f"drift-{hour}", action="external_upload", resource_id=f"critical-{hour}", resource_classification="critical", destination="https://outside", volume=10000, result="success"))
    db.commit()
    after = compute_behavioral_cluster(db, actors[0].id, now)
    assert after["actor_ids"] == before["actor_ids"]
    assert after["cluster_id"] == before["cluster_id"]
    assert after["assignment_as_of"] == before["assignment_as_of"]
    assert after["exclusion_days"] == 7
    db.close()
