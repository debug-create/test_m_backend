"""M7-style risk and evidence-coverage invariants."""

from engine.fusion import fuse
from engine.fusion import fuse_event_residuals


def test_full_coverage_produces_exact_zero_and_preserves_raw():
    result = fuse(1.0, 0.8, 0.6, 1.0, 0.4, 1.0)
    assert result["raw_deviation"] > 0
    assert result["context_coverage"] == 1.0
    assert result["residual_risk"] == 0.0


def test_coverage_is_evidence_measure_not_score_reduction_ratio():
    low = fuse(0.1, 0.0, 0.0, 0.1, 0.0, 0.5)
    high = fuse(1.0, 1.0, 1.0, 1.0, 1.0, 0.5)
    assert low["raw_deviation"] != high["raw_deviation"]
    assert low["context_coverage"] == high["context_coverage"] == 0.5


def test_context_never_changes_raw_deviation():
    uncovered = fuse(0.9, 0.4, 0.7, 1.0, 0.2, 0.0)
    covered = fuse(0.9, 0.4, 0.7, 1.0, 0.2, 1.0)
    assert uncovered["raw_deviation"] == covered["raw_deviation"]


def test_no_manual_weights_or_sigmoid_are_reported():
    result = fuse(0.9, 0.4, 0.7, 1.0, 0.2, 0.3)
    assert result["fusion_method"] == "unweighted_noisy_or_then_evidence_coverage"
    assert not any(key.startswith("W_") for key in result)


def test_many_low_risk_explanations_cannot_hide_one_critical_event():
    inputs = [
        {"event_id": index, "raw_risk": 0.05, "context_credit": 1.0, "critical_reasons": []}
        for index in range(1, 11)
    ]
    inputs.append({"event_id": 11, "raw_risk": 0.95, "context_credit": 0.0,
                   "critical_reasons": ["external_upload"]})
    result = fuse_event_residuals(inputs)
    assert result["residual_risk"] == 95.0
    assert result["context_coverage"] < 0.35


def test_explained_critical_event_retains_25_percent_floor():
    result = fuse_event_residuals([{
        "event_id": 1, "raw_risk": 0.9, "context_credit": 1.0,
        "critical_reasons": ["privilege_escalation"],
    }])
    row = result["event_risk_breakdown"][0]
    assert row["residual_before_floor"] == 0.0
    assert row["critical_floor"] == 25.0
    assert result["residual_risk"] == 25.0
