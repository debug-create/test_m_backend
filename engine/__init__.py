"""Engine package — behavioral transition detection modules."""

from engine.behavior import compute_feature_vector
from engine.baseline import compute_baseline_deviation
from engine.changepoint import detect_change_points, PageHinkleyDetector
from engine.context import evaluate_context_compatibility
from engine.fusion import compute_risk_for_events, counterfactual_breakdown

__all__ = [
    "compute_feature_vector",
    "compute_baseline_deviation",
    "detect_change_points",
    "PageHinkleyDetector",
    "evaluate_context_compatibility",
    "compute_risk_for_events",
    "counterfactual_breakdown",
]
