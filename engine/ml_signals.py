"""Deterministic inference for persisted non-LLM constituent models."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib
import numpy as np


MODEL_PATH = Path(__file__).resolve().parents[1] / "ml" / "behavior_isolation_forest.joblib"


@lru_cache(maxsize=1)
def load_behavior_model() -> dict[str, Any]:
    if not MODEL_PATH.exists():
        raise RuntimeError(
            "Persisted behavior model is missing; run `python -m ml.train_models` offline"
        )
    return joblib.load(MODEL_PATH)


def behavior_vector(features: dict[str, Any]) -> np.ndarray:
    bundle = load_behavior_model()
    return np.array(
        [[float(features.get(name, 0.0)) for name in bundle["feature_order"]]],
        dtype=float,
    )


def isolation_forest_signal(features: dict[str, Any]) -> float:
    """Return a calibrated 0–1 anomaly constituent from the persisted model."""
    bundle = load_behavior_model()
    score = float(bundle["model"].decision_function(behavior_vector(features))[0])
    threshold = float(bundle["normal_threshold"])
    floor = float(bundle["anomaly_floor"])
    denominator = max(threshold - floor, 1e-9)
    return round(max(0.0, min(1.0, (threshold - score) / denominator)), 4)


def behavior_model_metadata() -> dict[str, Any]:
    bundle = load_behavior_model()
    return {
        "signal_source": "learned:offline_isolation_forest",
        "model_type": bundle["model_type"],
        "training_source": bundle["training_source"],
        "training_seed": bundle["training_seed"],
    }
