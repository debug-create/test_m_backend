"""Train deterministic synthetic-data models offline.

Run explicitly when the checked-in artifact needs to be regenerated:
    python -m ml.train_models

The API never calls this module and never fits a model per request.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


ARTIFACT = Path(__file__).with_name("behavior_isolation_forest.joblib")
FEATURE_ORDER = (
    "login_hour_irregularity", "new_device_count", "new_resource_count",
    "sensitive_access_ratio", "download_volume_vs_baseline",
    "privilege_change_count", "external_destination_novelty",
    "suspicious_sequence_flag", "suspicious_sequence_magnitude",
)


def synthetic_normal_vectors(seed: int = 20260915, count: int = 2000) -> np.ndarray:
    rng = np.random.default_rng(seed)
    sequence = rng.binomial(1, 0.015, count)
    return np.column_stack([
        rng.gamma(1.2, 0.18, count),
        rng.binomial(1, 0.06, count),
        rng.poisson(0.35, count),
        rng.beta(1.2, 8.0, count),
        rng.lognormal(0.0, 0.30, count),
        rng.binomial(1, 0.025, count),
        rng.beta(0.7, 9.0, count),
        sequence,
        sequence * rng.uniform(0.3, 0.8, count),
    ]).astype(float)


def train(output: Path = ARTIFACT) -> Path:
    vectors = synthetic_normal_vectors()
    model = IsolationForest(
        n_estimators=200,
        contamination=0.03,
        random_state=20260915,
        n_jobs=1,
    ).fit(vectors)
    normal_scores = model.decision_function(vectors)
    anomaly_probes = np.array([
        [4, 4, 8, 1, 40, 3, 1, 1, 1],
        [3, 2, 5, .9, 25, 2, 1, 1, .9],
        [2, 5, 2, .8, 15, 1, .9, 0, 0],
    ], dtype=float)
    anomaly_scores = model.decision_function(anomaly_probes)
    bundle = {
        "model": model,
        "feature_order": FEATURE_ORDER,
        "normal_threshold": float(np.percentile(normal_scores, 5)),
        "anomaly_floor": float(min(anomaly_scores)),
        "training_seed": 20260915,
        "training_source": "synthetic_behavior_vectors_v1",
        "model_type": "IsolationForest",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, output, compress=3)
    return output


if __name__ == "__main__":
    print(train())
