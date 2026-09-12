"""Module 4 — Page-Hinkley change-point detector with regime latch / re-arm.

Implements the classic Page-Hinkley update rule, plus a latch so a sustained
plateau after a detected shift does not emit duplicate change points. The latch
re-arms only after a sustained return toward baseline (reverse PH).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Sequence, Union

from config import PH_ALPHA, PH_DELTA, PH_LAMBDA

Number = Union[int, float]


@dataclass
class PageHinkleyDetector:
    """Online Page-Hinkley change-point detector with regime latch."""

    delta: float = PH_DELTA
    threshold: float = PH_LAMBDA
    alpha: float = PH_ALPHA  # forgetting factor for running mean
    direction: str = "up"  # detect upward mean shifts (risk increases)
    feature_key: str = "overall_deviation"

    _mean: float = 0.0
    _n: int = 0
    _cum: float = 0.0
    _min_cum: float = 0.0
    _max_cum: float = 0.0
    change_points: list[int] = field(default_factory=list)

    # Regime latch state
    regime_state: str = "nominal"  # nominal | latched
    _baseline_mean: float = 0.0  # mean snapshot at latch time (pre-shift)
    _rearm_cum: float = 0.0
    _rearm_max: float = 0.0
    _rearm_mean: float = 0.0
    _rearm_n: int = 0

    def reset(self) -> None:
        self._mean = 0.0
        self._n = 0
        self._cum = 0.0
        self._min_cum = 0.0
        self._max_cum = 0.0
        self.change_points = []
        self.regime_state = "nominal"
        self._baseline_mean = 0.0
        self._rearm_cum = 0.0
        self._rearm_max = 0.0
        self._rearm_mean = 0.0
        self._rearm_n = 0

    def _latch(self) -> None:
        self.regime_state = "latched"
        self._baseline_mean = self._mean
        self._cum = 0.0
        self._min_cum = 0.0
        self._max_cum = 0.0
        self._rearm_cum = 0.0
        self._rearm_max = 0.0
        self._rearm_mean = self._mean
        self._rearm_n = 0

    def _try_rearm(self, x: float) -> bool:
        """
        Reverse Page-Hinkley: detect sustained return toward (or below) the
        pre-shift baseline mean. Uses the same δ / λ as the forward detector.
        """
        self._rearm_n += 1
        if self._rearm_n == 1:
            self._rearm_mean = x
            return False

        self._rearm_mean = self.alpha * x + (1.0 - self.alpha) * self._rearm_mean
        # Accumulate evidence that values are dropping toward baseline
        target = self._baseline_mean
        self._rearm_cum += (self._rearm_mean - x) - self.delta
        # Also credit when x is close to the stored baseline
        if abs(x - target) <= max(self.delta * 2, 0.05) and x <= self._rearm_mean:
            self._rearm_cum += self.delta

        self._rearm_max = max(self._rearm_max, self._rearm_cum)
        ph = self._rearm_max - self._rearm_cum
        # Fire when sustained downward move exceeds threshold, OR value has
        # stayed near baseline for enough steps with low rearm mean
        near_baseline = abs(x - target) <= max(abs(target) * 0.25 + 0.1, 0.15)
        if ph > self.threshold or (
            near_baseline and self._rearm_n >= 5 and self._rearm_mean <= target + self.delta * 3
        ):
            self.regime_state = "nominal"
            self._rearm_cum = 0.0
            self._rearm_max = 0.0
            self._rearm_n = 0
            self._cum = 0.0
            self._min_cum = 0.0
            self._max_cum = 0.0
            return True
        return False

    def update(self, value: Number, index: Optional[int] = None) -> bool:
        """
        Ingest one observation. Returns True if a *new* change point is detected
        at this step. While latched, never emits; may re-arm silently.
        """
        x = float(value)
        idx = index if index is not None else self._n

        if self.regime_state == "latched":
            # Still update running mean for transparency, but do not emit
            self._n += 1
            self._mean = self.alpha * x + (1.0 - self.alpha) * self._mean
            self._try_rearm(x)
            return False

        self._n += 1
        if self._n == 1:
            self._mean = x
            return False

        # Exponentially-weighted running mean
        self._mean = self.alpha * x + (1.0 - self.alpha) * self._mean

        if self.direction == "up":
            self._cum += x - self._mean - self.delta
            self._min_cum = min(self._min_cum, self._cum)
            ph = self._cum - self._min_cum
        else:
            self._cum += self._mean - x - self.delta
            self._max_cum = max(self._max_cum, self._cum)
            ph = self._max_cum - self._cum

        if ph > self.threshold:
            self.change_points.append(idx)
            self._latch()
            return True
        return False

    def detect(
        self,
        values: Sequence[Number],
        timestamps: Optional[Sequence[datetime]] = None,
        *,
        initial_regime: str = "nominal",
    ) -> dict:
        """
        Run the detector over an entire series.

        Returns change_point_indices/timestamps, final regime_state, and params.
        """
        self.reset()
        if initial_regime == "latched":
            # Preserve latch across a re-run (e.g. persisted actor state)
            self.regime_state = "latched"
            if values:
                self._baseline_mean = float(values[0])
                self._mean = float(values[0])

        for i, v in enumerate(values):
            self.update(v, index=i)

        ts_out: list[str] = []
        if timestamps is not None:
            for i in self.change_points:
                if 0 <= i < len(timestamps):
                    t = timestamps[i]
                    ts_out.append(t.isoformat() if hasattr(t, "isoformat") else str(t))

        return {
            "change_point_indices": list(self.change_points),
            "change_point_timestamps": ts_out,
            "series_length": len(values),
            "regime_state": self.regime_state,
            "feature_key": self.feature_key,
            "params": {
                "delta": self.delta,
                "lambda": self.threshold,
                "alpha": self.alpha,
                "direction": self.direction,
            },
        }


def detect_change_points(
    values: Sequence[Number],
    timestamps: Optional[Sequence[datetime]] = None,
    delta: float = PH_DELTA,
    threshold: float = PH_LAMBDA,
    alpha: float = PH_ALPHA,
    *,
    initial_regime: str = "nominal",
    feature_key: str = "overall_deviation",
) -> dict:
    """Convenience wrapper around PageHinkleyDetector.detect."""
    detector = PageHinkleyDetector(
        delta=delta,
        threshold=threshold,
        alpha=alpha,
        feature_key=feature_key,
    )
    return detector.detect(
        values, timestamps=timestamps, initial_regime=initial_regime
    )
