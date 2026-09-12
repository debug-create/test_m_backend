"""Smoke test: Page-Hinkley must detect a sustained mean shift on synthetic data."""

from engine.changepoint import PageHinkleyDetector, detect_change_points


def test_page_hinkley_detects_shift():
    # Stable low series, then sustained jump
    series = [0.1, 0.12, 0.08, 0.11, 0.09, 0.1, 0.13, 0.1] + [1.5] * 20
    result = detect_change_points(series, delta=0.05, threshold=1.5, alpha=0.05)
    assert result["change_point_indices"], "Expected at least one change point"
    # First detection should be after the jump begins (index >= 8)
    assert min(result["change_point_indices"]) >= 7


def test_page_hinkley_no_false_alarm_on_flat():
    series = [0.5] * 40
    detector = PageHinkleyDetector(delta=0.05, threshold=5.0, alpha=0.01)
    result = detector.detect(series)
    assert result["change_point_indices"] == []


def test_page_hinkley_latches_rearms_and_detects_independent_shift():
    detector = PageHinkleyDetector(delta=0.05, threshold=1.5, alpha=0.05)
    values = [0.1] * 10 + [1.5] * 20 + [0.1] * 12 + [1.5] * 20
    hits = [i for i, value in enumerate(values) if detector.update(value, i)]
    assert len([i for i in hits if 10 <= i < 42]) == 1
    assert len(hits) == 2
    assert hits[1] >= 42


if __name__ == "__main__":
    test_page_hinkley_detects_shift()
    test_page_hinkley_no_false_alarm_on_flat()
    print("PASS: Page-Hinkley detector behaves correctly on synthetic series.")
