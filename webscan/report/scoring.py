"""Letter-grade scorecard derived from a scan's severity counts."""
from __future__ import annotations

GRADE_COLORS = {"A": "--info", "B": "--low", "C": "--medium", "D": "--high",
                "E": "--high", "F": "--critical"}


def grade_from_counts(counts: dict[str, int]) -> tuple[str, int]:
    """Return (letter, 0-100 score) from a rating-counts dict."""
    critical = counts.get("Critical", 0)
    high = counts.get("High", 0)
    medium = counts.get("Medium", 0)
    low = counts.get("Low", 0)
    score = 100 - (critical * 40 + high * 20 + medium * 8 + low * 2)
    score = max(0, min(100, score))
    if critical:
        letter = "F"
    elif high:
        letter = "D" if score >= 55 else "F"
    elif medium:
        letter = "C" if score >= 70 else "D"
    elif low:
        letter = "B" if score >= 88 else "C"
    else:
        letter = "A"
    return letter, score


def grade(result) -> tuple[str, int]:
    return grade_from_counts(result.rating_counts)
