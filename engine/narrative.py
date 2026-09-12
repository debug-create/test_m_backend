"""Narrative validation — block verdict-laden language in generated case text."""

from __future__ import annotations

import re

# Banned as verdict claims in generated explanation/narrative strings.
# Scenario labels in seed/code (e.g. display_name) are out of scope.
_BANNED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("malicious", re.compile(r"\bmalicious\b", re.IGNORECASE)),
    ("suspicious", re.compile(r"\bsuspicious\b", re.IGNORECASE)),
    ("rogue", re.compile(r"\brogue\b", re.IGNORECASE)),
    ("attacker", re.compile(r"\battacker\b", re.IGNORECASE)),
    ("guilty", re.compile(r"\bguilty\b", re.IGNORECASE)),
    ("innocent", re.compile(r"\binnocent\b", re.IGNORECASE)),
    ("safe", re.compile(r"\bsafe\b", re.IGNORECASE)),
    ("threat actor", re.compile(r"\bthreat\s+actor\b", re.IGNORECASE)),
    ("criminal", re.compile(r"\bcriminal\b", re.IGNORECASE)),
    ("compromised", re.compile(r"\bcompromised\b", re.IGNORECASE)),
]


class VerdictLanguageError(ValueError):
    """Raised when generated narrative asserts a forbidden verdict word."""


def assert_no_verdict_language(text: str) -> str:
    """
    Raise VerdictLanguageError if `text` contains banned verdict language.
    Returns the original text unchanged when clean (does not mutate).
    """
    if text is None:
        return text
    sample = str(text)
    for label, pattern in _BANNED_PATTERNS:
        if pattern.search(sample):
            raise VerdictLanguageError(
                f"Generated narrative contains banned verdict language: '{label}'"
            )
    return sample


def sanitize_narrative_list(items: list[str]) -> list[str]:
    """Validate each string; return a new list (input not mutated)."""
    return [assert_no_verdict_language(s) for s in items]
