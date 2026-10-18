"""Remote ID input handling. Same rule as the backend: 9 digits, no leading zero."""

from __future__ import annotations

import re

REMOTE_ID = re.compile(r"^[1-9][0-9]{8}$")


def normalise(text: str) -> str:
    return re.sub(r"\s+", "", text)


def is_valid(text: str) -> bool:
    return bool(REMOTE_ID.fullmatch(normalise(text)))


def display(text: str) -> str:
    """'105280964' -> '105 280 964' (digits only, grouped in threes)."""
    digits = re.sub(r"\D", "", text)[:9]
    return " ".join(digits[i:i + 3] for i in range(0, len(digits), 3))
