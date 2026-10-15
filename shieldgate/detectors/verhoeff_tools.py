"""
PURPOSE : Verhoeff checksum (used by Aadhaar and VID) plus "likely typo" fix suggestions
          (adjacent-digit swaps first, then single-digit substitutions).
INPUTS  : digit strings.
OUTPUTS : verhoeff_valid(), verhoeff_check_digit(), suggest_fixes(), reformat_like().
HOW TO EXTEND : pass any other checksum predicate to suggest_fixes() (see Luhn in validators.py).
NOTE    : checksum validity only catches typing mistakes; it never proves a number was issued.
"""
from __future__ import annotations

from typing import Callable

_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    """True when the digit string (check digit included) passes the Verhoeff checksum."""
    if not number.isdigit():
        return False
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(number_without_check: str) -> int:
    """Check digit to append to `number_without_check`."""
    c = 0
    for i, ch in enumerate(reversed(number_without_check)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return _INV[c]


def suggest_fixes(number: str, is_valid: Callable[[str], bool], limit: int = 5,
                  accept: Callable[[str], bool] = lambda s: True) -> list[dict[str, str]]:
    """Return likely corrections: swapped neighbours first, then one wrong digit.

    Each item: {"number": candidate_digits, "reason": human explanation}.
    """
    out: list[dict[str, str]] = []
    seen = {number}
    for i in range(len(number) - 1):
        if number[i] != number[i + 1]:
            cand = number[:i] + number[i + 1] + number[i] + number[i + 2:]
            if cand not in seen and is_valid(cand) and accept(cand):
                seen.add(cand)
                out.append({"number": cand, "reason": f"digits {i + 1} and {i + 2} were swapped"})
    for i in range(len(number)):
        for d in "0123456789":
            if d == number[i]:
                continue
            cand = number[:i] + d + number[i + 1:]
            if cand not in seen and is_valid(cand) and accept(cand):
                seen.add(cand)
                out.append({"number": cand, "reason": f"digit {i + 1} was '{number[i]}' (maybe '{d}')"})
    return out[:limit]


def reformat_like(original: str, digits: str) -> str:
    """Re-apply the spacing/hyphens of `original` to a new digit string."""
    out, i = [], 0
    for ch in original:
        if ch.isdigit() and i < len(digits):
            out.append(digits[i])
            i += 1
        else:
            out.append(ch)
    return "".join(out) + digits[i:]
