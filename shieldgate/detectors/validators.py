"""
PURPOSE : Format/checksum validators selectable by name from config (identity.yaml `kind`,
          patterns `validator`). Wording rule: these perform "format and checksum validation"
          only; they never confirm that a number was issued.
INPUTS  : candidate string (separators already removed by the caller where numeric).
OUTPUTS : VALIDATORS registry of callables returning ValidationResult.
HOW TO EXTEND : decorate a function with @register_validator("name") and reference it in YAML.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from shieldgate.detectors.verhoeff_tools import suggest_fixes, verhoeff_valid


@dataclass
class ValidationResult:
    valid: bool
    reason: str = ""
    fixes: list[dict[str, str]] = field(default_factory=list)


VALIDATORS: dict[str, Callable[[str], ValidationResult]] = {}


def register_validator(name: str) -> Callable[[Callable[[str], ValidationResult]], Callable[[str], ValidationResult]]:
    def deco(fn: Callable[[str], ValidationResult]) -> Callable[[str], ValidationResult]:
        VALIDATORS[name] = fn
        return fn
    return deco


def luhn_valid(number: str) -> bool:
    if not number.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2:
            d *= 2
            d -= 9 if d > 9 else 0
        total += d
    return total % 10 == 0


@register_validator("verhoeff12")
def aadhaar(number: str) -> ValidationResult:
    """Aadhaar: 12 digits, first digit 2-9, Verhoeff checksum."""
    if len(number) != 12:
        return ValidationResult(False, f"an Aadhaar number has 12 digits, this has {len(number)}")
    if number[0] in "01":
        return ValidationResult(False, "Aadhaar numbers never start with 0 or 1")
    if verhoeff_valid(number):
        return ValidationResult(True, "format and checksum are valid")
    fixes = suggest_fixes(number, verhoeff_valid, accept=lambda s: s[0] in "23456789")
    return ValidationResult(False, "the checksum (Verhoeff) does not match - usually a typing mistake", fixes)


@register_validator("verhoeff16")
def vid(number: str) -> ValidationResult:
    """Aadhaar Virtual ID: 16 digits, Verhoeff checksum."""
    if len(number) != 16:
        return ValidationResult(False, f"a Virtual ID has 16 digits, this has {len(number)}")
    if verhoeff_valid(number):
        return ValidationResult(True, "format and checksum are valid")
    return ValidationResult(False, "the checksum (Verhoeff) does not match", suggest_fixes(number, verhoeff_valid))


@register_validator("luhn")
def card(number: str) -> ValidationResult:
    """Payment card: 13-19 digits and Luhn checksum."""
    if not 13 <= len(number) <= 19:
        return ValidationResult(False, f"card numbers have 13-19 digits, this has {len(number)}")
    if luhn_valid(number):
        return ValidationResult(True, "format and Luhn checksum are valid")
    return ValidationResult(False, "the Luhn checksum does not match - usually a typing mistake",
                            suggest_fixes(number, luhn_valid, limit=4))


@register_validator("pan")
def pan(value: str) -> ValidationResult:
    """PAN: AAAAA9999A with a valid holder-type letter in position 4."""
    v = value.upper()
    if not re.fullmatch(r"[A-Z]{5}\d{4}[A-Z]", v):
        return ValidationResult(False, "PAN format is 5 letters, 4 digits, 1 letter")
    if v[3] not in "ABCFGHLJPTK":
        return ValidationResult(False, "the 4th character is not a valid holder type (A,B,C,F,G,H,L,J,P,T,K)")
    return ValidationResult(True, "format is valid (PAN has no public checksum)")


@register_validator("phone_in")
def phone(value: str) -> ValidationResult:
    """Indian mobile number using the phonenumbers library."""
    import phonenumbers
    digits = re.sub(r"[^\d+]", "", value)
    if not re.fullmatch(r"(?:\+?91)?[6-9]\d{9}", digits):
        return ValidationResult(False, "an Indian mobile number has 10 digits and starts with 6, 7, 8 or 9")
    try:
        num = phonenumbers.parse(digits, "IN")
    except phonenumbers.NumberParseException:
        return ValidationResult(False, "this does not look like a phone number")
    if phonenumbers.is_valid_number(num):
        return ValidationResult(True, "format is valid")
    return ValidationResult(False, "this is not a valid Indian mobile number (10 digits starting 6-9)")


@register_validator("gstin")
def gstin(value: str) -> ValidationResult:
    """GSTIN: 15 chars, base-36 mod-36 checksum."""
    v = value.upper()
    if not re.fullmatch(r"\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]", v):
        return ValidationResult(False, "GSTIN format is invalid")
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    total = 0
    for i, ch in enumerate(v[:14]):
        p = chars.index(ch) * (1 if i % 2 == 0 else 2)
        total += p // 36 + p % 36
    return ValidationResult(chars[(36 - total % 36) % 36] == v[14], "checksum " + ("ok" if chars[(36 - total % 36) % 36] == v[14] else "mismatch"))

