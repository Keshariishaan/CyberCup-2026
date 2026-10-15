"""
PURPOSE : Unit tests for checksum validators and typo-fix suggestions.
INPUTS  : none. OUTPUTS : pass/fail.
HOW TO EXTEND : add vectors for new validators.
"""
from __future__ import annotations

from shieldgate.detectors.validators import VALIDATORS, luhn_valid
from shieldgate.detectors.verhoeff_tools import reformat_like, verhoeff_check_digit, verhoeff_valid


def test_verhoeff_known_vector():
    assert verhoeff_check_digit("236") == 3 and verhoeff_valid("2363")
    assert not verhoeff_valid("2364")


def test_aadhaar_rules():
    good = "23456789012" + str(verhoeff_check_digit("23456789012"))
    assert VALIDATORS["verhoeff12"](good).valid
    assert not VALIDATORS["verhoeff12"]("123456789012").valid  # leading 1
    assert "12 digits" in VALIDATORS["verhoeff12"]("2345").reason


def test_swap_fix_is_suggested_first():
    good = "23456789012" + str(verhoeff_check_digit("23456789012"))
    bad = good[:3] + good[4] + good[3] + good[5:]
    res = VALIDATORS["verhoeff12"](bad)
    fixes = {f["number"]: f["reason"] for f in res.fixes}
    assert not res.valid and good in fixes and "swapped" in fixes[good]


def test_luhn_and_card():
    assert luhn_valid("4111111111111111") and not luhn_valid("4111111111111112")
    assert VALIDATORS["luhn"]("4111111111111111").valid
    assert not VALIDATORS["luhn"]("4111111111111112").valid


def test_pan_phone_gstin():
    assert VALIDATORS["pan"]("ABCPD1234E").valid and not VALIDATORS["pan"]("ABCZD1234E").valid
    assert VALIDATORS["phone_in"]("9876543210").valid and not VALIDATORS["phone_in"]("1234567890").valid
    assert VALIDATORS["gstin"]("27AAPFU0939F1ZV").valid


def test_reformat_like_keeps_spacing():
    assert reformat_like("1234 5678 9012", "999988887777") == "9999 8888 7777"

