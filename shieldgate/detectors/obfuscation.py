"""
PURPOSE : Look through common obfuscation so sensitive data and attacks cannot hide: digits spelled out (English,
          Hinglish, Hindi), look-alike letters inside numbers (O for 0, l for 1 ...), base64, hex, ROT13 and
          reversed text. The decoded text is run through the normal detectors; findings are reported on the
          ORIGINAL span so tokenize/mask/block still apply to what the user actually typed.
          Also: `injection_split` catches an attack split across several messages of one conversation.
INPUTS  : text (+ ctx for the split detector). settings.methods lists the enabled techniques.
OUTPUTS : findings of the inner detectors' types (AADHAAR, PROMPT_INJECTION, SECRET ...) with meta.method.
HOW TO EXTEND : add a decoder function to the methods in ObfuscationDetector or a word to DIGIT_WORDS.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
from typing import Any

from core.interfaces import Detector
from core.registry import register_detector
from core.types import Finding
from shieldgate.detectors.validators import VALIDATORS

DIGIT_WORDS = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
    "shunya": 0, "ek": 1, "do": 2, "teen": 3, "char": 4, "chaar": 4, "paanch": 5, "panch": 5, "chhe": 6, "chah": 6,
    "saat": 7, "aath": 8, "nau": 9, "nav": 9,
    "शून्य": 0, "एक": 1, "दो": 2, "तीन": 3, "चार": 4, "पांच": 5, "पाँच": 5, "छह": 6, "छः": 6, "सात": 7, "आठ": 8, "नौ": 9,
}
LOOKALIKE = str.maketrans({"O": "0", "o": "0", "I": "1", "l": "1", "|": "1", "S": "5", "s": "5", "B": "8", "Z": "2", "z": "2"})
_SUBST = re.compile(r"(?<![A-Za-z0-9])[0-9OoIl|SsBZz]{4}[ -]?[0-9OoIl|SsBZz]{4}[ -]?[0-9OoIl|SsBZz]{4}(?![A-Za-z0-9])")
_B64 = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])")
_HEX = re.compile(r"(?<![0-9A-Za-z])(?:[0-9a-fA-F]{2}){8,}(?![0-9A-Za-z])")
INNER = ["identity", "pattern", "secrets", "injection_rules", "cross_user_extraction"]
TEXT_ONLY = ["injection_rules", "cross_user_extraction"]


def _printable(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    ok = sum(c.isprintable() or c in "\n\t" for c in s)
    return s if len(s) >= 8 and ok / len(s) >= 0.95 else None


def decode_b64(token: str) -> str | None:
    t = token.replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    try:
        return _printable(base64.b64decode(t, validate=True))
    except (binascii.Error, ValueError):
        return None


def decode_hex(token: str) -> str | None:
    try:
        return _printable(bytes.fromhex(token))
    except ValueError:
        return None


def digit_runs(text: str, min_len: int = 8) -> list[tuple[int, int, str]]:
    """Runs of >= min_len consecutive digit-words -> (start, end, digits)."""
    runs: list[tuple[int, int, str]] = []
    cur: list[tuple[int, int, int]] = []
    for m in re.finditer(r"\S+", text):
        word = m.group().strip(".,;:-()[]{}\"'").lower()
        if word in DIGIT_WORDS:
            cur.append((m.start(), m.end(), DIGIT_WORDS[word]))
            continue
        if len(cur) >= min_len:
            runs.append((cur[0][0], cur[-1][1], "".join(str(d) for _, _, d in cur)))
        cur = []
    if len(cur) >= min_len:
        runs.append((cur[0][0], cur[-1][1], "".join(str(d) for _, _, d in cur)))
    return runs


def classify_digits(d: str) -> tuple[str, str] | None:
    """(finding type, severity) when the digit string passes a format/checksum validator, else None."""
    if len(d) == 12 and VALIDATORS["verhoeff12"](d).valid:
        return "AADHAAR", "critical"
    if len(d) in (15, 16) and VALIDATORS["luhn"](d).valid:
        return "CARD", "critical"
    if len(d) == 16 and VALIDATORS["verhoeff16"](d).valid:
        return "VID", "critical"
    if len(d) in (10, 12) and VALIDATORS["phone_in"](d).valid:
        return "PHONE", "medium"
    return None


def _inner(config: Any, only: list[str]) -> dict[str, Detector]:
    from shieldgate.pipeline.stages.detect import get_detectors  # lazy: avoids an import cycle
    return get_detectors(config, only)


@register_detector("obfuscation")
class ObfuscationDetector(Detector):
    async def detect(self, text: str, ctx: Any = None) -> list[Finding]:
        from shieldgate.detectors.base import run_detectors
        methods = set(self.settings.get("methods", ["digit_words", "lookalike", "base64", "hex", "rot13", "reversed"]))
        out: list[Finding] = []
        if "digit_words" in methods:
            for s, e, digits in digit_runs(text):
                hit = classify_digits(digits)
                if hit:
                    out.append(Finding(self.name, hit[0], s, e, hit[1], 0.9, "A number written out in words was detected",
                                       {"method": "digit_words"}))
        if "lookalike" in methods:
            for m in _SUBST.finditer(text):
                core = re.sub(r"[ -]", "", m.group())
                if sum(c.isdigit() for c in core) >= 6 and re.search(r"[A-Za-z|]", core):
                    digits = core.translate(LOOKALIKE)
                    if digits.isdigit() and len(digits) == 12 and VALIDATORS["verhoeff12"](digits).valid:
                        out.append(Finding(self.name, "AADHAAR", m.start(), m.end(), "critical", 0.9,
                                           "An Aadhaar written with look-alike letters was detected", {"method": "lookalike"}))
        timeout = self.config.get("detectors")["timeout_ms"]
        decoded: list[tuple[str, int, int, str]] = []  # (method, start, end, decoded text)
        if "base64" in methods:
            for m in _B64.finditer(text):
                d = decode_b64(m.group())
                if d:
                    decoded.append(("base64", m.start(), m.end(), d))
        if "hex" in methods:
            for m in _HEX.finditer(text):
                d = decode_hex(m.group())
                if d:
                    decoded.append(("hex", m.start(), m.end(), d))
        for method, s, e, d in decoded:
            for f in await run_detectors(_inner(self.config, INNER), d, ctx, timeout):
                out.append(Finding(self.name, f.type, s, e, f.severity, f.confidence, f.message, {"method": method}))
        whole: list[tuple[str, str]] = []
        if "rot13" in methods:
            whole.append(("rot13", codecs.decode(text, "rot13")))
        if "reversed" in methods:
            whole += [("reversed", text[::-1]), ("reversed", " ".join(w[::-1] for w in text.split()))]
        for method, variant in whole:
            if variant == text:
                continue
            for d in _inner(self.config, TEXT_ONLY).values():  # exact matching only: decoded variants need no fuzzy scan
                fast = getattr(d, "detect_fast", d.detect)
                hit = await fast(variant, ctx)
                if hit:
                    f = hit[0]
                    out.append(Finding(self.name, f.type, 0, len(text), f.severity, f.confidence, f.message, {"method": method}))
                    break
        return out


@register_detector("injection_split")
class SplitInjectionDetector(Detector):
    """An attack split over several messages: evaluate the previous user turns joined with the current one."""

    async def detect(self, text: str, ctx: Any = None) -> list[Finding]:
        if ctx is None or not getattr(ctx, "conversation_id", ""):
            return []
        from shieldgate.detectors.base import run_detectors
        n = int(self.settings.get("previous_messages", 3))
        history = ctx.services.memory.history(ctx.conversation_id, n + 1, 1500)
        prev = [m["content"] for m in history if m["role"] == "user"][-n:]
        if not prev:
            return []
        dets = _inner(self.config, TEXT_ONLY)
        timeout = self.config.get("detectors")["timeout_ms"]
        if await run_detectors(dets, text, ctx, timeout):
            return []  # the current message alone is already caught by the normal detectors
        joined = await run_detectors(dets, " ".join(prev + [text]), ctx, timeout)
        return [Finding(self.name, f.type, 0, len(text), f.severity, f.confidence,
                        "An attack split across several messages was detected", {"method": "split"}) for f in joined[:1]]
