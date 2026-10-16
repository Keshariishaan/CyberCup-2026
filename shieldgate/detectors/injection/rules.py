"""
PURPOSE : Rule-based prompt-injection detector (English, Hindi, Hinglish). Exact phrases and
          regexes on the text, plus a de-obfuscated pass (leetspeak, spacing, homoglyphs, fuzzy
          word-window matching) that defeats trivial evasion.
INPUTS  : text; settings.files = attack config names (config/attacks/*.yaml).
OUTPUTS : PROMPT_INJECTION findings (critical).
HOW TO EXTEND : add phrases/regexes to a YAML file under config/attacks/, or add a new
          language file and list it in config/detectors.yaml.
"""
from __future__ import annotations

import re
import unicodedata
from difflib import SequenceMatcher
from typing import Any

from core.interfaces import Detector
from core.registry import register_detector
from core.types import Finding

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_ZW = dict.fromkeys(map(ord, "​‌‍⁠﻿"))
MESSAGE = "Looks like an attempt to override the assistant's rules or reveal hidden instructions."


def deobfuscate(text: str) -> str:
    """Lowercase, strip accents/zero-width, undo leetspeak, squeeze separators to single spaces."""
    t = unicodedata.normalize("NFKD", text).translate(_ZW).lower().translate(_LEET)
    t = "".join(c for c in t if not unicodedata.combining(c) or "ऀ" <= c <= "ॿ")
    t = re.sub(r"(?<=\w)[.\-_*]+(?=\w)", "", t)  # i.g.n.o.r.e -> ignore
    t = re.sub(r"[^\wऀ-ॿ]+", " ", t)
    return re.sub(r"\s+", " ", t).strip()


@register_detector("injection_rules")
class InjectionRulesDetector(Detector):
    def _load(self) -> tuple[list[str], list[re.Pattern[str]]]:
        cfgs = [self.config.get(f) for f in self.settings.get("files", [])]
        key = tuple(id(c) for c in cfgs)
        if getattr(self, "_loaded_key", None) != key:  # recompute only when the config object changed
            phrases: list[str] = []
            regexes: list[re.Pattern[str]] = []
            for cfg in cfgs:
                phrases += [deobfuscate(p) for p in cfg.get("phrases", [])]
                regexes += [re.compile(r) for r in cfg.get("regexes", [])]
            self._loaded, self._loaded_key = (phrases, regexes), key
        return self._loaded

    async def detect_fast(self, text: str, ctx: Any = None) -> list[Finding]:
        """Exact phrase and regex matching only (skips the fuzzy word-window scan) - used on decoded variants."""
        return await self.detect(text, ctx, fuzzy=False)

    async def detect(self, text: str, ctx: Any = None, fuzzy: bool = True) -> list[Finding]:
        phrases, regexes = self._load()
        hits: list[tuple[int, int, str]] = []
        for rx in regexes:
            for m in rx.finditer(text):
                hits.append((m.start(), m.end(), "pattern"))
        clean = deobfuscate(text)
        if not hits:
            for p in phrases:
                if p and p in clean:
                    hits.append((0, len(text), "phrase"))
                    break
        if fuzzy and not hits and len(clean) < 3000:
            words = clean.split()
            for p in phrases:
                n = len(p.split())
                if n < 2:
                    continue
                for i in range(max(1, len(words) - n + 1)):
                    window = " ".join(words[i:i + n])
                    sm = SequenceMatcher(None, window, p)
                    if sm.real_quick_ratio() >= 0.85 and sm.quick_ratio() >= 0.85 and sm.ratio() >= 0.86:
                        hits.append((0, len(text), "fuzzy"))
                        break
                if hits:
                    break
        if not hits:  # regexes on the de-obfuscated text catch spaced/leet variants
            for rx in regexes:
                if rx.search(clean):
                    hits.append((0, len(text), "obfuscated"))
                    break
        return [Finding(self.name, "PROMPT_INJECTION", s, e, "critical", 0.95, MESSAGE, {"method": how})
                for s, e, how in hits[:1]]
