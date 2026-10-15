"""
PURPOSE : Run generated attacks (and benign controls) through normalize -> detect -> decide ONLY
          (no LLM, no memory, nothing stored) and report the catch rate per category plus misses.
INPUTS  : Services, role to test as, per_category count.
OUTPUTS : report dict {overall, by_category, false_positive_rate, missed_examples}.
HOW TO EXTEND : add mutators in generators.py; report format is consumed by the RedTeam page.
"""
from __future__ import annotations

from typing import Any

from core.types import CurrentUser
from shieldgate.detectors.base import run_detectors
from shieldgate.pipeline.stages.detect import get_detectors
from shieldgate.pipeline.stages.normalize import HOMOGLYPHS, _ZW
from shieldgate.policy.engine import PolicyEngine
from shieldgate.redteam.generators import BENIGN, generate
import unicodedata

BLOCKING = {"block", "block_with_rewrite", "deny", "deny_and_alert"}


async def _blocked(services: Any, text: str, role: str) -> bool:
    t = unicodedata.normalize("NFKC", text).translate(_ZW).translate(HOMOGLYPHS)
    findings = await run_detectors(get_detectors(services.config), t, None, services.config.get("detectors")["timeout_ms"])
    d = PolicyEngine(services.config).decide(findings, role)
    return d.blocking_action in BLOCKING


async def run(services: Any, user: CurrentUser, per_category: int = 6) -> dict[str, Any]:
    cases = generate(services.config, per_category)
    by_cat: dict[str, list[int]] = {}
    missed: list[dict[str, str]] = []
    for cat, prompt in cases:
        hit = await _blocked(services, prompt, user.role)
        by_cat.setdefault(cat, [0, 0])
        by_cat[cat][0] += int(hit)
        by_cat[cat][1] += 1
        if not hit:
            missed.append({"category": cat, "prompt": prompt[:120]})
    fp = sum([await _blocked(services, b, user.role) for b in BENIGN])
    total_hit = sum(v[0] for v in by_cat.values())
    total = sum(v[1] for v in by_cat.values())
    return {"overall": round(total_hit / total, 3) if total else 0.0, "total": total,
            "by_category": {k: {"caught": v[0], "total": v[1], "rate": round(v[0] / v[1], 3)} for k, v in by_cat.items()},
            "false_positives": fp, "benign_total": len(BENIGN), "missed_examples": missed[:15]}
