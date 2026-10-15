"""
PURPOSE : Shared helpers for detectors: context-window checks, pattern loading and the
          factory that builds enabled detectors from config/detectors.yaml.
INPUTS  : ConfigService, detector names.
OUTPUTS : context_near(), load_patterns(), build_detectors(), run_detectors().
HOW TO EXTEND : plugins subclass core.interfaces.Detector directly; use these helpers if handy.
"""
from __future__ import annotations

import asyncio
from typing import Any

from core.errors import FailClosed
from core.interfaces import Detector
from core.registry import REGISTRIES
from core.types import Finding


def context_near(text: str, start: int, end: int, words: list[str], before: int = 40, after: int = 25) -> bool:
    """True when any context word appears shortly before/after the span (case-insensitive)."""
    if not words:
        return True
    window = text[max(0, start - before):start].lower() + " " + text[end:end + after].lower()
    return any(w.lower() in window for w in words)


def load_patterns(config: Any, files: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in files:
        out.extend(config.get(f)["patterns"])
    return out


def build_detectors(config: Any, only: list[str] | None = None) -> dict[str, Detector]:
    """Instantiate enabled detectors (optionally restricted to `only` names)."""
    cfg = config.get("detectors")["detectors"]
    built: dict[str, Detector] = {}
    for name, spec in cfg.items():
        if not spec.get("enabled", True) or (only is not None and name not in only):
            continue
        if name not in REGISTRIES["detector"]:
            raise FailClosed(f"detector '{name}' is configured but not registered")
        built[name] = REGISTRIES["detector"].create(name, spec.get("settings", {}), config)
    return built


async def run_detectors(detectors: dict[str, Detector], text: str, ctx: Any = None,
                        timeout_ms: int = 800) -> list[Finding]:
    """Run detectors concurrently. Any error or timeout raises FailClosed."""
    async def one(d: Detector) -> list[Finding]:
        return await asyncio.wait_for(d.detect(text, ctx), timeout_ms / 1000)

    try:
        results = await asyncio.gather(*(one(d) for d in detectors.values()))
    except Exception as exc:  # noqa: BLE001 - fail closed on any detector problem
        raise FailClosed(f"detector failure ({type(exc).__name__})") from exc
    findings = [f for r in results for f in r]
    for name, res in zip(detectors, results):
        for f in res:
            f.detector = f.detector or name
    return findings
