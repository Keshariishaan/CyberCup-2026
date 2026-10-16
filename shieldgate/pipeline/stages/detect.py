"""
PURPOSE : Stage `detect` - run all enabled detectors (config/detectors.yaml) concurrently with a
          per-detector timeout. Any detector error fails closed (FailClosed -> request held).
INPUTS  : ctx.text. OUTPUTS : ctx.findings (spans + types only).
HOW TO EXTEND : enable/disable detectors in detectors.yaml; add new ones as plugins.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from core.interfaces import PipelineStage
from core.registry import register_stage
from shieldgate.detectors.base import build_detectors, run_detectors

_cache: dict[tuple[str, tuple[str, ...] | None], dict[str, Any]] = {}


def get_detectors(config: Any, only: list[str] | None = None) -> dict[str, Any]:
    """Detector instances cached per (detectors-config content, requested set). Stages ask for different sets
    (all / chunk scan / response check / decoded variants); each keeps its own warm instances, so the attack-corpus
    embeddings and compiled rules are built once, not on every request."""
    key = hashlib.md5(json.dumps(config.get("detectors"), sort_keys=True, default=str).encode()).hexdigest()
    k = (key, tuple(only) if only is not None else None)
    if k not in _cache:
        if len(_cache) > 64:
            _cache.clear()
        _cache[k] = build_detectors(config, only)
    return _cache[k]


@register_stage("detect")
class DetectStage(PipelineStage):
    async def run(self, ctx) -> None:  # noqa: ANN001
        cfg = ctx.services.config
        ctx.findings = await run_detectors(get_detectors(cfg), ctx.text, ctx, cfg.get("detectors")["timeout_ms"])
