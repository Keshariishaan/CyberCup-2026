"""
PURPOSE : Stage `detect` - run all enabled detectors (config/detectors.yaml) concurrently with a
          per-detector timeout. Any detector error fails closed (FailClosed -> request held).
INPUTS  : ctx.text. OUTPUTS : ctx.findings (spans + types only).
HOW TO EXTEND : enable/disable detectors in detectors.yaml; add new ones as plugins.
"""
from __future__ import annotations

import json
from typing import Any

from core.interfaces import PipelineStage
from core.registry import register_stage
from shieldgate.detectors.base import build_detectors, run_detectors

_cache: dict[str, Any] = {"key": None, "detectors": None}


def get_detectors(config: Any, only: list[str] | None = None) -> dict[str, Any]:
    """Detector instances cached per detectors-config content (keeps corpus embeddings warm)."""
    key = json.dumps([config.get("detectors"), only], sort_keys=True, default=str)
    if _cache.get("key") != key:
        _cache["key"], _cache["detectors"] = key, build_detectors(config, only)
    return _cache["detectors"]


@register_stage("detect")
class DetectStage(PipelineStage):
    async def run(self, ctx) -> None:  # noqa: ANN001
        cfg = ctx.services.config
        ctx.findings = await run_detectors(get_detectors(cfg), ctx.text, ctx, cfg.get("detectors")["timeout_ms"])
