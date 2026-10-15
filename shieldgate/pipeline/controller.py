"""
PURPOSE : Pipeline controller - runs the stages listed in config/pipeline.yaml in order,
          records per-stage timings, and FAILS CLOSED: any stage exception holds the request
          (nothing reaches the LLM) while the always_run audit stage still executes.
INPUTS  : Services container, PipelineContext.
OUTPUTS : the same context with status/message/response populated.
HOW TO EXTEND : add a stage class with @register_stage("name") and list it in pipeline.yaml.
"""
from __future__ import annotations

import time

from core.interfaces import PipelineStage
from core.logging import get_logger
from core.registry import REGISTRIES
from core.types import HELD, PipelineContext, Services

log = get_logger("pipeline")
HELD_MESSAGE = "Your request was held because a security check could not complete. Nothing was sent to the AI."


class PipelineController:
    def __init__(self, services: Services) -> None:
        self.services = services
        self._stages: dict[str, PipelineStage] = {}

    def _stage(self, name: str) -> PipelineStage:
        if name not in self._stages:
            self._stages[name] = REGISTRIES["stage"].create(name)
        return self._stages[name]

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        cfg = self.services.config.get("pipeline")
        for name in [*cfg["inbound"], *cfg["outbound"]]:
            try:
                stage = self._stage(name)
            except KeyError:
                ctx.halt(HELD, HELD_MESSAGE)
                ctx.audit("fail_closed", severity="high", stage=name, error="unknown_stage")
                continue
            if ctx.halted and not stage.always_run:
                continue
            t0 = time.perf_counter()
            try:
                await stage.run(ctx)
            except Exception as exc:  # noqa: BLE001 - fail closed, never pass through
                log.error("stage %s failed: %s", name, type(exc).__name__)
                ctx.response = ""
                ctx.halt(HELD, HELD_MESSAGE)
                ctx.audit("fail_closed", severity="high", stage=name, error=type(exc).__name__)
            ctx.timings[name] = round((time.perf_counter() - t0) * 1000, 2)
        total = (time.perf_counter() - ctx.started) * 1000
        ctx.timings["total"] = round(total, 2)
        ctx.timings["gateway_overhead"] = round(total - ctx.llm_ms, 2)
        return ctx
