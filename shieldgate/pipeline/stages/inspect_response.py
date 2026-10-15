"""
PURPOSE : Stage `inspect_response` - check what the model returned before the user sees it:
          system-prompt canary leaks, honeytokens, secrets and stray personal identifiers.
          Tokenize actions are downgraded to mask here so response PII is never "restored".
INPUTS  : ctx.llm_text. OUTPUTS : cleaned ctx.llm_text; alerts in the audit trail.
HOW TO EXTEND : choose detectors via pipeline.yaml response_detectors.
"""
from __future__ import annotations

from core.interfaces import PipelineStage
from core.registry import REGISTRIES, register_stage
from core.types import BLOCKED
from shieldgate.pipeline.stages.act import apply_transforms
from shieldgate.pipeline.stages.detect import get_detectors
from shieldgate.policy.engine import PolicyEngine
from shieldgate.detectors.base import run_detectors

WITHHELD = "The AI's answer was withheld because it did not pass the response security checks."
STOP_ACTIONS = {"deny", "deny_and_alert", "block", "block_with_rewrite"}


@register_stage("inspect_response")
class InspectResponseStage(PipelineStage):
    async def run(self, ctx) -> None:  # noqa: ANN001
        svc = ctx.services
        text = ctx.llm_text
        if ctx.canary and ctx.canary in text:
            ctx.audit("alert", severity="critical", types=["SYSTEM_PROMPT_LEAK"])
            ctx.llm_text = ""
            ctx.halt(BLOCKED, WITHHELD)
            return
        names = svc.config.get("pipeline").get("response_detectors", [])
        found = await run_detectors(get_detectors(svc.config, names), text, ctx,
                                    svc.config.get("detectors")["timeout_ms"])
        found = [f for f in found if not f.type.endswith("_INVALID")]
        if not found:
            return
        decision = PolicyEngine(svc.config).decide(found, ctx.user.role, approved=True)
        stop = [f for f, a, _ in decision.items if a in STOP_ACTIONS]
        if stop:
            ctx.audit("alert", severity="critical" if any(f.type == "HONEYTOKEN" for f in stop) else "high",
                      types=sorted({f.type for f in stop}), where="response")
            ctx.llm_text = ""
            ctx.halt(BLOCKED, WITHHELD)
            return
        items = [(f, "mask" if a == "tokenize" else a) for f, a, _ in decision.items
                 if a in ("tokenize", "mask", "redact")]
        if items:
            ctx.llm_text = apply_transforms(ctx, text, items)
            ctx.audit("response_sanitized", severity="medium", finding_types=_count(items))
            ctx.notice("info", "Some personal data in the AI's answer was masked.")


def _count(items) -> dict[str, int]:  # noqa: ANN001
    out: dict[str, int] = {}
    for f, _ in items:
        out[f.type] = out.get(f.type, 0) + 1
    return out
