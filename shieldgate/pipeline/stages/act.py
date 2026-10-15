"""
PURPOSE : Stage `act` - execute the decision: run the strongest blocking action (halts the
          request), otherwise apply transform actions (tokenize/mask/redact) to the text and
          run notice-only actions. Also exports apply_transforms() for response inspection.
INPUTS  : ctx.decision, ctx.text.
OUTPUTS : sanitized ctx.text / ctx.sanitized_text, notices, or a halted ctx.
HOW TO EXTEND : new actions need no change here - they are looked up by name from the registry.
"""
from __future__ import annotations

from typing import Any

from core.interfaces import Action, PipelineStage
from core.registry import REGISTRIES, register_stage
from core.types import Decision, Finding
from shieldgate.policy.precedence import resolve_overlaps


def apply_transforms(ctx: Any, text: str, items: list[tuple[Finding, str]]) -> str:
    """Apply replacement() of each finding's action; numbering is left-to-right, edits right-to-left."""
    actions = {name: REGISTRIES["action"].create(name) for _, name in items}
    # only actions that override replacement() take part, so e.g. a whole-text `warn` finding
    # cannot shadow a PII span that must be tokenized
    by_id = {id(f): actions[n] for f, n in items if type(actions[n]).replacement is not Action.replacement}
    spans = resolve_overlaps([f for f, _ in items if id(f) in by_id])
    reps: list[tuple[Finding, str]] = []
    for f in spans:  # ascending: placeholder numbers follow reading order
        r = by_id[id(f)].replacement(ctx, f, text[f.start:f.end])
        if r is not None:
            reps.append((f, r))
    for f, r in reversed(reps):
        text = text[:f.start] + r + text[f.end:]
    return text


async def run_non_blocking(ctx: Any, decision: Decision) -> None:
    """Run apply() for notice-style actions and transform the text for replacement actions."""
    by_action: dict[str, list[Finding]] = {}
    for f, a, _ in decision.items:
        by_action.setdefault(a, []).append(f)
    for name, fs in by_action.items():
        await REGISTRIES["action"].create(name).apply(ctx, fs)
    ctx.text = apply_transforms(ctx, ctx.text, [(f, a) for f, a, _ in decision.items])


@register_stage("act")
class ActStage(PipelineStage):
    async def run(self, ctx) -> None:  # noqa: ANN001
        d: Decision = ctx.decision
        if d.blocking_action:
            fs = [f for f, a, _ in d.items if a == d.blocking_action]
            await REGISTRIES["action"].create(d.blocking_action).apply(ctx, fs)
            return
        await run_non_blocking(ctx, d)
        ctx.sanitized_text = ctx.text
