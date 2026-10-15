"""
PURPOSE : Stage `decide` - ask the policy engine what to do with the findings (role overrides,
          precedence, approvals) and update the conversation's multi-turn risk score.
INPUTS  : ctx.findings, ctx.user.role, ctx.approval_id.
OUTPUTS : ctx.decision; may halt when cumulative conversation risk exceeds the threshold.
HOW TO EXTEND : tune conversation_risk in app.yaml; policy lives in policy.yaml.
"""
from __future__ import annotations

from core.interfaces import PipelineStage
from core.registry import register_stage
from core.types import BLOCKED
from shieldgate.policy.engine import PolicyEngine


@register_stage("decide")
class DecideStage(PipelineStage):
    async def run(self, ctx) -> None:  # noqa: ANN001
        svc = ctx.services
        approved = svc.approvals.is_approved(ctx.approval_id, ctx.user, ctx.text)
        ctx.decision = PolicyEngine(svc.config).decide(ctx.findings, ctx.user.role, approved)
        risk_cfg = svc.config.get("app").get("conversation_risk", {})
        weights = risk_cfg.get("weights", {})
        # risk grows with hostile attempts (blocked/denied actions), not with PII that was safely tokenized
        counted = set(risk_cfg.get("count_actions", ["block", "block_with_rewrite", "deny", "deny_and_alert"]))
        delta = int(sum(weights.get(f.severity, 0) for f, a, _ in ctx.decision.items if a in counted))
        ctx.risk_added = delta
        score = svc.memory.add_risk(ctx.conversation_id, delta, risk_cfg.get("decay", 0.8))
        ctx.extras["risk_score"] = round(score, 1)
        if not ctx.decision.blocking_action and score >= risk_cfg.get("block_threshold", 60):  # cool-down after repeated attempts
            ctx.audit("risk_block", severity="high", risk=round(score, 1))
            ctx.halt(BLOCKED, "Several risky requests in a row were detected in this conversation. "
                              "Please start a new conversation or contact your administrator.")


