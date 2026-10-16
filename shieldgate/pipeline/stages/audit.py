"""
PURPOSE : Stage `audit` (always runs) - emit one content-free "chat" audit event (types/counts,
          actions, token usage, timings, status) plus any queued alert/denial events.
          Never includes the prompt, the response, or any sensitive value.
INPUTS  : the whole context. OUTPUTS : events on the audit queue.
HOW TO EXTEND : add more counters to `details`; keep them content-free.
"""
from __future__ import annotations

from core.interfaces import PipelineStage
from core.registry import register_stage


@register_stage("audit")
class AuditStage(PipelineStage):
    always_run = True

    async def run(self, ctx) -> None:  # noqa: ANN001
        svc = ctx.services
        types: dict[str, int] = {}
        for f in ctx.findings:
            types[f.type] = types.get(f.type, 0) + 1
        actions: dict[str, int] = {}
        if ctx.decision:
            for _, a, _ in ctx.decision.items:
                actions[a] = actions.get(a, 0) + 1
        # which policy rule fired for which finding type, and what action it produced - answers "which policy triggered?"
        agg: dict[tuple[str, str, str], int] = {}
        if ctx.decision:
            for f, a, rule in ctx.decision.items:
                agg[(f.type, rule, a)] = agg.get((f.type, rule, a), 0) + 1
        policies = [{"type": t, "rule_id": r, "action": a, "count": n} for (t, r, a), n in sorted(agg.items())]
        prov = [{"chunk": c["chunk_id"], "v": c.get("version", 1), "sha": c.get("sha", "")} for c in ctx.provenance]
        base = {"user_id": ctx.user.user_id, "username": ctx.user.username, "role": ctx.user.role,
                "request_id": ctx.request_id}
        sev = "info"
        if ctx.findings:
            sev = max((f.severity for f in ctx.findings), key=lambda s: ["info", "low", "medium", "high", "critical"].index(s))
        svc.audit.emit({**base, "event": "chat", "status": ctx.status, "severity": sev, "details": {
            "finding_types": types, "actions": actions, "tokenized": ctx.extras.get("tokenized", {}),
            "tokens": [ctx.usage.get("prompt_tokens", 0), ctx.usage.get("completion_tokens", 0)],
            "cached": ctx.cache_hit, "docs": sorted({c["doc_id"] for c in ctx.chunks}),
            "skills": [s["skill"] for s in ctx.skill_outputs], "risk": ctx.extras.get("risk_score", 0),
            "gateway_overhead_ms": ctx.timings.get("gateway_overhead", 0), "llm_ms": round(ctx.llm_ms, 1),
            "policies": policies, "provenance": prov, "conversation_id": ctx.conversation_id}})
        for ev in ctx.audit_events:
            ev = dict(ev)
            name, severity = ev.pop("event"), ev.pop("severity", "info")
            svc.audit.emit({**base, "event": name, "status": ctx.status, "severity": severity,
                            "details": {**ev, "policies": policies, "conversation_id": ctx.conversation_id}})
