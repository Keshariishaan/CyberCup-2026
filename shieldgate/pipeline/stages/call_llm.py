"""
PURPOSE : Stage `call_llm` - call the provider within the latency budget, with an encrypted TTL
          response cache and token/cost tracking in the database.
INPUTS  : ctx.system_prompt, ctx.messages.
OUTPUTS : ctx.llm_text (still containing placeholders), ctx.usage; a TokenUsage row.
HOW TO EXTEND : switch providers via LLM_PROVIDER; tune llm.cache and cost rates in app.yaml.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time

from core.errors import FailClosed
from core.interfaces import PipelineStage
from core.registry import register_stage
from shieldgate.db.models import TokenUsage


@register_stage("call_llm")
class CallLLMStage(PipelineStage):
    async def run(self, ctx) -> None:  # noqa: ANN001
        svc = ctx.services
        cfg = svc.config.get("app")["llm"]
        budget_ms = svc.config.get("pipeline")["latency_budget_ms"]
        remaining = budget_ms / 1000 - (time.perf_counter() - ctx.started)
        if remaining <= 0.05:
            raise FailClosed("latency budget exhausted before the model call")
        cache_cfg = cfg.get("cache", {})
        key = "llmcache:" + hashlib.sha256(json.dumps([ctx.system_prompt, ctx.messages, ctx.user.role],
                                                      sort_keys=True).encode()).hexdigest()
        fernet = svc.settings.fernet()
        hit = svc.store.get(key) if cache_cfg.get("enabled") else None
        if hit:
            data = json.loads(fernet.decrypt(hit.encode()).decode())
            ctx.llm_text, ctx.cache_hit = data["text"], True
            pt = ct = 0
            model = data["model"]
        else:
            t0 = time.perf_counter()
            try:
                resp = await asyncio.wait_for(svc.llm.complete(ctx.system_prompt, ctx.messages), remaining)
            except asyncio.TimeoutError as exc:
                raise FailClosed("latency budget exceeded by the model") from exc
            ctx.llm_ms = (time.perf_counter() - t0) * 1000
            ctx.llm_text, pt, ct, model = resp.text, resp.prompt_tokens, resp.completion_tokens, resp.model
            if cache_cfg.get("enabled"):
                svc.store.set(key, fernet.encrypt(json.dumps({"text": resp.text, "model": model}).encode()).decode(),
                              ttl=cache_cfg.get("ttl_s", 300))
        cost = pt / 1000 * cfg.get("cost_per_1k_prompt", 0) + ct / 1000 * cfg.get("cost_per_1k_completion", 0)
        ctx.usage = {"prompt_tokens": pt, "completion_tokens": ct, "cost": round(cost, 6), "model": model,
                     "cached": ctx.cache_hit}
        with svc.session_factory() as s:
            s.add(TokenUsage(user_id=ctx.user.user_id, conversation_id=ctx.conversation_id,
                             request_id=ctx.request_id, prompt_tokens=pt, completion_tokens=ct,
                             cost=cost, model=model, cached=ctx.cache_hit))
            s.commit()
