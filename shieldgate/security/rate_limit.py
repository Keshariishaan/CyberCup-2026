"""
PURPOSE : Fixed-window request rate limiting and daily token-budget checks, using the
          SessionStore (shared across instances) and DB token usage.
INPUTS  : user id, limits from config/app.yaml (limits.requests_per_minute).
OUTPUTS : check_rate(), tokens_used_today(), check_token_budget().
HOW TO EXTEND : change limits in config/app.yaml; for sliding windows swap check_rate.
"""
from __future__ import annotations

from typing import Any

from core.errors import RateLimited


def check_rate(store: Any, user_id: int, per_minute: int) -> None:
    """Raise RateLimited when the user exceeds `per_minute` requests."""
    import time
    window = int(time.time() // 60)
    if store.incr(f"rate:{user_id}:{window}", ttl=70) > per_minute:
        raise RateLimited("Rate limit reached. Please wait a moment.")


def tokens_used_today(session_factory: Any, user_id: int) -> int:
    from sqlalchemy import func, select
    from shieldgate.db.models import TokenUsage, utcnow
    start = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    with session_factory() as s:
        total = s.execute(select(func.coalesce(func.sum(TokenUsage.prompt_tokens + TokenUsage.completion_tokens), 0))
                          .where(TokenUsage.user_id == user_id, TokenUsage.created_at >= start)).scalar()
    return int(total or 0)


def check_token_budget(session_factory: Any, user_id: int, budget: int) -> int:
    """Return tokens used; raise RateLimited when the daily budget is exhausted."""
    used = tokens_used_today(session_factory, user_id)
    if budget and used >= budget:
        raise RateLimited("Daily token budget reached")
    return used
