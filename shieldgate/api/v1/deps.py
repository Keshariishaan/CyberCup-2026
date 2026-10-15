"""
PURPOSE : Small helpers shared by route modules: audit emission for admin actions.
INPUTS  : Request, CurrentUser, event name + content-free details.
OUTPUTS : emit() puts an audit event on the queue.
HOW TO EXTEND : keep details to ids/types/counts only.
"""
from __future__ import annotations

from typing import Any

from fastapi import Request

from core.types import CurrentUser


def emit(request: Request, user: CurrentUser | None, event: str, severity: str = "info", status: str = "ok",
         **details: Any) -> None:
    request.app.state.audit.emit({
        "user_id": user.user_id if user else 0, "username": user.username if user else "",
        "role": user.role if user else "", "event": event, "severity": severity, "status": status,
        "details": details})
