"""
PURPOSE : Notification feed for the bell icon. Built from incidents (the grouped record of flagged/suspicious
          activity), filtered by the viewer's role:
          - mode "flagged"  (managers): every open incident caused by users LOWER in the hierarchy (role level below the viewer's);
          - mode "critical" (admins)  : high-alert activity from anyone - severity critical, or repeated attempts.
          Roles opt in with `notifications: flagged|critical` in config/roles.yaml. "Unread" = changed since the user
          last pressed "mark all read" (stored per user). No message content is involved - categories, counts, users.
INPUTS  : session factory, ConfigService, viewer role/user id.
OUTPUTS : feed(), mark_read().
HOW TO EXTEND : add a mode in visible() or a new category title in TITLES.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import select

from shieldgate.db.models import Incident, NotificationRead, User, utcnow

TITLES = {
    "prompt_injection": "Prompt-injection attempt", "secret_exposure": "Credential or key sent to the AI",
    "honeytoken_touched": "Canary token touched", "data_extraction": "Attempt to extract other users' data",
    "response_leak": "System prompt leak blocked", "restricted_content_leak": "Restricted content in an answer",
    "confidential_content": "Confidential content", "unauthorized_access": "Access to a restricted document attempted",
    "poisoned_document": "Poisoned document chunk dropped", "repeated_attempts": "Repeated risky requests",
    "blocked_request": "Blocked request",
}
WINDOW_DAYS = 14


def _mode(config: Any, role: str) -> tuple[str, int, dict[str, int]]:
    roles = config.get("roles")["roles"]
    spec = roles.get(role, {})
    return spec.get("notifications", "") or "", int(spec.get("level", 0)), {r: int(s.get("level", 0)) for r, s in roles.items()}


def feed(session_factory: Any, config: Any, user_id: int, role: str, limit: int = 40) -> dict[str, Any]:
    mode, my_level, levels = _mode(config, role)
    if not mode:
        return {"enabled": False, "mode": "", "unread": 0, "items": []}
    since = utcnow() - timedelta(days=WINDOW_DAYS)
    with session_factory() as s:
        incs = s.execute(select(Incident).where(Incident.status == "open", Incident.last_seen >= since)
                         .order_by(Incident.last_seen.desc()).limit(300)).scalars().all()
        roles_of = {u.id: u.role for u in s.execute(select(User).where(User.id.in_({i.user_id for i in incs} or {0}))).scalars()}
        read = s.get(NotificationRead, user_id)
    last_read = read.last_read_at if read else None
    items: list[dict[str, Any]] = []
    for i in incs:
        lvl = levels.get(roles_of.get(i.user_id, ""), 0)
        if i.user_id == user_id:
            continue  # nobody gets alerted about themselves
        if mode == "flagged" and lvl >= my_level:
            continue
        if mode == "critical" and not (i.severity == "critical" or i.repeated):
            continue
        items.append({"id": i.id, "user": i.username, "role": roles_of.get(i.user_id, ""), "category": i.category,
                      "title": TITLES.get(i.category, i.category.replace("_", " ").capitalize()), "severity": i.severity,
                      "count": i.count, "repeated": bool(i.repeated), "first_seen": i.first_seen.isoformat(),
                      "last_seen": i.last_seen.isoformat(), "unread": last_read is None or i.last_seen > last_read})
    items = sorted(items, key=lambda x: x["last_seen"], reverse=True)
    items = sorted(items, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4))
    items = sorted(items, key=lambda x: not x["unread"])[:limit]
    return {"enabled": True, "mode": mode, "unread": sum(1 for x in items if x["unread"]), "items": items}


def mark_read(session_factory: Any, user_id: int) -> None:
    with session_factory() as s:
        row = s.get(NotificationRead, user_id)
        if row is None:
            s.add(NotificationRead(user_id=user_id, last_read_at=utcnow()))
        else:
            row.last_read_at = utcnow()
        s.commit()
