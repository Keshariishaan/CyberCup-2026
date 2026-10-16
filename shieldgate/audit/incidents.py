"""
PURPOSE : Incident records. Groups related alerts, blocks and repeated attempts by user + category into one open
          incident (with a counter and severity) that a manager/admin can resolve. Fed by every audit event, so
          the audit trail stays the single source of truth. Stores no content - categories, counts and ids only.
INPUTS  : audit events (dicts as written by DBAuditSink).
OUTPUTS : upserted Incident rows; list_incidents(), resolve(), summary helpers.
HOW TO EXTEND : add finding types to CATEGORY_BY_TYPE or event names in classify(); change REPEAT_THRESHOLD.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select

from shieldgate.db.models import Incident, utcnow

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ESCALATE = {"low": "medium", "medium": "high", "high": "critical", "critical": "critical"}
REPEAT_THRESHOLD = 3  # the third occurrence of the same category by the same user marks the incident "repeated"
CATEGORY_BY_TYPE = {
    "PROMPT_INJECTION": "prompt_injection", "SECRET": "secret_exposure", "HONEYTOKEN": "honeytoken_touched",
    "DATA_EXTRACTION": "data_extraction", "SYSTEM_PROMPT_LEAK": "response_leak",
    "RESTRICTED_CONTENT": "restricted_content_leak", "CONFIDENTIAL": "confidential_content",
}


def classify(event: dict[str, Any]) -> list[tuple[str, str]]:
    """Return [(category, severity)] for audit events that count towards an incident."""
    name, details = event.get("event", ""), event.get("details", {}) or {}
    sev, status = event.get("severity", "info"), event.get("status", "")
    out: list[tuple[str, str]] = []
    if name == "alert":
        out = [(CATEGORY_BY_TYPE.get(t, t.lower()), sev if SEV_RANK.get(sev, 0) >= 3 else "high") for t in details.get("types", [])]
    elif name == "rag_denied":
        out = [("unauthorized_access", "medium")]
    elif name == "chunk_dropped":
        out = [("poisoned_document", sev if SEV_RANK.get(sev, 0) >= 3 else "high")]
    elif name == "risk_block":
        out = [("repeated_attempts", "high")]
    elif name == "chat" and status in ("blocked", "denied") and SEV_RANK.get(sev, 0) >= 3:
        out = [(CATEGORY_BY_TYPE[t], sev) for t in (details.get("finding_types") or {}) if t in CATEGORY_BY_TYPE]
        out = out or [("blocked_request", sev)]
    return out


def track(session_factory: Any, event: dict[str, Any]) -> None:
    """Upsert open incidents for this event (same user + category -> same incident)."""
    uid = event.get("user_id", 0)
    if not uid:
        return
    rid = event.get("request_id", "")
    for category, sev in classify(event):
        with session_factory() as s:
            inc = s.execute(select(Incident).where(Incident.user_id == uid, Incident.category == category,
                                                   Incident.status == "open")).scalars().first()
            now = utcnow()
            if inc is None:
                s.add(Incident(user_id=uid, username=event.get("username", ""), category=category, severity=sev,
                               last_request_id=rid, first_seen=now, last_seen=now))
            else:
                if not rid or inc.last_request_id != rid:  # one request = one occurrence (chat + alert rows)
                    inc.count += 1
                inc.last_seen, inc.last_request_id = now, rid
                if SEV_RANK[sev] > SEV_RANK.get(inc.severity, 0):
                    inc.severity = sev
                if inc.count >= REPEAT_THRESHOLD and not inc.repeated:
                    inc.repeated, inc.severity = True, ESCALATE.get(inc.severity, inc.severity)
            s.commit()


def _view(i: Incident) -> dict[str, Any]:
    return {"id": i.id, "user": i.username, "category": i.category, "severity": i.severity, "status": i.status,
            "count": i.count, "repeated": bool(i.repeated), "first_seen": i.first_seen.isoformat(),
            "last_seen": i.last_seen.isoformat(), "resolved_by": i.resolved_by, "note": i.note,
            "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None}


def list_incidents(session_factory: Any, status: str = "all", limit: int = 200) -> list[dict[str, Any]]:
    q = select(Incident).order_by(Incident.last_seen.desc()).limit(limit)
    if status in ("open", "resolved"):
        q = q.where(Incident.status == status)
    with session_factory() as s:
        rows = s.execute(q).scalars().all()
    rows = sorted(rows, key=lambda i: (i.status != "open", -SEV_RANK.get(i.severity, 0)))  # open + severe first
    return [_view(i) for i in rows]


def set_status(session_factory: Any, incident_id: int, resolved: bool, actor: str, note: str = "") -> bool:
    with session_factory() as s:
        i = s.get(Incident, incident_id)
        if i is None:
            return False
        i.status = "resolved" if resolved else "open"
        i.resolved_by, i.resolved_at, i.note = (actor, utcnow(), note[:255]) if resolved else ("", None, "")
        s.commit()
    return True
