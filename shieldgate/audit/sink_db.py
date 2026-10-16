"""
PURPOSE : Database sink for the audit trail - writes hash-chained, content-free rows and can
          verify a chain. Details may hold only counts, types, ids and HMACs.
INPUTS  : session factory, audit key, instance id.
OUTPUTS : write(), verify_chain(), recent(), summary().
HOW TO EXTEND : add another sink (SIEM/webhook) by subclassing AuditSink and registering it in AuditQueue.
"""
from __future__ import annotations

import threading
from datetime import timedelta
from typing import Any

from sqlalchemy import select

from shieldgate.audit.hashing import entry_hash
from shieldgate.audit.incidents import track
from shieldgate.db.models import AuditLog, utcnow

FORBIDDEN_KEYS = {"text", "prompt", "response", "value", "content", "message"}


class DBAuditSink:
    def __init__(self, session_factory: Any, key: str, instance: str) -> None:
        self.sf, self.key, self.instance = session_factory, key, instance
        self._lock = threading.Lock()
        with self.sf() as s:
            last = s.execute(select(AuditLog.entry_hash).where(AuditLog.instance == instance)
                             .order_by(AuditLog.id.desc())).scalars().first()
        self._prev = last or ""

    def write(self, event: dict[str, Any]) -> None:
        """Persist one event. Keys that could carry content are dropped defensively."""
        details = {k: v for k, v in event.get("details", {}).items() if k not in FORBIDDEN_KEYS}
        fields = {"instance": self.instance, "user_id": event.get("user_id", 0), "event": event["event"],
                  "status": event.get("status", ""), "severity": event.get("severity", "info"),
                  "request_id": event.get("request_id", ""), "details": details}
        with self._lock:  # the chain must be extended by one writer at a time
            h = entry_hash(self.key, self._prev, fields)
            with self.sf() as s:
                s.add(AuditLog(instance=self.instance, user_id=fields["user_id"], username=event.get("username", ""),
                               role=event.get("role", ""), request_id=fields["request_id"], event=fields["event"],
                               status=fields["status"], severity=fields["severity"], details=details,
                               prev_hash=self._prev, entry_hash=h))
                s.commit()
            self._prev = h
        try:  # incidents are derived data: never let them break audit writing
            track(self.sf, {**event, "details": details})
        except Exception:  # noqa: BLE001
            pass

    def verify_chain(self, instance: str | None = None) -> tuple[bool, int]:
        """Recompute every hash for an instance chain; returns (ok, rows_checked)."""
        prev, n = "", 0
        with self.sf() as s:
            rows = s.execute(select(AuditLog).where(AuditLog.instance == (instance or self.instance))
                             .order_by(AuditLog.id)).scalars().all()
        for r in rows:
            fields = {"instance": r.instance, "user_id": r.user_id, "event": r.event, "status": r.status,
                      "severity": r.severity, "request_id": r.request_id, "details": r.details}
            if r.prev_hash != prev or r.entry_hash != entry_hash(self.key, prev, fields):
                return False, n
            prev, n = r.entry_hash, n + 1
        return True, n

    def recent(self, user_id: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
        q = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
        if user_id is not None:
            q = q.where(AuditLog.user_id == user_id)
        with self.sf() as s:
            rows = s.execute(q).scalars().all()
        return [{"id": r.id, "ts": r.ts.isoformat(), "user": r.username, "role": r.role, "event": r.event,
                 "status": r.status, "severity": r.severity, "details": r.details,
                 "request_id": r.request_id} for r in rows]

    BLOCKED_STATUSES = ("blocked", "denied", "held")

    def chat_requests(self, kind: str = "blocked", days: int = 30, limit: int = 200) -> list[dict[str, Any]]:
        """Content-free list of chat requests by outcome: 'blocked' (blocked/denied/held), 'allowed', or 'all'."""
        since = utcnow() - timedelta(days=days)
        q = select(AuditLog).where(AuditLog.event == "chat", AuditLog.ts >= since).order_by(AuditLog.id.desc()).limit(limit)
        if kind == "blocked":
            q = q.where(AuditLog.status.in_(self.BLOCKED_STATUSES))
        elif kind == "allowed":
            q = q.where(AuditLog.status == "allowed")
        with self.sf() as s:
            rows = s.execute(q).scalars().all()
        return [{"id": r.id, "time": r.ts.isoformat(), "user": r.username, "role": r.role, "status": r.status,
                 "severity": r.severity, "request_id": r.request_id,
                 "finding_types": r.details.get("finding_types", {}), "actions": r.details.get("actions", {}),
                 "policies": r.details.get("policies", []), "conversation_id": r.details.get("conversation_id", "")}
                for r in rows]

    def priority_event(self, user_id: int) -> dict[str, Any] | None:
        """The user's most severe recent chat event (critical beats high; newest wins ties), or None."""
        with self.sf() as s:
            rows = s.execute(select(AuditLog).where(AuditLog.user_id == user_id, AuditLog.event == "chat",
                                                    AuditLog.severity.in_(("high", "critical")))
                             .order_by(AuditLog.id.desc()).limit(200)).scalars().all()
        if not rows:
            return None
        best = max(rows, key=lambda r: (r.severity == "critical", r.id))
        return {"id": best.id, "time": best.ts.isoformat(), "status": best.status, "severity": best.severity,
                "request_id": best.request_id, "details": best.details}

    def summary(self, days: int = 30) -> dict[str, Any]:
        """Aggregates for dashboards/reports: counts by event/status/severity and finding types."""
        since = utcnow() - timedelta(days=days)
        with self.sf() as s:
            rows = s.execute(select(AuditLog).where(AuditLog.ts >= since)).scalars().all()
        by_event: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        by_type: dict[str, int] = {}
        daily: dict[str, int] = {}
        blocked_daily: dict[str, int] = {}
        outcomes: dict[str, dict[str, int]] = {}
        for r in rows:
            by_event[r.event] = by_event.get(r.event, 0) + 1
            if r.status:
                by_status[r.status] = by_status.get(r.status, 0) + 1
            by_sev[r.severity] = by_sev.get(r.severity, 0) + 1
            for t, n in (r.details.get("finding_types") or {}).items():
                by_type[t] = by_type.get(t, 0) + int(n)
            day = r.ts.date().isoformat()
            daily[day] = daily.get(day, 0) + (1 if r.event == "chat" else 0)
            if r.event == "chat" and r.status in ("blocked", "denied", "held"):
                blocked_daily[day] = blocked_daily.get(day, 0) + 1
            if r.event == "chat":
                kind = "allowed" if r.status == "allowed" else "blocked" if r.status in ("blocked", "denied", "held") else "other"
                outcomes.setdefault(day, {"allowed": 0, "blocked": 0, "other": 0})[kind] += 1
        return {"days": days, "total_events": len(rows), "by_event": by_event, "by_status": by_status,
                "by_severity": by_sev, "by_finding_type": by_type, "chat_per_day": daily,
                "blocked_per_day": blocked_daily, "daily_outcomes": outcomes}
