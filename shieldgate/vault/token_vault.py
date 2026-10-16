"""
PURPOSE : Token vault - maps sensitive values to placeholders such as [AADHAAR_1]. Values are
          Fernet-encrypted inside the SessionStore with a per-conversation TTL, so nothing in
          the DB or logs ever holds the cleartext.
INPUTS  : scope (conversation id), type, value; restore modes from policy.yaml `restore`.
OUTPUTS : placeholders; restored/masked text.
HOW TO EXTEND : swap the SessionStore (Redis) for shared deployment; add per-type restore
          modes in policy.yaml.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from core.interfaces import SessionStore

PLACEHOLDER = re.compile(r"\[([A-Z][A-Z_]*)_(\d+)\]")


def mask_value(value: str) -> str:
    """Keep only the last 4 alphanumerics; separators survive for readability."""
    alnum = [i for i, c in enumerate(value) if c.isalnum()]
    keep = set(alnum[-4:])
    return "".join(c if (not c.isalnum() or i in keep) else "X" for i, c in enumerate(value))


class TokenVault:
    def __init__(self, store: SessionStore, fernet: Fernet, hmac_key: str, ttl: int = 3600) -> None:
        self.store, self.fernet, self.key, self.ttl = store, fernet, hmac_key.encode(), ttl

    def _h(self, type_: str, value: str) -> str:
        return hmac.new(self.key, f"{type_}:{value}".encode(), hashlib.sha256).hexdigest()

    def tokenize(self, scope: str, type_: str, value: str) -> str:
        """Return the placeholder for `value` (same value -> same placeholder within a scope)."""
        rev = f"vr:{scope}:{self._h(type_, value)}"
        existing = self.store.get(rev)
        if existing:
            return existing
        n = self.store.incr(f"vc:{scope}:{type_}", ttl=self.ttl)
        ph = f"[{type_}_{n}]"
        self.store.set(f"vp:{scope}:{ph}", self.fernet.encrypt(value.encode()).decode(), ttl=self.ttl)
        self.store.set(rev, ph, ttl=self.ttl)
        return ph

    def lookup(self, scope: str, placeholder: str) -> str | None:
        token = self.store.get(f"vp:{scope}:{placeholder}")
        if not token:
            return None
        try:
            return self.fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            return None

    def restore_ex(self, scope: str, text: str, restore_cfg: dict[str, Any] | None = None,
                   allow_full: frozenset[str] | set[str] = frozenset()) -> tuple[str, int, list[dict[str, str]]]:
        """Replace placeholders with real/masked values for the user who typed them.

        Modes per type (policy.yaml restore.per_type): full | masked | approval. "approval" shows the value masked
        unless the placeholder is in `allow_full` (an unexpired approved reveal). Returns (text, count, pending),
        where pending lists masked placeholders that COULD be revealed with an approval.
        """
        cfg = restore_cfg or {}
        count = 0
        pending: list[dict[str, str]] = []

        def sub(m: re.Match[str]) -> str:
            nonlocal count
            value = self.lookup(scope, m.group(0))
            if value is None:
                return m.group(0)
            count += 1
            mode = cfg.get("per_type", {}).get(m.group(1), cfg.get("default", "masked"))
            if mode == "full" or m.group(0) in allow_full:
                return value
            masked = mask_value(value)
            if mode == "approval":
                pending.append({"placeholder": m.group(0), "type": m.group(1), "masked": masked})
            return masked

        return PLACEHOLDER.sub(sub, text), count, pending

    def restore(self, scope: str, text: str, restore_cfg: dict[str, Any] | None = None) -> tuple[str, int]:
        out, n, _ = self.restore_ex(scope, text, restore_cfg)
        return out, n
