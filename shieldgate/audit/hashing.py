"""
PURPOSE : HMAC-SHA256 helpers for the audit trail: correlate values without storing them, and
          chain entries so tampering is detectable.
INPUTS  : audit key (AUDIT_HMAC_KEY), values or entry fields.
OUTPUTS : hmac_value(), entry_hash().
HOW TO EXTEND : rotate keys by adding a key id to the entry details.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def hmac_value(key: str, value: str) -> str:
    """Keyed hash of a value (for correlation); the value itself is never stored."""
    return hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()


def entry_hash(key: str, prev_hash: str, fields: dict[str, Any]) -> str:
    """HMAC over prev_hash + canonical JSON of the entry fields."""
    body = json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(key.encode(), (prev_hash + body).encode(), hashlib.sha256).hexdigest()
