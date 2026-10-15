"""
PURPOSE : Central logger factory with a scrubbing filter so that long digit runs,
          emails, bearer tokens and key-like strings never reach log output.
INPUTS  : logger name.
OUTPUTS : configured logging.Logger.
HOW TO EXTEND : add a (compiled regex, replacement) tuple to _SCRUBBERS.
"""
from __future__ import annotations

import logging
import os
import re

_SCRUBBERS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d[\d \-]{10,22}\d\b"), "[NUM]"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[EMAIL]"),
    (re.compile(r"(?i)bearer\s+[\w\-.=]+"), "Bearer [TOKEN]"),
    (re.compile(r"\b(AKIA|sk-|ghp_|xox[bp]-)[\w\-]{8,}"), "[KEY]"),
]


class ScrubFilter(logging.Filter):
    """Rewrites every record's message through the scrubbers."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for pat, rep in _SCRUBBERS:
            msg = pat.sub(rep, msg)
        record.msg, record.args = msg, ()
        record.exc_text = None  # tracebacks may embed values; never print them
        record.exc_info = None
        return True


_configured = False


def get_logger(name: str) -> logging.Logger:
    """Return a scrubbed logger. Level comes from LOG_LEVEL (default INFO)."""
    global _configured
    if not _configured:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        handler.addFilter(ScrubFilter())
        root = logging.getLogger("shieldgate")
        root.addHandler(handler)
        root.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())
        root.propagate = False
        _configured = True
    return logging.getLogger(f"shieldgate.{name}")
