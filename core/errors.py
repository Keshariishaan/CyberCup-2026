"""
PURPOSE : Exception hierarchy for ShieldGate. Messages here must NEVER contain
          prompts, responses or sensitive values (privacy by design).
INPUTS  : short, static, human-safe messages.
OUTPUTS : exceptions mapped to HTTP errors in shieldgate/main.py.
HOW TO EXTEND : subclass ShieldGateError and add an exception handler in main.py.
"""
from __future__ import annotations


class ShieldGateError(Exception):
    """Base class for all gateway errors."""

    status_code = 500
    public_message = "Internal gateway error"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.public_message)
        self.public = message or self.public_message


class ConfigError(ShieldGateError):
    """Configuration failed schema validation or could not be loaded."""

    status_code = 422
    public_message = "Invalid configuration"


class AuthError(ShieldGateError):
    """Authentication failed or token is invalid/revoked."""

    status_code = 401
    public_message = "Not authenticated"


class PermissionDenied(ShieldGateError):
    """The caller lacks the role or data-level privilege."""

    status_code = 403
    public_message = "You don't have permission"


class RateLimited(ShieldGateError):
    """Too many requests or login attempts."""

    status_code = 429
    public_message = "Too many requests"


class FailClosed(ShieldGateError):
    """A security component failed; the request is held, never passed through."""

    status_code = 503
    public_message = "Request held: a security check could not complete"


class NotFound(ShieldGateError):
    """A referenced object does not exist."""

    status_code = 404
    public_message = "Not found"
