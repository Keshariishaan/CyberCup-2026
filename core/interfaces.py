"""
PURPOSE : Abstract base classes for every replaceable part of AIZA:Portal.
INPUTS  : none (interfaces only).
OUTPUTS : Detector, Action, LLMProvider, VectorStore, Embedder, ReportGenerator,
          Skill, SessionStore, AuthProvider, PipelineStage.
HOW TO EXTEND : subclass one interface and decorate it with the matching
          @register_* decorator from core.registry (in plugins/ or the package).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from core.types import CurrentUser, Finding, PipelineContext


class Detector(ABC):
    """Finds sensitive or malicious content in text. Must never log the text."""

    name: str = "detector"

    def __init__(self, settings: dict[str, Any] | None = None, config: Any = None) -> None:
        self.settings = settings or {}
        self.config = config

    @abstractmethod
    async def detect(self, text: str, ctx: "PipelineContext | None" = None) -> list["Finding"]:
        """Return findings (spans + metadata) for `text`."""


class Action(ABC):
    """A policy action. Transform actions implement replacement(); blocking ones apply()."""

    name: str = "action"
    blocking: bool = False

    def replacement(self, ctx: "PipelineContext", finding: "Finding", value: str) -> str | None:
        """For transform actions: text that replaces the span (None = leave unchanged)."""
        return None

    async def apply(self, ctx: "PipelineContext", findings: list["Finding"]) -> None:
        """Side effects / halting for the findings mapped to this action."""
        return None


@dataclass
class LLMResponse:
    """Normalized provider response."""

    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    model: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


class LLMProvider(ABC):
    """Any chat-completion backend."""

    name: str = "llm"

    def __init__(self, **options: Any) -> None:
        self.options = options

    async def warm_up(self) -> None:
        """Optional: load the model before the first user request (default: nothing to do)."""

    @abstractmethod
    async def complete(self, system: str, messages: list[dict[str, str]],
                       tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        """Return the model completion for the (already sanitized) conversation."""


class Embedder(ABC):
    """Text -> vector."""

    name: str = "embedder"

    @abstractmethod
    def embed(self, texts: list[str]) -> list[list[float]]:
        """Return one unit-length vector per text."""


class VectorStore(ABC):
    """Vector storage with metadata filtering on doc_id (access control hook)."""

    name: str = "store"

    @abstractmethod
    def add(self, ids: list[str], vectors: list[list[float]], texts: list[str],
            metas: list[dict[str, Any]]) -> None: ...

    @abstractmethod
    def query(self, vector: list[float], k: int, doc_ids: list[str] | None) -> list[dict[str, Any]]:
        """Top-k hits {id,text,score,meta}, restricted to doc_ids when given ([] -> none)."""

    @abstractmethod
    def delete_doc(self, doc_id: str) -> None: ...

    @abstractmethod
    def reset(self) -> None: ...


class ReportGenerator(ABC):
    """Builds a compliance report from audit aggregates."""

    name: str = "report"
    content_type: str = "text/html"
    extension: str = "html"

    @abstractmethod
    def generate(self, summary: dict[str, Any], mapping: dict[str, Any]) -> bytes: ...


class Skill(ABC):
    """A modular capability the gateway can bind to roles/queries."""

    name: str = "skill"
    description: str = ""
    command: str = ""  # short slash command typed in chat, e.g. /policy
    example: str = ""  # one example request
    usage: str = ""  # when it is useful (one line)
    default_query: str = ""  # used when the command is typed without text
    triggers: list[str] = []  # lowercase substrings that activate the skill
    parameters: dict[str, Any] = {"type": "object", "properties": {}}

    @abstractmethod
    async def run(self, query: str, user: "CurrentUser", ctx: "PipelineContext") -> str:
        """Execute with the already-sanitized query. Must enforce its own data access."""

    def tool_definition(self) -> dict[str, Any]:
        """Tool schema exposed via the gateway (never executed by the model directly)."""
        return {"name": self.name, "description": self.description, "input_schema": self.parameters,
                "command": self.command, "example": self.example, "usage": self.usage,
                "default_query": self.default_query}


class SessionStore(ABC):
    """Key/value store with TTL and atomic counters (memory or Redis)."""

    @abstractmethod
    def get(self, key: str) -> str | None: ...

    @abstractmethod
    def set(self, key: str, value: str, ttl: int | None = None) -> None: ...

    @abstractmethod
    def delete(self, key: str) -> None: ...

    @abstractmethod
    def incr(self, key: str, ttl: int | None = None) -> int: ...

    @abstractmethod
    def ttl(self, key: str) -> int:
        """Seconds left, -1 if no expiry, -2 if missing."""


class AuthProvider(ABC):
    """Verifies credentials and returns the user's database id."""

    name: str = "auth"

    @abstractmethod
    def authenticate(self, username: str, password: str) -> int | None:
        """Return user id on success, None on failure (callers show a generic error)."""


class PipelineStage(ABC):
    """One step in config/pipeline.yaml."""

    name: str = "stage"
    always_run: bool = False  # run even if the pipeline halted (e.g. audit)

    @abstractmethod
    async def run(self, ctx: "PipelineContext") -> None: ...
