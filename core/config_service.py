"""
PURPOSE : Loads YAML config from config/, validates it with Pydantic schemas, and
          layers versioned, audited, roll-back-able admin edits stored in the DB.
INPUTS  : config dir path; optional SQLAlchemy session factory; config name such as
          "policy", "patterns/india", "attacks/hi".
OUTPUTS : dict configs (get), new versions (update), history (versions), rollback().
HOW TO EXTEND : add a Pydantic model to SCHEMAS for a new config name. Unknown names
          are accepted as free-form mappings (still must be valid YAML/dict).
"""
from __future__ import annotations

import re
import threading
import time
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from core.errors import ConfigError

CACHE_TTL = 3.0  # seconds; keeps multi-instance deployments eventually consistent


class _Loose(BaseModel):
    model_config = ConfigDict(extra="allow")


class RoleSpec(_Loose):
    label: str
    level: int = 0
    screens: list[str] = Field(default_factory=list)
    skills: list[str] = Field(default_factory=list)
    daily_token_budget: int = 20000
    can_approve: bool = False
    color: str = "#64748b"


class RolesConfig(_Loose):
    screens: list[str]
    roles: dict[str, RoleSpec]

    @field_validator("roles")
    @classmethod
    def _screens_known(cls, v: dict[str, RoleSpec], info: Any) -> dict[str, RoleSpec]:
        known = set(info.data.get("screens", []))
        for name, spec in v.items():
            bad = [s for s in spec.screens if s not in known]
            if bad:
                raise ValueError(f"role {name}: unknown screens {bad}")
        return v


class PolicyRule(_Loose):
    id: str
    types: list[str]
    action: str
    min_severity: str = "info"
    message: str = ""


class PolicyConfig(_Loose):
    version: int = 1
    default_action: str = "warn"
    precedence: list[str]
    rules: list[PolicyRule]
    role_overrides: dict[str, list[PolicyRule]] = Field(default_factory=dict)
    restore: dict[str, Any] = Field(default_factory=dict)


class PipelineConfig(_Loose):
    inbound: list[str]
    outbound: list[str]
    latency_budget_ms: int = 2000
    response_detectors: list[str] = Field(default_factory=list)


class UiConfig(_Loose):
    product_name: str
    logo_path: str = ""
    accent_color: str = "#2563eb"
    tagline: str = ""

    @field_validator("accent_color")
    @classmethod
    def _hex(cls, v: str) -> str:
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", v):
            raise ValueError("accent_color must look like #2563eb")
        return v


class DetectorSpec(_Loose):
    enabled: bool = True
    settings: dict[str, Any] = Field(default_factory=dict)


class DetectorsConfig(_Loose):
    detectors: dict[str, DetectorSpec]
    timeout_ms: int = 800


class PatternSpec(_Loose):
    id: str
    type: str
    regex: str
    severity: str = "medium"
    validator: str = ""
    context: list[str] = Field(default_factory=list)
    message: str = ""

    @field_validator("regex")
    @classmethod
    def _compiles(cls, v: str) -> str:
        re.compile(v)
        return v


class PatternsConfig(_Loose):
    patterns: list[PatternSpec]


class AttacksConfig(_Loose):
    language: str = "en"
    phrases: list[str] = Field(default_factory=list)
    regexes: list[str] = Field(default_factory=list)

    @field_validator("regexes")
    @classmethod
    def _compile(cls, v: list[str]) -> list[str]:
        for r in v:
            re.compile(r)
        return v


class IdentityRule(_Loose):
    type: str
    kind: str
    regex: str
    valid_type: str
    invalid_type: str = ""
    severity: str = "high"
    label: str = ""


class IdentityConfig(_Loose):
    types: list[IdentityRule]


class AppConfig(_Loose):
    llm: dict[str, Any] = Field(default_factory=dict)
    rag: dict[str, Any] = Field(default_factory=dict)
    limits: dict[str, Any] = Field(default_factory=dict)


SCHEMAS: dict[str, type[BaseModel]] = {
    "roles": RolesConfig, "policy": PolicyConfig, "pipeline": PipelineConfig, "ui": UiConfig,
    "detectors": DetectorsConfig, "identity": IdentityConfig, "app": AppConfig,
    "patterns/india": PatternsConfig, "patterns/secrets": PatternsConfig,
    "patterns/confidential": _Loose, "attacks/en": AttacksConfig, "attacks/hi": AttacksConfig,
    "attacks/hinglish": AttacksConfig,
}


class ConfigService:
    """File-backed config with DB-backed versioned overrides."""

    def __init__(self, config_dir: str | Path, session_factory: Any = None) -> None:
        self.dir = Path(config_dir)
        self.sf = session_factory
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = threading.Lock()

    # ---- helpers -------------------------------------------------------
    def _file(self, name: str) -> dict[str, Any]:
        path = self.dir / f"{name}.yaml"
        if not path.is_file():
            raise ConfigError(f"config '{name}' not found")
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"config '{name}' is not valid YAML") from exc
        return self.validate(name, data)

    def validate(self, name: str, data: Any) -> dict[str, Any]:
        """Validate `data` against the schema for `name`; return a plain dict."""
        if not isinstance(data, dict):
            raise ConfigError("config root must be a mapping")
        model = SCHEMAS.get(name)
        if model is None:
            return data
        try:
            return model.model_validate(data).model_dump(mode="python")
        except (ValidationError, ValueError, re.error) as exc:
            first = exc.errors()[0] if isinstance(exc, ValidationError) else {"msg": str(exc), "loc": ()}
            raise ConfigError(f"{name}: {'.'.join(map(str, first['loc']))}: {first['msg']}") from exc

    def names(self) -> list[str]:
        return sorted(str(p.relative_to(self.dir).with_suffix("")).replace("\\", "/")
                      for p in self.dir.rglob("*.yaml"))

    # ---- read ----------------------------------------------------------
    def get(self, name: str) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(name)
            if hit and now - hit[0] < CACHE_TTL:
                return hit[1]
        data = self._active_from_db(name)
        if data is None:
            data = self._file(name)
        with self._lock:
            self._cache[name] = (now, data)
        return data

    def _active_from_db(self, name: str) -> dict[str, Any] | None:
        if not self.sf:
            return None
        from sqlalchemy import select
        from shieldgate.db.models import ConfigVersion
        with self.sf() as s:
            row = s.execute(select(ConfigVersion).where(
                ConfigVersion.name == name, ConfigVersion.active.is_(True))
                .order_by(ConfigVersion.version.desc())).scalars().first()
            return dict(row.data) if row else None

    def invalidate(self) -> None:
        with self._lock:
            self._cache.clear()

    # ---- write ---------------------------------------------------------
    def update(self, name: str, data: dict[str, Any], actor: str, comment: str = "") -> int:
        """Validate then store as a new active version. Returns the version number."""
        if not self.sf:
            raise ConfigError("no database configured for versioned edits")
        if name not in self.names():
            raise ConfigError("unknown config name")
        clean = self.validate(name, data)
        from sqlalchemy import select, update
        from shieldgate.db.models import ConfigVersion
        with self.sf() as s:
            last = s.execute(select(ConfigVersion.version).where(ConfigVersion.name == name)
                             .order_by(ConfigVersion.version.desc())).scalars().first() or 0
            s.execute(update(ConfigVersion).where(ConfigVersion.name == name).values(active=False))
            s.add(ConfigVersion(name=name, version=last + 1, data=clean, created_by=actor,
                                comment=comment[:255], active=True))
            s.commit()
        self.invalidate()
        return last + 1

    def versions(self, name: str) -> list[dict[str, Any]]:
        if not self.sf:
            return []
        from sqlalchemy import select
        from shieldgate.db.models import ConfigVersion
        with self.sf() as s:
            rows = s.execute(select(ConfigVersion).where(ConfigVersion.name == name)
                             .order_by(ConfigVersion.version.desc())).scalars().all()
            return [{"version": r.version, "created_by": r.created_by, "comment": r.comment,
                     "active": r.active, "created_at": r.created_at.isoformat()} for r in rows]

    def rollback(self, name: str, version: int, actor: str) -> int:
        """Re-activate an older version as a NEW version (history is never rewritten)."""
        if not self.sf:
            raise ConfigError("no database configured")
        from sqlalchemy import select
        from shieldgate.db.models import ConfigVersion
        with self.sf() as s:
            row = s.execute(select(ConfigVersion).where(
                ConfigVersion.name == name, ConfigVersion.version == version)).scalars().first()
            if not row:
                raise ConfigError("version not found")
            data = dict(row.data)
        return self.update(name, data, actor, comment=f"rollback to v{version}")

    def reset_to_file(self, name: str, actor: str) -> None:
        """Deactivate all DB versions so the shipped YAML applies again."""
        if not self.sf:
            return
        from sqlalchemy import update
        from shieldgate.db.models import ConfigVersion
        with self.sf() as s:
            s.execute(update(ConfigVersion).where(ConfigVersion.name == name).values(active=False))
            s.commit()
        self.invalidate()
