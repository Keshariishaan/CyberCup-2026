"""
PURPOSE : Environment-driven settings (.env supported) for secrets and deployment.
INPUTS  : process environment and an optional .env file in the project root.
OUTPUTS : Settings object via get_settings(); crypto helpers (Fernet, HMAC keys).
HOW TO EXTEND : add a field + env name in Settings.load(). Business rules belong in
          config/*.yaml, not here - this module is for secrets/deployment only.
"""
from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parent.parent
_DEV_SECRET = "dev-only-change-me"


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            v = v.strip()
            if v[:1] not in ('"', "'") and " #" in v:      # inline comment on an unquoted value
                v = v.split(" #", 1)[0].strip()
            os.environ.setdefault(k.strip(), v.strip('"').strip("'"))


def _bool(v: str) -> bool:
    return v.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    env: str
    database_url: str
    session_store: str
    redis_url: str
    jwt_secret: str
    vault_key: str
    audit_key: str
    auth_provider: str
    show_demo_hint: bool
    config_dir: Path
    data_dir: Path
    plugin_dir: Path
    jwt_ttl_minutes: int
    vector_store: str
    embedder: str
    llm_provider: str
    llm_model: str
    llm_base_url: str
    llm_api_key: str
    api_url: str

    @classmethod
    def load(cls) -> "Settings":
        _load_dotenv(ROOT / ".env")
        e = os.environ.get
        env = e("ENV", "dev")
        s = cls(
            env=env,
            database_url=e("DATABASE_URL", f"sqlite:///{(ROOT / 'shieldgate.db').as_posix()}"),
            session_store=e("SESSION_STORE", "memory"),
            redis_url=e("REDIS_URL", "redis://localhost:6379/0"),
            jwt_secret=e("JWT_SECRET", _DEV_SECRET),
            vault_key=e("VAULT_KEY", _DEV_SECRET),
            audit_key=e("AUDIT_HMAC_KEY", _DEV_SECRET),
            auth_provider=e("AUTH_PROVIDER", "local"),
            show_demo_hint=_bool(e("SHOW_DEMO_HINT", "true")),
            config_dir=Path(e("CONFIG_DIR", str(ROOT / "config"))),
            data_dir=Path(e("DATA_DIR", str(ROOT / "data"))),
            plugin_dir=Path(e("PLUGIN_DIR", str(ROOT / "plugins"))),
            jwt_ttl_minutes=int(e("JWT_TTL_MINUTES", "60")),
            vector_store=e("VECTOR_STORE", "auto"),
            embedder=e("EMBEDDER", "auto"),
            llm_provider=e("LLM_PROVIDER", ""),  # empty -> config/app.yaml llm.provider
            llm_model=e("LLM_MODEL", ""),
            llm_base_url=e("LLM_BASE_URL", ""),
            llm_api_key=e("LLM_API_KEY", ""),
            api_url=e("API_URL", "http://localhost:8000"),
        )
        if env == "production" and _DEV_SECRET in (s.jwt_secret, s.vault_key, s.audit_key):
            raise RuntimeError("Set JWT_SECRET, VAULT_KEY and AUDIT_HMAC_KEY in production")
        return s

    def fernet(self) -> Fernet:
        """Fernet cipher derived from VAULT_KEY (any string)."""
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(self.vault_key.encode()).digest()))


@lru_cache
def get_settings() -> Settings:
    return Settings.load()
