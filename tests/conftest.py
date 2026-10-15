"""
PURPOSE : pytest fixtures - an isolated app (in-memory SQLite, memory session store, hash
          embedder, mock LLM) and helpers to log in as the seeded demo users.
INPUTS  : none. OUTPUTS : `client`, `login()` fixtures.
HOW TO EXTEND : add fixtures; keep tests free of network and model downloads.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
TMP = Path(tempfile.mkdtemp(prefix="shieldgate_test_"))  # file DB: in-memory SQLite shares one connection across threads
os.environ.update({"DATABASE_URL": f"sqlite:///{(TMP / 'test.db').as_posix()}", "SESSION_STORE": "memory", "VECTOR_STORE": "memory",
                   "EMBEDDER": "hash", "LLM_PROVIDER": "mock", "ENV": "test", "SHOW_DEMO_HINT": "true",
                   "LOG_LEVEL": "WARNING"})

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="session")
def client():
    from shieldgate.main import create_app
    from shieldgate.settings import Settings
    with TestClient(create_app(Settings.load())) as c:
        cfg = c.app.state.config  # relax the per-minute rate limit so the suite can chat freely
        app_cfg = cfg.get("app")
        app_cfg["limits"]["requests_per_minute"] = 10_000
        cfg.update("app", app_cfg, "tests", "relax rate limit")
        yield c


@pytest.fixture(scope="session")
def tokens(client):
    out = {}
    for u in ("intern1", "emp1", "hr1", "mgr1", "admin1"):
        r = client.post("/v1/auth/login", json={"username": u, "password": "Demo@123"})
        assert r.status_code == 200, r.text
        out[u] = {"Authorization": "Bearer " + r.json()["access_token"]}
    return out


@pytest.fixture()
def chat(client, tokens):
    def _chat(user: str, message: str, **kw):
        r = client.post("/v1/chat", json={"message": message, **kw}, headers=tokens[user])
        assert r.status_code == 200, r.text
        return r.json()
    return _chat


