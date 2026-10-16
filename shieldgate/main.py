"""
PURPOSE : FastAPI application factory. Builds all services (DB, session store, config, vault,
          RAG, LLM, audit, approvals), discovers plugins, mounts the /v1 routers and maps
          gateway errors to HTTP responses.
INPUTS  : environment / .env via settings.py (or a Settings object passed to create_app()).
OUTPUTS : `app` for uvicorn:  uvicorn shieldgate.main:app
HOW TO EXTEND : add a router module under api/v1 and include it in ROUTERS.
"""
from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from core.config_service import ConfigService
from core.errors import ShieldGateError
from core.logging import get_logger
from core.registry import discover
from core.types import Services
from shieldgate.approvals.service import ApprovalService
from shieldgate.audit.queue import AuditQueue
from shieldgate.audit.sink_db import DBAuditSink
from shieldgate.db.session import init_db, make_engine, make_session_factory
from shieldgate.llm.base import make_llm
from shieldgate.llm.memory import ConversationMemory
from shieldgate.pipeline.controller import PipelineController
from shieldgate.policy.engine import PolicyEngine
from shieldgate.rag.backend import RAGBackend
from shieldgate.rag.embedders.base import make_embedder, set_shared_embedder
from shieldgate.rag.stores.factory import make_store
from shieldgate.security.auth_providers import make_auth_provider
from shieldgate.security.session_store import make_session_store
from shieldgate.seed import seed_all
from shieldgate.settings import Settings, get_settings
from shieldgate.vault.token_vault import TokenVault

log = get_logger("main")


def build_state(app: FastAPI, settings: Settings) -> None:
    """Wire every component onto app.state (also used directly by tests)."""
    engine = make_engine(settings.database_url)
    init_db(engine)
    sf = make_session_factory(engine)
    store = make_session_store(settings.session_store, settings.redis_url)
    config = ConfigService(settings.config_dir, sf)
    discover(settings.plugin_dir)
    embedder = make_embedder(settings.embedder)
    set_shared_embedder(embedder)
    vstore = make_store(settings.vector_store, settings.data_dir)
    limits = config.get("app")["limits"]
    vault = TokenVault(store, settings.fernet(), settings.vault_key, limits.get("vault_ttl_s", 3600))
    rag = RAGBackend(vstore, embedder, sf, config, settings.data_dir)
    import os
    seed_all(settings, config, sf, vstore, embedder, os.environ.get("SEED_DEMO_USERS", "true").lower() != "false")
    # warm-up: load the embedding model and attack-corpus vectors now, so the first user request
    # does not spend its latency budget on model loading
    try:
        from shieldgate.pipeline.stages.detect import get_detectors
        embedder.embed(["warm up"])
        for d in get_detectors(config).values():
            if hasattr(d, "_corpus_vectors"):
                d._corpus_vectors(embedder)
    except Exception as exc:  # noqa: BLE001
        log.warning("warm-up failed: %s", type(exc).__name__)
    sink = DBAuditSink(sf, settings.audit_key, uuid.uuid4().hex[:8])
    audit = AuditQueue(sink)
    services = Services(config=config, session_factory=sf, store=store, vault=vault, rag=rag,
                        llm=make_llm(settings, config), memory=ConversationMemory(sf, settings.fernet(), config),
                        audit=audit, approvals=ApprovalService(sf, config, settings.audit_key), settings=settings)
    services.policy = PolicyEngine(config)
    app.state.settings, app.state.store, app.state.session_factory = settings, store, sf
    app.state.config, app.state.services, app.state.audit, app.state.sink = config, services, audit, sink
    app.state.controller = PipelineController(services)
    app.state.auth = make_auth_provider(settings.auth_provider, sf, store)
    app.state.engine = engine


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # noqa: ANN202
        build_state(app, settings)
        await app.state.audit.start()
        app.state.warm = asyncio.create_task(app.state.services.llm.warm_up())  # load the model in the background
        log.info("AIZA:Portal started (llm=%s, store=%s)", settings.llm_provider or "config", settings.session_store)
        yield
        await app.state.audit.stop()

    app = FastAPI(title="AIZA:Portal", version="1.0", lifespan=lifespan)

    @app.exception_handler(ShieldGateError)
    async def _handle(_: Request, exc: ShieldGateError) -> JSONResponse:
        return JSONResponse({"detail": exc.public}, status_code=exc.status_code)

    from shieldgate.api.v1 import access, admin, approvals, auth, chat, health, history, identity, notifications, policy, redteam, reports, reveal
    for module in (health, auth, chat, identity, history, approvals, access, reveal, notifications, admin, policy, redteam, reports):
        app.include_router(module.router, prefix="/v1")
    return app


app = create_app()
