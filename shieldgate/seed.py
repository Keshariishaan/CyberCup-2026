"""
PURPOSE : Seed demo data: users (password Demo@123), the intern's explicit salary-record
          privilege, the document catalogue and the vector index. Idempotent.
INPUTS  : Services-like objects (session factory, config, store, embedder, settings).
OUTPUTS : rows inserted; index built.
HOW TO EXTEND : add users to DEMO_USERS. Never ship demo passwords to production
          (set SEED_DEMO_USERS=false).
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select

from shieldgate.db.models import User, UserPrivilege
from shieldgate.rag.ingest import index_all, seed_documents
from shieldgate.security.auth_providers import hash_password

DEMO_PASSWORD = "Demo@123"
DEMO_USERS = [
    ("intern1", "intern", "Karan Verma"),
    ("emp1", "employee", "Riya Sharma"),
    ("hr1", "hr_admin", "Sunita Rao"),
    ("mgr1", "manager", "Arjun Mehta"),
    ("admin1", "admin", "Neha Kapoor"),
]


def seed_users(session_factory: Any) -> int:
    added = 0
    pw = hash_password(DEMO_PASSWORD)
    with session_factory() as s:
        for username, role, name in DEMO_USERS:
            if s.execute(select(User).where(User.username == username)).scalars().first():
                continue
            s.add(User(username=username, role=role, full_name=name, password_hash=pw))
            added += 1
        s.commit()
        intern = s.execute(select(User).where(User.username == "intern1")).scalars().first()
        if intern and not s.execute(select(UserPrivilege).where(
                UserPrivilege.user_id == intern.id, UserPrivilege.resource == "salary_record_karan")).scalars().first():
            s.add(UserPrivilege(user_id=intern.id, kind="doc", resource="salary_record_karan", granted_by="seed"))
            s.commit()
    return added


def seed_all(settings: Any, config: Any, session_factory: Any, store: Any, embedder: Any, demo_users: bool = True) -> None:
    if demo_users:
        seed_users(session_factory)
    seed_documents(config, session_factory)
    store.reset()
    index_all(config, session_factory, store, embedder, settings.data_dir)
