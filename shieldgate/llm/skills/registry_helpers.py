"""
PURPOSE : Decide which skills a user may use and which match a query, then run them. Skills are
          bound to roles in config/roles.yaml (`skills`) or to individuals via DB privileges
          ("skill:<name>"). Skills receive only the SANITIZED query and enforce their own data access.
INPUTS  : CurrentUser, ConfigService, sanitized text.
OUTPUTS : allowed_skills(), run_matching(), tool_definitions().
HOW TO EXTEND : write a Skill subclass with @register_skill("name") in plugins/ and add the
          name to a role's `skills` list in roles.yaml.
"""
from __future__ import annotations

from typing import Any

from core.interfaces import Skill
from core.registry import REGISTRIES
from core.types import CurrentUser


def allowed_skills(user: CurrentUser, config: Any, privileges: list[str]) -> list[Skill]:
    role_skills = config.get("roles")["roles"].get(user.role, {}).get("skills", [])
    names = set(role_skills) | {p.split(":", 1)[1] for p in privileges if p.startswith("skill:")}
    return [REGISTRIES["skill"].create(n) for n in sorted(names) if n in REGISTRIES["skill"]]


def tool_definitions(user: CurrentUser, config: Any, privileges: list[str]) -> list[dict[str, Any]]:
    return [s.tool_definition() for s in allowed_skills(user, config, privileges)]


async def run_matching(text: str, user: CurrentUser, ctx: Any, config: Any, privileges: list[str]) -> list[dict[str, str]]:
    low = text.lower()
    out: list[dict[str, str]] = []
    for skill in allowed_skills(user, config, privileges):
        if any(t in low for t in skill.triggers):
            out.append({"skill": skill.name, "output": (await skill.run(text, user, ctx))[:1200]})
    return out
