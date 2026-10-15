"""
PURPOSE : Policy engine - maps findings to actions using config/policy.yaml (versioned,
          role overrides first, then base rules, then default). Fails closed on unknown actions.
INPUTS  : findings, role name, `approved` flag (a valid manager approval exists).
OUTPUTS : Decision (per-finding actions, strongest blocking action, reasons).
HOW TO EXTEND : edit policy.yaml / the Policies page; register new actions with @register_action.
"""
from __future__ import annotations

from typing import Any

from core.errors import FailClosed
from core.registry import REGISTRIES
from core.types import SEVERITY_RANK, Decision, Finding
from shieldgate.policy.precedence import strongest


class PolicyEngine:
    def __init__(self, config: Any) -> None:
        self.config = config

    def decide(self, findings: list[Finding], role: str, approved: bool = False) -> Decision:
        cfg = self.config.get("policy")
        rules = list(cfg["role_overrides"].get(role, [])) + list(cfg["rules"])
        decision = Decision()
        for f in findings:
            action, rule_id = cfg["default_action"], "default"
            for r in rules:
                if (f.type in r["types"] or "*" in r["types"]) and f.rank >= SEVERITY_RANK.get(r.get("min_severity", "info"), 0):
                    action, rule_id = r["action"], r["id"]
                    if r.get("message"):
                        f.meta["policy_message"] = r["message"]
                    break
            if action == "require_approval" and approved:
                action = "warn"
            if action not in REGISTRIES["action"]:
                raise FailClosed(f"policy references unknown action '{action}'")
            decision.items.append((f, action, rule_id))
        blocking = [a for _, a, _ in decision.items if REGISTRIES["action"].get(a).blocking]
        decision.blocking_action = strongest(blocking, cfg["precedence"])
        decision.reasons = sorted({f"{f.type}->{a}" for f, a, _ in decision.items})
        return decision
