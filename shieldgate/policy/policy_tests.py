"""
PURPOSE : Policy-as-tests runner. Runs the prompts in config/policy_tests.yaml through the CURRENT detectors and a
          PROPOSED policy (without saving anything) and reports which expectations break. Used to refuse a policy
          save/rollback that would break them, and by the "run tests on this draft" button.
INPUTS  : ConfigService, proposed policy dict, list of test cases.
OUTPUTS : list of result dicts {id, ok, expected, actual}; failures() filters the broken ones.
HOW TO EXTEND : add expectation kinds in _check(); add cases to config/policy_tests.yaml.
"""
from __future__ import annotations

import unicodedata
from typing import Any

from shieldgate.detectors.base import run_detectors
from shieldgate.pipeline.stages.detect import get_detectors
from shieldgate.pipeline.stages.normalize import HOMOGLYPHS, _ZW
from shieldgate.policy.engine import PolicyEngine


class OverrideConfig:
    """Config view where selected names come from a proposed (unsaved) value."""

    def __init__(self, base: Any, overrides: dict[str, Any]) -> None:
        self.base, self.overrides = base, overrides

    def get(self, name: str) -> dict[str, Any]:
        return self.overrides[name] if name in self.overrides else self.base.get(name)


def _check(case: dict[str, Any], blocking: str | None, actions: dict[str, str]) -> tuple[bool, dict[str, Any], dict[str, Any]]:
    expected: dict[str, Any] = {}
    actual: dict[str, Any] = {"blocking": blocking, "actions": actions}
    ok = True
    if "expect_blocking" in case:
        expected["blocking"] = case["expect_blocking"]
        ok &= blocking == case["expect_blocking"]
    for t, a in (case.get("expect_actions") or {}).items():
        expected.setdefault("actions", {})[t] = a
        ok &= actions.get(t) == a
    return bool(ok), expected, actual


async def run_tests(config: Any, proposed_policy: dict[str, Any], tests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    view = OverrideConfig(config, {"policy": proposed_policy})
    engine = PolicyEngine(view)
    dets = get_detectors(config)
    timeout = config.get("detectors")["timeout_ms"]
    results: list[dict[str, Any]] = []
    for case in tests:
        text = unicodedata.normalize("NFKC", case["text"]).translate(_ZW).translate(HOMOGLYPHS)
        findings = await run_detectors(dets, text, None, timeout)
        decision = engine.decide(findings, case.get("role", "employee"))
        actions: dict[str, str] = {}
        for f, a, _ in decision.items:
            actions.setdefault(f.type, a)
        ok, expected, actual = _check(case, decision.blocking_action, actions)
        results.append({"id": case["id"], "ok": ok, "expected": expected, "actual": actual})
    return results


def failures(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in results if not r["ok"]]


def summarize(results: list[dict[str, Any]], limit: int = 4) -> str:
    bad = failures(results)
    parts = [f"{r['id']} (expected {r['expected']}, got blocking={r['actual']['blocking']})" for r in bad[:limit]]
    return f"{len(bad)} of {len(results)} policy test(s) fail: " + "; ".join(parts) + ("; ..." if len(bad) > limit else "")
