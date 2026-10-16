"""
PURPOSE : Evaluation harness - runs tests/test_prompts.csv through the real pipeline (mock LLM,
          isolated temp DB) and reports accuracy, per-class errors and gateway latency.
INPUTS  : tests/test_prompts.csv (role,prompt,expected_status). Optional: --csv PATH.
OUTPUTS : console report; exit code 1 if any row mismatches.
HOW TO EXTEND : add rows to the CSV; roles map to demo users (intern->intern1, employee->emp1 ...).
USAGE   : python tests/evaluate.py
"""
from __future__ import annotations

import argparse
import csv
import os
import statistics
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
TMP = Path(tempfile.mkdtemp(prefix="shieldgate_eval_"))
import shutil
shutil.copytree(ROOT / "data", TMP / "data", ignore=shutil.ignore_patterns("chroma"))  # tests write documents: use a copy
os.environ["DATA_DIR"] = str(TMP / "data")
os.environ.update({"DATABASE_URL": f"sqlite:///{(TMP / 'eval.db').as_posix()}", "VECTOR_STORE": "memory",
                   "EMBEDDER": os.environ.get("EMBEDDER", "hash"), "LLM_PROVIDER": "mock", "SESSION_STORE": "memory",
                   "LOG_LEVEL": "ERROR"})

USERS = {"intern": "intern1", "employee": "emp1", "hr_admin": "hr1", "manager": "mgr1", "admin": "admin1", "finance": "fin1"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(ROOT / "tests" / "test_prompts.csv"))
    args = ap.parse_args()
    from fastapi.testclient import TestClient
    from shieldgate.main import create_app
    from shieldgate.settings import Settings

    rows = list(csv.DictReader(open(args.csv, encoding="utf-8")))
    bad, overheads = [], []
    with TestClient(create_app(Settings.load())) as c:
        cfg = c.app.state.config
        app_cfg = cfg.get("app")
        app_cfg["limits"]["requests_per_minute"] = 100000
        cfg.update("app", app_cfg, "eval", "no rate limit")
        tokens = {}
        for role, user in USERS.items():
            r = c.post("/v1/auth/login", json={"username": user, "password": "Demo@123"})
            tokens[role] = {"Authorization": "Bearer " + r.json()["access_token"]}
        for row in rows:
            res = c.post("/v1/chat", json={"message": row["prompt"]}, headers=tokens[row["role"]]).json()
            overheads.append(res["timings"].get("gateway_overhead", 0))
            if res["status"] != row["expected_status"]:
                bad.append((row, res["status"]))
    ok = len(rows) - len(bad)
    print(f"{ok}/{len(rows)} correct ({ok / len(rows):.0%})")
    print(f"gateway overhead ms: median {statistics.median(overheads):.1f}, max {max(overheads):.1f}")
    for row, got in bad:
        print(f"  MISMATCH [{row['role']}] expected {row['expected_status']}, got {got}: {row['prompt'][:70]}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
