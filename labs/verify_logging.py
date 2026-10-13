"""Run Lab 3 against disposable SQLite and in-memory Storage, never Supabase."""
from __future__ import annotations

import argparse
import ast
import io
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def event_literals(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.IfExp):
        return event_literals(node.body) + event_literals(node.orelse)
    return []


def event_catalogue() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for filename in ("app.py", "casework.py", "custody.py", "reports.py"):
        tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            position = 0 if node.func.id == "append_event" else 1 if node.func.id == "fail_auth" else None
            if position is None or len(node.args) <= position:
                continue
            for name in event_literals(node.args[position]):
                result.setdefault(name, []).append(f"{filename}:{node.lineno}")
    return {name: sorted(set(locations)) for name, locations in sorted(result.items())}


class VerificationResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed: list[str] = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed.append(test.id())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "labs/results/lab3.json")
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_audit_logging")
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=2,
                                    resultclass=VerificationResult).run(suite)
    catalogue = event_catalogue()
    report = {
        "lab": 3,
        "project": "Evidence Vault",
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "database": "temporary SQLite in memory",
        "storage": "MemoryStorage; no network or real evidence",
        "successful": result.wasSuccessful(),
        "tests_run": result.testsRun,
        "passed": result.passed,
        "failed": [test.id() for test, _ in result.failures + result.errors],
        "registered_event_types_count": len(catalogue),
        "registered_event_types": catalogue,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"successful": report["successful"], "tests_run": result.testsRun,
                      "event_types": len(catalogue)}, ensure_ascii=False))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
