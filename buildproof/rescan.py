from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from typing import Any

from .server import _analyze, _history, _rescan_status_path


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _write_status(status: dict[str, Any]) -> None:
    path = _rescan_status_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(status, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def rescan_all() -> dict[str, Any]:
    projects = [item for item in _history() if str(item.get("root", "")).startswith("https://github.com/")]
    status: dict[str, Any] = {
        "status": "running", "started_at": _now(), "completed_at": None,
        "total": len(projects), "completed": 0, "failed": 0, "current": None, "results": [],
    }
    _write_status(status)
    for project in projects:
        source = str(project["root"])
        status["current"] = source
        _write_status(status)
        try:
            report = _analyze(source)
            status["results"].append({
                "id": report["id"], "project": report["project"], "status": "completed",
                "generated_at": report["generated_at"],
                "attack_surfaces": report.get("attack_manifest", {}).get("summary", {}).get("attack_surfaces", 0),
            })
            status["completed"] += 1
        except Exception as exc:  # Keep the remaining monitored projects moving.
            status["results"].append({
                "id": project["id"], "project": project["project"], "status": "failed", "error": str(exc),
            })
            status["failed"] += 1
        _write_status(status)
    status["status"] = "completed" if status["failed"] == 0 else "completed_with_errors"
    status["current"] = None
    status["completed_at"] = _now()
    _write_status(status)
    return status


def main() -> None:
    parser = argparse.ArgumentParser(description="Re-analyze every monitored BuildProof repository")
    parser.parse_args()
    result = rescan_all()
    sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
    raise SystemExit(1 if result["failed"] else 0)


if __name__ == "__main__":
    main()
