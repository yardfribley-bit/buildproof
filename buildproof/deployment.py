from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


def _request(method: str, path: str, payload: dict[str, str] | None = None) -> dict[str, Any]:
    base = os.environ.get("BUILDPROOF_SURFACE_URL", "").rstrip("/")
    token = os.environ.get("BUILDPROOF_SURFACE_TOKEN", "")
    if not base or not token:
        return {"status": "disabled"}
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        f"{base}{path}",
        data=data,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            detail = json.load(exc)
        except (json.JSONDecodeError, UnicodeDecodeError):
            detail = {"error": f"Surface returned HTTP {exc.code}"}
        return {"status": "trigger_failed", **detail}
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "error": str(exc)}


def trigger_deployment(report: dict[str, Any]) -> dict[str, Any]:
    commit = str(report.get("source_commit", ""))
    if len(commit) != 40:
        return {"status": "not_requested", "error": "No exact source commit is available."}
    return _request(
        "POST",
        "/jobs",
        {"report_id": str(report["id"]), "repo": str(report["root"]), "commit": commit},
    )


def deployment_status(report_id: str) -> dict[str, Any]:
    return _request("GET", f"/jobs/{report_id}")
