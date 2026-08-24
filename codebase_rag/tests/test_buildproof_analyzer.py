from __future__ import annotations

import json
from pathlib import Path

from starlette.testclient import TestClient

from buildproof import analyze_repository
from buildproof.server import create_app


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_maps_next_page_through_imports_to_fastapi_route(tmp_path: Path) -> None:
    _write(
        tmp_path / "web/package.json",
        json.dumps({"dependencies": {"next": "16", "react": "19"}}),
    )
    _write(
        tmp_path / "web/app/(workspace)/users/page.tsx",
        'import { Users } from "@/components/users"; export default Users;\n',
    )
    _write(
        tmp_path / "web/components/users.tsx",
        'fetch(`/api/v1/users/${userId}`);\n',
    )
    _write(
        tmp_path / "deeptutor/api/main.py",
        'app.include_router(users.router, prefix="/api/v1/users", dependencies=_auth)\n'
        '@app.get("/")\nasync def root(): pass\n',
    )
    _write(
        tmp_path / "deeptutor/api/routers/users.py",
        'router = APIRouter()\n@router.get("/{user_id}")\nasync def get_user(): pass\n',
    )

    report = analyze_repository(tmp_path)

    assert report.stats["pages"] == 1
    assert report.stats["http_endpoints"] == 2
    assert report.stats["mapped_calls"] == 1
    assert report.pages[0].route == "/users"
    assert report.pages[0].endpoints[0].path == "/api/v1/users/:param"


def test_marks_unresolved_client_calls_without_guessing(tmp_path: Path) -> None:
    _write(tmp_path / "web/app/page.tsx", 'fetch("/api/v1/missing");\n')

    report = analyze_repository(tmp_path)

    assert report.stats["unresolved_calls"] == 1
    assert report.pages[0].unresolved_calls[0].path == "/api/v1/missing"
    assert report.pages[0].endpoints == []


def test_analysis_api_returns_evidence_report(tmp_path: Path) -> None:
    _write(tmp_path / "web/app/page.tsx", 'fetch("/api/v1/status");\n')
    _write(
        tmp_path / "deeptutor/api/main.py",
        '@app.get("/api/v1/status")\nasync def status(): pass\n',
    )

    with TestClient(create_app()) as client:
        response = client.post("/api/analyze", json={"repo": str(tmp_path)})

    assert response.status_code == 200
    payload = response.json()
    assert payload["stats"]["mapped_calls"] == 1
    assert payload["pages"][0]["endpoints"][0]["evidence"]["line"] == 2
