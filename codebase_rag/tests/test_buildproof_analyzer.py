from __future__ import annotations

import json
import os
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
    assert report.pages[0].endpoints[0].handler == "get_user"


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


def test_public_mode_rejects_local_paths(tmp_path: Path) -> None:
    previous = os.environ.get("BUILDPROOF_PUBLIC")
    os.environ["BUILDPROOF_PUBLIC"] = "true"
    try:
        with TestClient(create_app()) as client:
            response = client.post("/api/analyze", json={"repo": str(tmp_path)})
    finally:
        if previous is None:
            os.environ.pop("BUILDPROOF_PUBLIC", None)
        else:
            os.environ["BUILDPROOF_PUBLIC"] = previous

    assert response.status_code == 400
    assert "GitHub" in response.json()["error"]


def test_saved_reports_are_listed_and_retrievable(tmp_path: Path) -> None:
    previous = os.environ.get("BUILDPROOF_DATA")
    os.environ["BUILDPROOF_DATA"] = str(tmp_path / "data")
    _write(tmp_path / "repo/web/app/page.tsx", 'fetch("/api/status");\n')
    try:
        with TestClient(create_app()) as client:
            analyzed = client.post("/api/analyze", json={"repo": str(tmp_path / "repo")})
            projects = client.get("/api/projects")
            saved = client.get(f"/api/projects/{analyzed.json()['id']}")
    finally:
        if previous is None:
            os.environ.pop("BUILDPROOF_DATA", None)
        else:
            os.environ["BUILDPROOF_DATA"] = previous

    assert projects.json()[0]["project"] == "repo"
    assert saved.json()["stats"]["pages"] == 1


def test_extracts_direct_supply_chain_components(tmp_path: Path) -> None:
    _write(
        tmp_path / "web/package.json",
        json.dumps({"dependencies": {"next": "16.2.3"}, "devDependencies": {"eslint": "^9.0.0"}}),
    )
    _write(
        tmp_path / "web/package-lock.json",
        json.dumps({"lockfileVersion": 3, "packages": {"node_modules/next": {"version": "16.2.3"}, "node_modules/eslint": {"version": "9.22.0"}}}),
    )
    _write(tmp_path / "requirements.txt", "fastapi==0.116.1\nuvicorn>=0.35\n")

    report = analyze_repository(tmp_path)
    components = {(item.ecosystem, item.name): item.version for item in report.components}

    assert components[("npm", "next")] == "16.2.3"
    assert components[("npm", "eslint")] == "^9.0.0"
    assert components[("PyPI", "fastapi")] == "==0.116.1"
    assert report.stats["components"] == 4
    layers = {item.name: item.layer for item in report.components}
    assert layers["next"] == "前端"
    assert layers["eslint"] == "工程工具"
    assert layers["fastapi"] == "后端"
    locked = {item.name: item.locked_version for item in report.components}
    assert locked["eslint"] == "9.22.0"
    assert all(item.scan_status == "not_scanned" for item in report.components)


def test_article_library_and_article_are_served() -> None:
    with TestClient(create_app()) as client:
        library = client.get("/articles")
        article = client.get("/articles/agent-code-acceptance")
        screenshot = client.get("/assets/deeptutor-overview.png")

    assert library.status_code == 200
    assert "文章与研究" in library.text
    assert article.status_code == 200
    assert "Agent 开始写完整系统" in article.text
    assert screenshot.status_code == 200
    assert screenshot.headers["content-type"] == "image/png"


def test_discovers_non_deeptutor_next_and_fastapi_layouts(tmp_path: Path) -> None:
    _write(tmp_path / "frontend/app/dashboard/page.tsx", 'fetch("/api/items");\n')
    _write(
        tmp_path / "backend/routes/items.py",
        'router = APIRouter()\n@router.get("/")\nasync def list_items(): pass\n',
    )
    _write(
        tmp_path / "backend/main.py",
        'app.include_router(items.router, prefix="/api/items")\n',
    )

    report = analyze_repository(tmp_path)

    assert report.pages[0].route == "/dashboard"
    assert report.endpoints[0].path == "/api/items"
    assert report.pages[0].endpoints[0].handler == "list_items"


def test_resolves_exact_npm_versions_from_pnpm_workspace_lock(tmp_path: Path) -> None:
    _write(
        tmp_path / "apps/web/package.json",
        json.dumps({"dependencies": {"next": "^16.0.0", "@scope/ui": "^2.0.0"}}),
    )
    _write(
        tmp_path / "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\npackages:\n  next@16.2.3:\n    resolution: {}\n  '@scope/ui@2.4.1':\n    resolution: {}\n",
    )

    report = analyze_repository(tmp_path)
    locked = {item.name: item.locked_version for item in report.components}

    assert locked["next"] == "16.2.3"
    assert locked["@scope/ui"] == "2.4.1"
