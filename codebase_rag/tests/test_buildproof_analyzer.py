from __future__ import annotations

import json
import os
from pathlib import Path

from starlette.testclient import TestClient

from buildproof import analyze_repository, rescan
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
    assert report.relations[0].status == "unresolved"


def test_builds_frontend_next_api_backend_relation(tmp_path: Path) -> None:
    _write(tmp_path / "web/app/dashboard/page.tsx", 'fetch("/api/users/42");\n')
    _write(
        tmp_path / "web/app/api/users/[id]/route.ts",
        'export async function GET() { return fetch("/api/v1/users/${id}") }\n',
    )
    _write(
        tmp_path / "backend/users.py",
        'router = APIRouter(prefix="/api/v1/users")\n'
        '@router.get("/{user_id}")\nasync def get_user(): pass\n',
    )

    report = analyze_repository(tmp_path)

    relation = report.relations[0]
    assert relation.status == "proxy"
    assert relation.api is not None and relation.api.layer == "frontend-api"
    assert relation.api.path == "/api/users/:id"
    assert relation.backend is not None and relation.backend.handler == "get_user"
    assert report.stats["mapped_calls"] == 1


def test_maps_frontend_supabase_sdk_to_external_backend(tmp_path: Path) -> None:
    _write(
        tmp_path / "web/app/account/page.tsx",
        'const supabase = createClient();\nawait supabase.auth.signOut();\n'
        'await supabase.from("profiles").update(values);\n',
    )

    report = analyze_repository(tmp_path)

    assert report.stats["client_calls"] == 2
    assert report.stats["mapped_calls"] == 2
    assert {item.backend.layer for item in report.relations if item.backend} == {"external-supabase"}
    assert {item.call.path for item in report.relations} == {
        "supabase://auth/signOut",
        "supabase://table/profiles",
    }


def test_generates_shannon_attack_manifest_with_candidate_and_evidence(tmp_path: Path) -> None:
    _write(tmp_path / "web/app/users/page.tsx", 'fetch("/api/users/${id}");\n')
    _write(
        tmp_path / "backend/users.py",
        'router = APIRouter(prefix="/api/users")\n'
        '@router.get("/{user_id}")\n'
        'async def get_user(user_id):\n'
        '    return db.execute("select * from users where id=" + user_id)\n',
    )

    report = analyze_repository(tmp_path)
    manifest = report.attack_manifest

    assert manifest["schema_version"] == "buildproof.attack-manifest.v1"
    surface = manifest["attack_surfaces"][0]
    assert {item["type"] for item in surface["hypotheses"]} == {"idor", "sql-injection"}
    assert surface["sinks"][0]["evidence"]["path"] == "backend/users.py"
    assert all(item["status"] == "candidate" for item in surface["hypotheses"])


def test_uses_frontend_http_method_to_avoid_ambiguous_routes(tmp_path: Path) -> None:
    _write(tmp_path / "web/app/page.tsx", 'api.post("/api/items");\n')
    _write(
        tmp_path / "backend/items.py",
        'router = APIRouter(prefix="/api/items")\n'
        '@router.get("")\nasync def list_items(): pass\n'
        '@router.post("")\nasync def create_item(): pass\n',
    )

    report = analyze_repository(tmp_path)

    assert report.pages[0].calls[0].method == "POST"
    assert [item.backend.handler for item in report.relations if item.backend] == ["create_item"]


def test_attack_manifest_api_is_machine_readable(tmp_path: Path) -> None:
    previous = os.environ.get("BUILDPROOF_DATA")
    os.environ["BUILDPROOF_DATA"] = str(tmp_path / "data")
    _write(tmp_path / "repo/web/app/page.tsx", 'fetch("/api/status");\n')
    try:
        with TestClient(create_app()) as client:
            analyzed = client.post("/api/analyze", json={"repo": str(tmp_path / "repo")}).json()
            response = client.get(f"/api/projects/{analyzed['id']}/attack-manifest")
    finally:
        if previous is None:
            os.environ.pop("BUILDPROOF_DATA", None)
        else:
            os.environ["BUILDPROOF_DATA"] = previous

    assert response.status_code == 200
    assert response.json()["schema_version"] == "buildproof.attack-manifest.v1"


def test_rescan_all_updates_every_monitored_project_and_status(tmp_path: Path, monkeypatch) -> None:
    previous = os.environ.get("BUILDPROOF_DATA")
    os.environ["BUILDPROOF_DATA"] = str(tmp_path / "data")
    reports = tmp_path / "data/reports"
    reports.mkdir(parents=True)
    for name in ("one", "two"):
        _write(
            reports / f"owner--{name}.json",
            json.dumps({
                "id": f"owner--{name}", "project": name,
                "root": f"https://github.com/owner/{name}", "generated_at": "old", "stats": {},
            }),
        )
    scanned: list[str] = []

    def fake_analyze(source: str) -> dict[str, object]:
        scanned.append(source)
        name = source.rsplit("/", 1)[-1]
        return {
            "id": f"owner--{name}", "project": name, "generated_at": "new",
            "attack_manifest": {"summary": {"attack_surfaces": 3}},
        }

    monkeypatch.setattr(rescan, "_analyze", fake_analyze)
    try:
        result = rescan.rescan_all()
        with TestClient(create_app()) as client:
            saved_status = client.get("/api/rescan-status").json()
    finally:
        if previous is None:
            os.environ.pop("BUILDPROOF_DATA", None)
        else:
            os.environ["BUILDPROOF_DATA"] = previous

    assert set(scanned) == {"https://github.com/owner/one", "https://github.com/owner/two"}
    assert result["status"] == "completed"
    assert result["completed"] == 2
    assert saved_status["results"][0]["attack_surfaces"] == 3


def test_runtime_ingest_requires_token_and_returns_redacted_summary(tmp_path: Path) -> None:
    previous_data = os.environ.get("BUILDPROOF_DATA")
    previous_token = os.environ.get("BUILDPROOF_RUNTIME_TOKEN")
    os.environ["BUILDPROOF_DATA"] = str(tmp_path / "data")
    os.environ["BUILDPROOF_RUNTIME_TOKEN"] = "test-runtime-token"
    reports = tmp_path / "data/reports"
    reports.mkdir(parents=True)
    _write(reports / "owner--repo.json", json.dumps({"id": "owner--repo"}))
    payload = {
        "source": "surface-node",
        "events": [{
            "ts": 1_700_000_000, "etype": "HTTP", "method": "POST",
            "url": "/api/login?password=must-not-be-copied", "status": "401",
            "tags": ["auth_brute"], "raw_secret": "never stored",
        }],
    }
    try:
        with TestClient(create_app()) as client:
            denied = client.post("/api/runtime/ingest/owner--repo", json=payload)
            accepted = client.post(
                "/api/runtime/ingest/owner--repo",
                json=payload,
                headers={"authorization": "Bearer test-runtime-token"},
            )
            summary = client.get("/api/projects/owner--repo/runtime")
    finally:
        if previous_data is None:
            os.environ.pop("BUILDPROOF_DATA", None)
        else:
            os.environ["BUILDPROOF_DATA"] = previous_data
        if previous_token is None:
            os.environ.pop("BUILDPROOF_RUNTIME_TOKEN", None)
        else:
            os.environ["BUILDPROOF_RUNTIME_TOKEN"] = previous_token

    assert denied.status_code == 401
    assert accepted.json() == {"accepted": 1}
    assert summary.json()["status"] == "observing"
    assert summary.json()["alerts"] == 1
    assert "raw_secret" not in json.dumps(summary.json())


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


def test_resolves_aliased_router_and_local_prefix(tmp_path: Path) -> None:
    _write(
        tmp_path / "backend/routes/agents.py",
        'router = APIRouter(prefix="/agents")\n@router.get("/{agent_id}")\nasync def get_agent(): pass\n',
    )
    _write(
        tmp_path / "backend/main.py",
        'from .routes.agents import router as agents_router\napp.include_router(agents_router, prefix="/api/v1")\n',
    )
    _write(tmp_path / "frontend/app/page.tsx", 'fetch("/api/v1/agents/42");\n')

    report = analyze_repository(tmp_path)

    assert report.endpoints[0].path == "/api/v1/agents/:param"
    assert report.stats["mapped_calls"] == 1


def test_propagates_constant_global_api_prefix(tmp_path: Path) -> None:
    _write(tmp_path / "backend/config.py", 'API_V1_STR: str = "/api/v1"\n')
    _write(
        tmp_path / "backend/routes/users.py",
        'router = APIRouter()\n@router.get("/me")\nasync def me(): pass\n',
    )
    _write(
        tmp_path / "backend/routes/__init__.py",
        'v1_router.include_router(users.router, prefix="/users")\n',
    )
    _write(
        tmp_path / "backend/main.py",
        'app.include_router(api_router, prefix=settings.API_V1_STR)\n',
    )
    _write(tmp_path / "frontend/app/page.tsx", 'fetch("/api/v1/users/me");\n')

    report = analyze_repository(tmp_path)

    assert report.endpoints[0].path == "/api/v1/users/me"
    assert report.stats["mapped_calls"] == 1


def test_parses_fastapi_routes_inside_cookiecutter_templates(tmp_path: Path) -> None:
    _write(
        tmp_path / "backend/users.py",
        '{%- if cookiecutter.use_auth %}\nrouter = APIRouter(prefix="/api/users")\n@router.get("/me")\nasync def me(): pass\n{% endif %}\n',
    )
    _write(tmp_path / "frontend/app/page.tsx", 'fetch("/api/users/me");\n')

    report = analyze_repository(tmp_path)

    assert report.endpoints[0].handler == "me"
    assert report.stats["mapped_calls"] == 1
