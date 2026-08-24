from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

from .analyzer import analyze_repository
from .deployment import deployment_status, trigger_deployment
from .runtime_audit import MAX_BATCH_BYTES, append_events, parse_batch, runtime_summary

STATIC_ROOT = Path(__file__).with_name("static")
GITHUB_REPO = re.compile(
    r"^(?:https://github\.com/)?(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
ANALYSIS_GATE = asyncio.Semaphore(1)


def _public_mode() -> bool:
    return os.environ.get("BUILDPROOF_PUBLIC", "").lower() in {"1", "true", "yes"}


def _reports_root() -> Path:
    root = Path(os.environ.get("BUILDPROOF_DATA", "/tmp/buildproof")) / "reports"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _rescan_status_path() -> Path:
    return _reports_root().parent / "rescan-status.json"


def _runtime_root() -> Path:
    return _reports_root().parent / "runtime"


def _report_id(report: dict[str, object]) -> str:
    root = str(report.get("root", ""))
    match = GITHUB_REPO.fullmatch(root)
    if match:
        return f"{match.group('owner')}--{match.group('repo')}".lower()
    return re.sub(r"[^a-z0-9_.-]+", "-", str(report.get("project", "project")).lower())


def _save_report(report: dict[str, object]) -> dict[str, object]:
    report = {**report, "id": _report_id(report)}
    destination = _reports_root() / f"{report['id']}.json"
    temporary = destination.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    temporary.replace(destination)
    return report


def _history() -> list[dict[str, object]]:
    projects = []
    for path in _reports_root().glob("*.json"):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            projects.append({key: report[key] for key in ("id", "project", "root", "generated_at", "stats")})
        except (KeyError, OSError, json.JSONDecodeError):
            continue
    return sorted(projects, key=lambda item: str(item["generated_at"]), reverse=True)


def _prepare_public_repository(value: str) -> tuple[Path, str, str]:
    match = GITHUB_REPO.fullmatch(value.strip())
    if not match:
        raise ValueError("请输入公开 GitHub 仓库地址，例如 https://github.com/owner/repo")
    owner, repo = match.group("owner"), match.group("repo")
    slug = f"{owner}/{repo}"
    cache_root = Path(os.environ.get("BUILDPROOF_DATA", "/tmp/buildproof")) / "repos"
    cache_root.mkdir(parents=True, exist_ok=True)
    target = cache_root / owner / repo
    url = f"https://github.com/{slug}.git"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        shutil.rmtree(target)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", url, str(target)],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(target, ignore_errors=True)
        raise ValueError("仓库下载超时，请尝试体积更小的仓库。") from exc
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(target, ignore_errors=True)
        raise ValueError("无法下载该公开仓库，请检查地址和访问权限。") from exc
    size = sum(path.stat().st_size for path in target.rglob("*") if path.is_file())
    if size > 500 * 1024 * 1024:
        shutil.rmtree(target, ignore_errors=True)
        raise ValueError("仓库超过 500 MB，暂不支持在线分析。")
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=target, check=True, capture_output=True, text=True, timeout=10
    ).stdout.strip()
    return target, f"https://github.com/{slug}", commit


def _analyze(repo: str) -> dict[str, object]:
    source = repo
    source_commit = ""
    temporary_repository = False
    if _public_mode():
        path, source, source_commit = _prepare_public_repository(repo)
        temporary_repository = True
    else:
        path = Path(repo).expanduser().resolve()
    try:
        report = analyze_repository(path).to_dict()
        if _public_mode():
            report["root"] = source
            report["source_commit"] = source_commit
            report["attack_manifest"]["source"] = source
        saved = _save_report(report)
        if _public_mode():
            saved["deployment"] = trigger_deployment(saved)
            saved = _save_report(saved)
        return saved
    finally:
        if temporary_repository:
            shutil.rmtree(path, ignore_errors=True)


async def index(_request: Request) -> FileResponse:
    return FileResponse(STATIC_ROOT / "index.html")


async def asset(request: Request) -> FileResponse:
    name = request.path_params["name"]
    images = {"deeptutor-overview.png", "deeptutor-call-chain.png", "deeptutor-supply-chain.png"}
    if name not in {"app.js", "styles.css", "security.css", *images}:
        return FileResponse(STATIC_ROOT / "index.html", status_code=404)
    return FileResponse(STATIC_ROOT / "images" / name if name in images else STATIC_ROOT / name)


async def articles(_request: Request) -> FileResponse:
    return FileResponse(STATIC_ROOT / "articles.html")


async def article(request: Request) -> FileResponse:
    slug = request.path_params["slug"]
    path = STATIC_ROOT / "articles" / f"{slug}.html"
    if not re.fullmatch(r"[a-z0-9-]+", slug) or not path.is_file():
        return FileResponse(STATIC_ROOT / "articles.html", status_code=404)
    return FileResponse(path)


async def analyze(request: Request) -> JSONResponse:
    if request.method == "POST":
        payload = await request.json()
        repo = str(payload.get("repo", "")).strip()
    else:
        repo = parse_qs(request.url.query).get("repo", [""])[0].strip()
    repo = repo or os.environ.get("BUILDPROOF_REPO", "")
    if not repo:
        return JSONResponse({"error": "A repository path is required."}, status_code=400)
    try:
        async with ANALYSIS_GATE:
            report = await run_in_threadpool(_analyze, repo)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse(report)


async def history(_request: Request) -> JSONResponse:
    return JSONResponse(_history())


async def rescan_status(_request: Request) -> JSONResponse:
    path = _rescan_status_path()
    if not path.is_file():
        return JSONResponse({"status": "never_run"})
    try:
        return JSONResponse(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return JSONResponse({"status": "unknown", "error": "扫描状态文件不可读。"}, status_code=503)


async def runtime_ingest(request: Request) -> JSONResponse:
    expected = os.environ.get("BUILDPROOF_RUNTIME_TOKEN", "")
    supplied = request.headers.get("authorization", "").removeprefix("Bearer ")
    if not expected or not hmac.compare_digest(supplied, expected):
        return JSONResponse({"error": "Unauthorized."}, status_code=401)
    report_id = request.path_params["report_id"].lower()
    if not re.fullmatch(r"[a-z0-9_.-]+", report_id):
        return JSONResponse({"error": "Invalid report id."}, status_code=400)
    if not (_reports_root() / f"{report_id}.json").is_file():
        return JSONResponse({"error": "Report not found."}, status_code=404)
    if int(request.headers.get("content-length", "0") or 0) > MAX_BATCH_BYTES:
        return JSONResponse({"error": "Runtime event batch exceeds 1 MiB."}, status_code=413)
    try:
        events = parse_batch(await request.body(), request.headers.get("x-runtime-source", "surface"))
        append_events(_runtime_root(), report_id, events)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse({"accepted": len(events)})


async def project_runtime(request: Request) -> JSONResponse:
    report_id = request.path_params["report_id"].lower()
    if not re.fullmatch(r"[a-z0-9_.-]+", report_id):
        return JSONResponse({"error": "Invalid report id."}, status_code=400)
    return JSONResponse(runtime_summary(_runtime_root(), report_id))


async def project_deployment(request: Request) -> JSONResponse:
    report_id = request.path_params["report_id"].lower()
    if not re.fullmatch(r"[a-z0-9_.-]+", report_id):
        return JSONResponse({"error": "Invalid report id."}, status_code=400)
    return JSONResponse(await run_in_threadpool(deployment_status, report_id))


async def saved_report(request: Request) -> JSONResponse:
    report_id = request.path_params["report_id"].lower()
    if not re.fullmatch(r"[a-z0-9_.-]+", report_id):
        return JSONResponse({"error": "Invalid report id."}, status_code=400)
    path = _reports_root() / f"{report_id}.json"
    if not path.is_file():
        return JSONResponse({"error": "Report not found."}, status_code=404)
    return JSONResponse(json.loads(path.read_text(encoding="utf-8")))


async def attack_manifest(request: Request) -> JSONResponse:
    report_id = request.path_params["report_id"].lower()
    if not re.fullmatch(r"[a-z0-9_.-]+", report_id):
        return JSONResponse({"error": "Invalid report id."}, status_code=400)
    path = _reports_root() / f"{report_id}.json"
    if not path.is_file():
        return JSONResponse({"error": "Report not found."}, status_code=404)
    report = json.loads(path.read_text(encoding="utf-8"))
    manifest = report.get("attack_manifest")
    if not manifest:
        return JSONResponse({"error": "Re-analyze this project to generate an attack manifest."}, status_code=409)
    return JSONResponse(manifest)


def create_app() -> Starlette:
    return Starlette(
        debug=False,
        routes=[
            Route("/", index),
            Route("/assets/{name}", asset),
            Route("/articles", articles),
            Route("/articles/{slug}", article),
            Route("/api/analyze", analyze, methods=["GET", "POST"]),
            Route("/api/projects", history),
            Route("/api/rescan-status", rescan_status),
            Route("/api/runtime/ingest/{report_id}", runtime_ingest, methods=["POST"]),
            Route("/api/projects/{report_id}", saved_report),
            Route("/api/projects/{report_id}/attack-manifest", attack_manifest),
            Route("/api/projects/{report_id}/runtime", project_runtime),
            Route("/api/projects/{report_id}/deployment", project_deployment),
        ],
    )


app = create_app()


def main() -> None:
    parser = argparse.ArgumentParser(description="BuildProof code analysis console")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--repo", default="")
    parser.add_argument("--public", action="store_true")
    args = parser.parse_args()
    if args.repo:
        os.environ["BUILDPROOF_REPO"] = str(Path(args.repo).expanduser().resolve())
    if args.public:
        os.environ["BUILDPROOF_PUBLIC"] = "true"
    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
