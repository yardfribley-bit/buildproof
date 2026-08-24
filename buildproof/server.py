from __future__ import annotations

import argparse
import asyncio
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

STATIC_ROOT = Path(__file__).with_name("static")
GITHUB_REPO = re.compile(
    r"^(?:https://github\.com/)?(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
ANALYSIS_GATE = asyncio.Semaphore(1)


def _public_mode() -> bool:
    return os.environ.get("BUILDPROOF_PUBLIC", "").lower() in {"1", "true", "yes"}


def _prepare_public_repository(value: str) -> tuple[Path, str]:
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
    return target, f"https://github.com/{slug}"


def _analyze(repo: str) -> dict[str, object]:
    source = repo
    if _public_mode():
        path, source = _prepare_public_repository(repo)
    else:
        path = Path(repo).expanduser().resolve()
    report = analyze_repository(path).to_dict()
    if _public_mode():
        report["root"] = source
    return report


async def index(_request: Request) -> FileResponse:
    return FileResponse(STATIC_ROOT / "index.html")


async def asset(request: Request) -> FileResponse:
    name = request.path_params["name"]
    if name not in {"app.js", "styles.css"}:
        return FileResponse(STATIC_ROOT / "index.html", status_code=404)
    return FileResponse(STATIC_ROOT / name)


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


def create_app() -> Starlette:
    return Starlette(
        debug=False,
        routes=[
            Route("/", index),
            Route("/assets/{name}", asset),
            Route("/api/analyze", analyze, methods=["GET", "POST"]),
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
