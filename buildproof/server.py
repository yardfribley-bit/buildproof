from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

from .analyzer import analyze_repository

STATIC_ROOT = Path(__file__).with_name("static")


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
        report = analyze_repository(repo)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse(report.to_dict())


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
    args = parser.parse_args()
    if args.repo:
        os.environ["BUILDPROOF_REPO"] = str(Path(args.repo).expanduser().resolve())
    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

