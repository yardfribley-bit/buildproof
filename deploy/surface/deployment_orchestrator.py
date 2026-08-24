#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

HOST = os.environ.get("SURFACE_ORCHESTRATOR_HOST", "0.0.0.0")
PORT = int(os.environ.get("SURFACE_ORCHESTRATOR_PORT", "18788"))
TOKEN = os.environ["SURFACE_ORCHESTRATOR_TOKEN"]
RUNTIME_BASE = os.environ["SURFACE_RUNTIME_BASE"].rstrip("/")
RUNTIME_TOKEN = os.environ["SURFACE_RUNTIME_TOKEN"]
ROOT = Path(os.environ.get("SURFACE_RUN_ROOT", "/var/lib/buildproof-surface/runs"))
TTL_SECONDS = int(os.environ.get("SURFACE_RUN_TTL", "21600"))
MAX_BUILD_SECONDS = int(os.environ.get("SURFACE_BUILD_TIMEOUT", "3600"))
REPORT_ID = re.compile(r"[a-z0-9_.-]+")
GITHUB_REPO = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?")
TASKS: queue.Queue[str] = queue.Queue()
LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _job_dir(report_id: str) -> Path:
    return ROOT / report_id


def _status_path(report_id: str) -> Path:
    return _job_dir(report_id) / "status.json"


def _read_status(report_id: str) -> dict[str, Any] | None:
    try:
        return json.loads(_status_path(report_id).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_status(report_id: str, **updates: Any) -> dict[str, Any]:
    with LOCK:
        current = _read_status(report_id) or {"report_id": report_id, "created_at": _now()}
        current.update(updates, updated_at=_now())
        path = _status_path(report_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(current, ensure_ascii=False), encoding="utf-8")
        temporary.replace(path)
        return current


def _run(command: list[str], *, timeout: int = 300, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc))[-2000:]
        raise RuntimeError(f"{command[0]} {command[1]} failed: {detail}") from exc


def _event(report_id: str, event_type: str, summary: str, *, tags: list[str] | None = None, **fields: Any) -> None:
    payload = {"event_type": event_type, "action": {"summary": summary}, "tags": tags or [], **fields}
    request = urllib.request.Request(
        f"{RUNTIME_BASE}/{report_id}",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {RUNTIME_TOKEN}", "Content-Type": "application/json", "X-Runtime-Source": os.uname().nodename},
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=20).close()
    except (OSError, urllib.error.URLError):
        pass


def _container_name(report_id: str) -> str:
    digest = hashlib.sha256(report_id.encode()).hexdigest()[:12]
    return f"buildproof-{digest}"


def _destroy(report_id: str, *, remove_data: bool = True) -> None:
    subprocess.run(["docker", "rm", "-f", _container_name(report_id)], check=False, capture_output=True, text=True)
    if remove_data:
        shutil.rmtree(_job_dir(report_id) / "data", ignore_errors=True)


def _image_ports(image: str) -> list[int]:
    result = _run(["docker", "image", "inspect", image, "--format", "{{json .Config.ExposedPorts}}"])
    exposed = json.loads(result.stdout.strip() or "{}") or {}
    return sorted({int(value.split("/", 1)[0]) for value in exposed})


def _probe(port: int, deadline: float) -> int | None:
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as response:
                return response.status
        except (OSError, urllib.error.URLError):
            time.sleep(5)
    return None


def _deploy(report_id: str) -> None:
    status = _read_status(report_id) or {}
    repo, commit = status["repo"], status["commit"]
    worktree = _job_dir(report_id) / "source"
    image = f"buildproof/{report_id}:{commit[:12]}"
    try:
        _write_status(report_id, status="cloning", phase="clone")
        _event(report_id, "deployment.started", f"cloning exact commit {commit[:12]}", path=repo)
        shutil.rmtree(worktree, ignore_errors=True)
        worktree.parent.mkdir(parents=True, exist_ok=True)
        _run(["git", "clone", "--filter=blob:none", "--no-checkout", repo, str(worktree)], timeout=300)
        _run(["git", "checkout", "--detach", commit], timeout=120, cwd=worktree)
        actual = _run(["git", "rev-parse", "HEAD"], cwd=worktree).stdout.strip()
        if actual != commit:
            raise RuntimeError(f"checked out {actual}, expected {commit}")
        if not (worktree / "Dockerfile").is_file():
            raise RuntimeError("repository has no root Dockerfile; compose-only deployment is not supported yet")

        _write_status(report_id, status="building", phase="build")
        dockerfile = (worktree / "Dockerfile").read_text(encoding="utf-8", errors="replace")
        target = ["--target", "production"] if re.search(r"^FROM\s+.+\s+AS\s+production\s*$", dockerfile, re.MULTILINE | re.IGNORECASE) else []
        _run(
            [
                "docker", "buildx", "build", "--load", "--label", f"buildproof.source_commit={commit}",
                *target, "-t", image, ".",
            ],
            timeout=MAX_BUILD_SECONDS,
            cwd=worktree,
        )
        ports = _image_ports(image)
        if not ports:
            raise RuntimeError("built image declares no exposed TCP port")
        public_container_port = 3782 if 3782 in ports else ports[0]
        public_port = 20000 + int(hashlib.sha256(report_id.encode()).hexdigest()[:4], 16) % 20000
        data = _job_dir(report_id) / "data"
        data.mkdir(parents=True, exist_ok=True)
        _destroy(report_id, remove_data=False)
        command = [
            "docker", "run", "-d", "--name", _container_name(report_id), "--restart=no",
            "--memory=768m", "--memory-swap=2g", "--pids-limit=512", "--security-opt", "no-new-privileges:true",
            "--label", f"buildproof.report={report_id}", "--label", f"buildproof.source_commit={commit}",
            "-p", f"0.0.0.0:{public_port}:{public_container_port}", "-v", f"{data}:/app/data", image,
        ]
        _run(command)
        _write_status(report_id, status="probing", phase="health", public_port=public_port, container_port=public_container_port)
        code = _probe(public_port, time.monotonic() + 180)
        if code is None:
            logs = _run(["docker", "logs", "--tail", "80", _container_name(report_id)]).stdout
            raise RuntimeError(f"HTTP health probe timed out; container logs: {logs[-2000:]}")
        url = f"http://{os.environ.get('SURFACE_PUBLIC_HOST', '')}:{public_port}/"
        expires_at = time.time() + TTL_SECONDS
        _write_status(report_id, status="running", phase="complete", http_status=code, url=url, commit_verified=True, expires_at=expires_at)
        _event(report_id, "deployment.ready", f"exact commit {commit[:12]} running", process=_container_name(report_id), path=repo)
        _event(report_id, "http.probe", "public application probe", process=_container_name(report_id), method="GET", url=url, status=str(code))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        _write_status(report_id, status="failed", phase="failed", error=str(exc)[-1000:])
        _event(report_id, "deployment.failed", str(exc)[-500:], tags=["deployment_failed"], path=repo)
        _destroy(report_id, remove_data=False)
    finally:
        shutil.rmtree(worktree, ignore_errors=True)


def _worker() -> None:
    while True:
        report_id = TASKS.get()
        _deploy(report_id)
        TASKS.task_done()


def _reaper() -> None:
    while True:
        for path in ROOT.glob("*/status.json"):
            status = _read_status(path.parent.name) or {}
            expires_at = status.get("expires_at")
            if status.get("status") == "running" and expires_at is not None and float(expires_at) <= time.time():
                _destroy(path.parent.name)
                _write_status(path.parent.name, status="expired", phase="destroyed")
                _event(path.parent.name, "deployment.destroyed", "TTL expired; container and data removed")
        time.sleep(60)


class Handler(BaseHTTPRequestHandler):
    def _authorized(self) -> bool:
        return hmac.compare_digest(self.headers.get("Authorization", "").removeprefix("Bearer "), TOKEN)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if not self._authorized() or self.path != "/jobs":
            self._json(401 if not self._authorized() else 404, {"error": "Unauthorized"})
            return
        try:
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            report_id = str(payload["report_id"]).lower()
            repo, commit = str(payload["repo"]), str(payload["commit"]).lower()
            if not REPORT_ID.fullmatch(report_id) or not GITHUB_REPO.fullmatch(repo) or not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise ValueError("invalid report_id, repo, or commit")
        except (KeyError, ValueError, json.JSONDecodeError):
            self._json(400, {"error": "Invalid deployment request"})
            return
        current = _read_status(report_id) or {}
        if current.get("status") in {"queued", "cloning", "building", "probing"}:
            self._json(409, current)
            return
        status = _write_status(report_id, status="queued", phase="queued", repo=repo, commit=commit, error=None)
        TASKS.put(report_id)
        self._json(202, status)

    def do_GET(self) -> None:
        if not self._authorized():
            self._json(401, {"error": "Unauthorized"})
            return
        match = re.fullmatch(r"/jobs/([a-z0-9_.-]+)", self.path)
        status = _read_status(match.group(1)) if match else None
        self._json(200 if status else 404, status or {"error": "Job not found"})

    def do_DELETE(self) -> None:
        if not self._authorized():
            self._json(401, {"error": "Unauthorized"})
            return
        match = re.fullmatch(r"/jobs/([a-z0-9_.-]+)", self.path)
        if not match:
            self._json(404, {"error": "Job not found"})
            return
        report_id = match.group(1)
        _destroy(report_id)
        self._json(200, _write_status(report_id, status="destroyed", phase="destroyed"))

    def log_message(self, *_args: object) -> None:
        return


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=_worker, daemon=True).start()
    threading.Thread(target=_reaper, daemon=True).start()
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
