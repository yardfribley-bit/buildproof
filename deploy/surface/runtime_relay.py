#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LISTEN_HOST = os.environ.get("SURFACE_RELAY_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("SURFACE_RELAY_PORT", "18787"))
UPSTREAM = os.environ["SURFACE_RUNTIME_UPSTREAM"]
TOKEN = os.environ["SURFACE_RUNTIME_TOKEN"]
SPOOL = Path(os.environ.get("SURFACE_RELAY_SPOOL", "/var/lib/buildproof-surface/spool"))
MAX_BATCH = 1024 * 1024
STATE = {"accepted": 0, "forwarded": 0, "failed": 0, "last_forwarded_at": None}


def _forward(path: Path) -> bool:
    request = urllib.request.Request(
        UPSTREAM,
        data=path.read_bytes(),
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/x-ndjson",
            "X-Runtime-Source": os.uname().nodename,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status < 200 or response.status >= 300:
                return False
    except (OSError, urllib.error.URLError):
        STATE["failed"] += 1
        return False
    path.unlink(missing_ok=True)
    STATE["forwarded"] += 1
    STATE["last_forwarded_at"] = time.time()
    return True


def _worker() -> None:
    while True:
        for path in sorted(SPOOL.glob("*.ndjson")):
            if not _forward(path):
                break
        time.sleep(5)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/ingest":
            self.send_error(404)
            return
        length = int(self.headers.get("content-length", "0") or 0)
        if length <= 0 or length > MAX_BATCH:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        try:
            for line in body.splitlines():
                json.loads(line)
        except json.JSONDecodeError:
            self.send_error(400)
            return
        path = SPOOL / f"{time.time_ns()}-{uuid.uuid4().hex}.ndjson"
        path.write_bytes(body)
        STATE["accepted"] += 1
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"accepted":true}')

    def do_GET(self) -> None:
        if self.path != "/health":
            self.send_error(404)
            return
        payload = {**STATE, "status": "ok", "queued": len(list(SPOOL.glob("*.ndjson")))}
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def main() -> None:
    SPOOL.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=_worker, daemon=True).start()
    ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
