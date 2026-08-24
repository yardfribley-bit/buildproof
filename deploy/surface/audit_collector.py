#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

AUDIT_LOG = Path(os.environ.get("SURFACE_AUDIT_LOG", "/var/log/audit/audit.log"))
CHECKPOINT = Path(os.environ.get("SURFACE_AUDIT_CHECKPOINT", "/var/lib/buildproof-surface/audit.offset"))
RELAY = os.environ.get("SURFACE_RELAY_URL", "http://127.0.0.1:18787/ingest")
FIELD = re.compile(r'\b(?P<key>exe|comm|success|key|uid|auid)=(?:"(?P<quoted>[^"]*)"|(?P<plain>\S+))')


def _post(events: list[dict[str, object]]) -> bool:
    body = b"\n".join(json.dumps(event, separators=(",", ":")).encode() for event in events)
    request = urllib.request.Request(RELAY, data=body, headers={"Content-Type": "application/x-ndjson"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status == 202
    except (OSError, urllib.error.URLError):
        return False


def _event(line: str) -> dict[str, object] | None:
    if "type=SYSCALL" not in line or "buildproof_exec" not in line:
        return None
    values = {match.group("key"): match.group("quoted") or match.group("plain") for match in FIELD.finditer(line)}
    process = values.get("comm") or Path(values.get("exe", "")).name
    if not process:
        return None
    tags = []
    if values.get("success") not in {"yes", "1"}:
        tags.append("exec_failed")
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "process.exec",
        "process": process,
        "path": values.get("exe", ""),
        "action": {"summary": f"uid={values.get('uid', '')} auid={values.get('auid', '')}"},
        "tags": tags,
    }


def main() -> None:
    CHECKPOINT.parent.mkdir(parents=True, exist_ok=True)
    _post([{
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "runtime.audit.started",
        "process": "buildproof-audit-collector",
        "action": {"summary": "Linux audit execution monitoring active"},
        "tags": [],
    }])
    while not AUDIT_LOG.exists():
        time.sleep(2)
    offset = int(CHECKPOINT.read_text().strip() or "0") if CHECKPOINT.exists() else AUDIT_LOG.stat().st_size
    while True:
        size = AUDIT_LOG.stat().st_size
        if size < offset:
            offset = 0
        with AUDIT_LOG.open(encoding="utf-8", errors="replace") as stream:
            stream.seek(offset)
            events = [event for line in stream if (event := _event(line))]
            offset = stream.tell()
        failed = False
        for index in range(0, len(events), 1000):
            if not _post(events[index : index + 1000]):
                failed = True
                break
        if failed:
            time.sleep(5)
            continue
        CHECKPOINT.write_text(str(offset), encoding="utf-8")
        time.sleep(2)


if __name__ == "__main__":
    main()
