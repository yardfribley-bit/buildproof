from __future__ import annotations

import json
import re
from collections import Counter, deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPORT_ID = re.compile(r"[a-z0-9_.-]+")
MAX_BATCH_BYTES = 1024 * 1024
MAX_EVENTS_PER_BATCH = 1000


def _timestamp(event: dict[str, Any]) -> str:
    value = event.get("timestamp")
    if isinstance(value, str) and value:
        return value
    raw = event.get("ts")
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw, UTC).isoformat()
    return datetime.now(UTC).isoformat()


def _text(value: Any, limit: int = 500) -> str:
    return str(value or "")[:limit]


def normalize_event(event: dict[str, Any], source: str) -> dict[str, Any]:
    action = event.get("action") if isinstance(event.get("action"), dict) else {}
    arguments = action.get("arguments_redacted") if isinstance(action.get("arguments_redacted"), dict) else {}
    tags = event.get("tags") if isinstance(event.get("tags"), list) else []
    return {
        "timestamp": _timestamp(event),
        "event_type": _text(event.get("event_type") or event.get("etype") or "runtime.event", 80),
        "source": _text(event.get("source") or source, 120),
        "trace_id": _text(event.get("trace_id"), 160),
        "span_id": _text(event.get("span_id"), 160),
        "process": _text(event.get("process") or arguments.get("exe") or arguments.get("comm"), 300),
        "path": _text(event.get("path") or arguments.get("path"), 500),
        "method": _text(event.get("method"), 16),
        "url": _text(event.get("url"), 500).split("?", 1)[0],
        "status": _text(event.get("status"), 16),
        "peer": _text(arguments.get("peer"), 200),
        "summary": _text(action.get("summary"), 500),
        "tags": [_text(item, 80) for item in tags[:20]],
    }


def parse_batch(body: bytes, source: str) -> list[dict[str, Any]]:
    if len(body) > MAX_BATCH_BYTES:
        raise ValueError("Runtime event batch exceeds 1 MiB.")
    text = body.decode("utf-8")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(payload, dict) and isinstance(payload.get("events"), list):
        source = _text(payload.get("source") or source, 120)
        payload = payload["events"]
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list) or len(payload) > MAX_EVENTS_PER_BATCH:
        raise ValueError("Runtime event payload must contain at most 1000 events.")
    if not all(isinstance(item, dict) for item in payload):
        raise ValueError("Every runtime event must be a JSON object.")
    return [normalize_event(item, source) for item in payload]


def append_events(root: Path, report_id: str, events: list[dict[str, Any]]) -> None:
    if not REPORT_ID.fullmatch(report_id):
        raise ValueError("Invalid report id.")
    root.mkdir(parents=True, exist_ok=True)
    with (root / f"{report_id}.jsonl").open("a", encoding="utf-8") as stream:
        for event in events:
            stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")


def runtime_summary(root: Path, report_id: str) -> dict[str, Any]:
    path = root / f"{report_id}.jsonl"
    if not path.is_file():
        return {"status": "waiting", "events": 0, "alerts": 0, "last_event_at": None, "counts": {}, "recent": []}
    recent: deque[dict[str, Any]] = deque(maxlen=100)
    counts: Counter[str] = Counter()
    total = alerts = 0
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            counts[event.get("event_type", "runtime.event")] += 1
            alerts += bool(event.get("tags"))
            recent.append(event)
    return {
        "status": "observing" if total else "waiting", "events": total, "alerts": alerts,
        "last_event_at": recent[-1]["timestamp"] if recent else None,
        "counts": dict(counts.most_common()), "recent": list(reversed(recent)),
    }
