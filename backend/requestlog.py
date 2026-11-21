"""In-memory ring buffer of recent HTTP requests for Step 4 (`traffic.live`)."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List

LOG: Deque[Dict[str, Any]] = deque(maxlen=5000)
_lock = threading.Lock()


def record(method: str, path: str, query: str, body_text: str, client: str) -> None:
    entry = {
        "ts": time.time(),
        "method": str(method),
        "path": str(path),
        "query": str(query or ""),
        "body": str(body_text or "")[:2000],
        "client": str(client or ""),
    }
    with _lock:
        LOG.append(entry)


def recent(window_minutes: int) -> List[Dict[str, Any]]:
    cutoff = time.time() - (max(window_minutes, 0) * 60.0)
    with _lock:
        return [dict(item) for item in LOG if item["ts"] >= cutoff]
