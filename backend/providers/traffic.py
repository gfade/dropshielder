"""Step 4: does our own recent traffic show signs of exploitation?

Looks at recent requests to the store and returns attack signals. This step
does not depend on the CVE feed: it must still work when the feed is down.
`cves` is passed only so a signal can name the CVE it looks like.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .. import requestlog
from ..normalizer import normalize_input_twice
from ..schemas import Cve, Signal
from . import fixtures


def _iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _match_cve_for_kind(kind: str, cves: List[Cve]) -> Optional[str]:
    needles = ("travers", "../") if kind == "path_traversal" else ("sql", "inject")
    for c in cves:
        hay = f"{c.get('attack_shape', '')} {c.get('summary', '')}".lower()
        if any(n in hay for n in needles):
            return c["id"]
    return None


def mock(scenario: str, cves: List[Cve], window_minutes: int) -> List[Signal]:
    return [dict(s) for s in fixtures.SIGNALS_BY_SCENARIO.get(scenario, [])]  # type: ignore[misc]


def live(scenario: str, cves: List[Cve], window_minutes: int) -> List[Signal]:
    entries = requestlog.recent(window_minutes)
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

    for entry in entries:
        combined = f"{entry.get('query', '')}&{entry.get('body', '')}"
        norm = normalize_input_twice(combined)
        if norm.has_traversal_structure:
            kind = "path_traversal"
        elif norm.has_sql_structure:
            kind = "sqli"
        else:
            continue
        key = (kind, str(entry.get("path", "/")))
        groups.setdefault(key, []).append(entry)

    signals: List[Signal] = []
    for (kind, path), hits in groups.items():
        count = len(hits)
        first_ts = min(float(h["ts"]) for h in hits)
        last_ts = max(float(h["ts"]) for h in hits)
        sample_raw = str(hits[0].get("query") or hits[0].get("body") or "")[:200]
        if count == 1:
            conf = 0.6
        elif count <= 4:
            conf = 0.85
        else:
            conf = 0.95

        signals.append(
            {
                "kind": kind,
                "path": path,
                "sample": sample_raw,
                "count": count,
                "first_seen": _iso_utc(first_ts),
                "last_seen": _iso_utc(last_ts),
                "matched_cve": _match_cve_for_kind(kind, cves),
                "confidence": conf,
            }
        )

    return signals
