"""Step 1: what software is this page running?

Returns the packages (name + exact version) the storefront depends on.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from pathlib import Path
from typing import Dict, List, Set, Tuple

from ..schemas import Package
from . import fixtures

_EXACT_VER_RE = re.compile(r"^\d+\.\d+\.\d+")
_TAG_URL_RE = re.compile(
    r"<(?:script[^>]+src|link[^>]+href)=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_CDNJS_RE = re.compile(
    r"cdnjs\.cloudflare\.com/ajax/libs/([a-zA-Z0-9._-]+)/(\d+\.\d+\.\d+[a-zA-Z0-9.-]*)/",
    re.IGNORECASE,
)
_JSDELIVR_RE = re.compile(
    r"cdn\.jsdelivr\.net/npm/(@?[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)?)@(\d+\.\d+\.\d+[a-zA-Z0-9.-]*)",
    re.IGNORECASE,
)
_UNPKG_RE = re.compile(
    r"unpkg\.com/(@?[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)?)@(\d+\.\d+\.\d+[a-zA-Z0-9.-]*)",
    re.IGNORECASE,
)

_CDN_NAME_MAP: Dict[str, str] = {
    "lodash.js": "lodash",
    "twitter-bootstrap": "bootstrap",
    "handlebars.js": "handlebars",
    "angular.js": "angular",
    "angularjs": "angular",
    "moment.js": "moment",
    "underscore.js": "underscore",
    "mustache.js": "mustache",
    "backbone.js": "backbone",
    "three.js": "three",
    "socket.io": "socket.io-client",
}


def _normalize_cdn_name(raw: str) -> str:
    low = raw.strip().lower()
    if low in _CDN_NAME_MAP:
        return _CDN_NAME_MAP[low]
    if low.endswith(".js") and low[:-3] in _CDN_NAME_MAP:
        return _CDN_NAME_MAP[low[:-3]]
    return low


def _fetch_page(page_url: str) -> str:
    req = urllib.request.Request(
        page_url,
        headers={"User-Agent": "Dropshielder/1.0"},
    )
    with urllib.request.urlopen(req, timeout=6) as resp:
        return resp.read(250_000).decode("utf-8", errors="replace")


def mock(scenario: str, page_url: str) -> List[Package]:
    return [dict(p) for p in fixtures.PACKAGES]  # type: ignore[misc]


def live(scenario: str, page_url: str) -> List[Package]:
    from . import ProviderError

    pkg_path_raw = os.environ.get("DROPSHIELDER_PACKAGE_JSON", "").strip()
    if not pkg_path_raw:
        raise ProviderError("DROPSHIELDER_PACKAGE_JSON is not set or missing")
    pkg_path = Path(pkg_path_raw)
    if not pkg_path.is_file():
        raise ProviderError("DROPSHIELDER_PACKAGE_JSON is not set or missing")

    try:
        parsed = json.loads(pkg_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ProviderError(f"Cannot parse package.json: {exc}") from exc

    deps = parsed.get("dependencies")
    if not isinstance(deps, dict):
        deps = {}

    results: List[Package] = []
    seen: Set[Tuple[str, str]] = set()

    def _add(name: str, version: str, source: str) -> None:
        cleaned = str(version).lstrip("^~>=< ").strip()
        if not name or not _EXACT_VER_RE.match(cleaned):
            return
        key = (name, cleaned)
        if key not in seen:
            seen.add(key)
            results.append({"name": name, "version": cleaned, "source": source})

    for raw_name, raw_ver in deps.items():
        _add(str(raw_name).strip(), str(raw_ver), "package.json")

    if page_url:
        try:
            html = _fetch_page(page_url)
            for asset_url in _TAG_URL_RE.findall(html):
                for m in _CDNJS_RE.finditer(asset_url):
                    _add(_normalize_cdn_name(m.group(1)), m.group(2), "<script src> on product page")
                for m in _JSDELIVR_RE.finditer(asset_url):
                    _add(_normalize_cdn_name(m.group(1)), m.group(2), "<script src> on product page")
                for m in _UNPKG_RE.finditer(asset_url):
                    _add(_normalize_cdn_name(m.group(1)), m.group(2), "<script src> on product page")
        except Exception:
            # Per Task 1: if fetching the page fails, do not raise; package.json list is still useful.
            pass

    return results
