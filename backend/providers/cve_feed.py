"""Step 2: which published CVEs affect these exact package versions?

Returns every CVE that affects the installed versions. The scan decides which
ones are "new" by comparing ids against what the merchant has acknowledged, so
this provider must not filter by date.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from typing import Any, Dict, List, Set, Tuple
import urllib.error
import urllib.request

from ..schemas import Cve, Package
from . import fixtures

_VALID_SEVERITIES = {"LOW", "MODERATE", "HIGH", "CRITICAL"}


def _post_json(url: str, body: Dict[str, Any]) -> Dict[str, Any]:
    from . import ProviderError

    payload = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Dropshielder/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            if resp.status != 200:
                raise ProviderError(f"OSV returned HTTP {resp.status}")
            data = json.loads(resp.read().decode("utf-8"))
    except ProviderError:
        raise
    except urllib.error.HTTPError as exc:
        raise ProviderError(f"OSV returned HTTP {exc.code}") from exc
    except Exception as exc:
        raise ProviderError(f"OSV batch query failed: {exc}") from exc
    if not isinstance(data, dict):
        raise ProviderError("OSV returned invalid batch payload")
    return data


def _get_json(url: str) -> Dict[str, Any]:
    from . import ProviderError

    req = urllib.request.Request(url, headers={"User-Agent": "Dropshielder/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            if resp.status != 200:
                raise ProviderError(f"OSV detail returned HTTP {resp.status}")
            data = json.loads(resp.read().decode("utf-8"))
    except ProviderError:
        raise
    except urllib.error.HTTPError as exc:
        raise ProviderError(f"OSV detail returned HTTP {exc.code}") from exc
    except Exception as exc:
        raise ProviderError(f"OSV detail fetch failed: {exc}") from exc
    if not isinstance(data, dict):
        raise ProviderError("OSV returned invalid detail payload")
    return data


def _build_cve(osv_id: str, pkg_name: str, pkg_ver: str, detail: Dict[str, Any]) -> Cve:
    aliases = detail.get("aliases")
    cve_alias = ""
    if isinstance(aliases, list):
        for a in aliases:
            if isinstance(a, str) and a.startswith("CVE-"):
                cve_alias = a
                break
    cid = cve_alias if cve_alias else osv_id

    raw_summary = detail.get("summary")
    if not isinstance(raw_summary, str) or not raw_summary.strip():
        raw_details = detail.get("details")
        raw_summary = raw_details[:160] if isinstance(raw_details, str) else ""
    summary = raw_summary.strip()[:160]

    pub_raw = detail.get("published")
    published = pub_raw[:10] if isinstance(pub_raw, str) else ""

    db_spec = detail.get("database_specific")
    sev_raw = db_spec.get("severity") if isinstance(db_spec, dict) else None
    sev_up = str(sev_raw).upper() if isinstance(sev_raw, str) else ""
    severity = sev_up if sev_up in _VALID_SEVERITIES else "MODERATE"

    fixed_version = ""
    affected = detail.get("affected")
    if isinstance(affected, list):
        for aff in affected:
            if not isinstance(aff, dict):
                continue
            aff_pkg = aff.get("package")
            if isinstance(aff_pkg, dict) and aff_pkg.get("name") == pkg_name:
                ranges = aff.get("ranges")
                if isinstance(ranges, list):
                    for rng in ranges:
                        events = rng.get("events") if isinstance(rng, dict) else None
                        if isinstance(events, list):
                            for ev in events:
                                if isinstance(ev, dict) and ev.get("fixed") and not fixed_version:
                                    fixed_version = str(ev["fixed"])

    url = (
        f"https://nvd.nist.gov/vuln/detail/{cid}"
        if cid.startswith("CVE-")
        else f"https://osv.dev/vulnerability/{osv_id}"
    )

    return {
        "id": cid,
        "package": pkg_name,
        "version": pkg_ver,
        "severity": severity,
        "summary": summary,
        "published": published,
        "fixed_version": fixed_version,
        "url": url,
    }


def mock(scenario: str, packages: List[Package]) -> List[Cve]:
    if scenario == "feed_down":
        from . import ProviderError

        raise ProviderError("CVE feed timed out (mock failure)")
    return [dict(c) for c in fixtures.CVES_BY_SCENARIO.get(scenario, [])]  # type: ignore[misc]


def live(scenario: str, packages: List[Package]) -> List[Cve]:
    from . import ProviderError

    if not packages:
        return []

    queries = [
        {"package": {"name": p["name"], "ecosystem": "npm"}, "version": p["version"]}
        for p in packages
    ]
    batch = _post_json("https://api.osv.dev/v1/querybatch", {"queries": queries})
    results = batch.get("results")
    if not isinstance(results, list) or len(results) != len(packages):
        raise ProviderError("OSV batch result count did not match queried packages")

    to_fetch: List[Tuple[str, str, str]] = []
    for pkg, res in zip(packages, results):
        vulns = res.get("vulns") if isinstance(res, dict) else None
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            vid = v.get("id") if isinstance(v, dict) else None
            if isinstance(vid, str) and vid:
                to_fetch.append((vid, pkg["name"], pkg["version"]))
                if len(to_fetch) >= 25:
                    break
        if len(to_fetch) >= 25:
            break

    if not to_fetch:
        return []

    unique_ids = list(dict.fromkeys(vid for vid, _, _ in to_fetch))
    with ThreadPoolExecutor(max_workers=8) as pool:
        details_list = list(pool.map(lambda vid: _get_json(f"https://api.osv.dev/v1/vulns/{vid}"), unique_ids))
    detail_by_id = dict(zip(unique_ids, details_list))

    out: List[Cve] = []
    seen: Set[Tuple[str, str]] = set()
    for vid, pkg_name, pkg_ver in to_fetch:
        cve = _build_cve(vid, pkg_name, pkg_ver, detail_by_id[vid])
        key = (cve["id"], cve["package"])
        if key not in seen:
            seen.add(key)
            out.append(cve)
    return out
