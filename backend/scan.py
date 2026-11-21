"""The scan: runs the steps in order and reports progress as it goes.

`run_scan` is a generator. It yields ("step", Step) twice per step (running,
then done/skipped/failed) and finally ("report", Report). The server forwards
each yield to the webpage as a server-sent event.

A failed step never stops the scan. Later steps run on whatever evidence
exists, and the verdict policy refuses to say SAFE when anything failed.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Tuple

from . import providers, verdict
from .schemas import Report, Step

TRAFFIC_WINDOW_MINUTES = 60


class Skip(Exception):
    """Raised by a step that has nothing to do; the message is shown on the page."""


def _inventory(st: Dict[str, Any]) -> Tuple[str, Any]:
    st["packages"], _ = providers.call("inventory", st["scenario"], st["page_url"], force_mock=st["force_mock"])
    return f"{len(st['packages'])} packages found.", st["packages"]


def _cve_feed(st: Dict[str, Any]) -> Tuple[str, Any]:
    if not st["packages"]:
        raise Skip("No package list to check.")
    cves, _ = providers.call("cve_feed", st["scenario"], st["packages"], force_mock=st["force_mock"])
    for c in cves:
        c["is_new"] = c["id"] not in st["acknowledged"]
        c["known_exploited"] = False
        c["reachable"] = None
    st["cves"] = cves
    st["new_cves"] = [c for c in cves if c["is_new"]]
    return f"{len(cves)} CVE(s) affect these versions, {len(st['new_cves'])} new.", cves


def _known_exploited(st: Dict[str, Any]) -> Tuple[str, Any]:
    if not st["new_cves"]:
        raise Skip("No new CVEs to look up.")
    ids = [c["id"] for c in st["new_cves"]]
    listed, _ = providers.call("known_exploited", st["scenario"], ids, force_mock=st["force_mock"])
    for c in st["new_cves"]:
        c["known_exploited"] = c["id"] in listed
    return (
        f"{len(listed)} of {len(ids)} listed as exploited in the wild."
        if listed
        else "None listed as exploited in the wild."
    ), listed


def _traffic(st: Dict[str, Any]) -> Tuple[str, Any]:
    st["signals"], _ = providers.call(
        "traffic", st["scenario"], st["cves"], TRAFFIC_WINDOW_MINUTES, force_mock=st["force_mock"]
    )
    n = len(st["signals"])
    return (
        f"{n} attack signal(s) in the last {TRAFFIC_WINDOW_MINUTES} minutes."
        if n
        else f"No attack signals in the last {TRAFFIC_WINDOW_MINUTES} minutes."
    ), st["signals"]


def _advisory_reader(st: Dict[str, Any]) -> Tuple[str, Any]:
    if not st["new_cves"]:
        raise Skip("No new advisories to read.")
    snapshot = [dict(c) for c in st["new_cves"]]
    notes, _ = providers.call("advisory_reader", st["scenario"], snapshot, force_mock=st["force_mock"])
    for c in st["new_cves"]:
        c.update(notes.get(c["id"], {}))
    return f"Read {len(notes)} advisory(ies).", notes


def _exposure_analyst(st: Dict[str, Any]) -> Tuple[str, Any]:
    if not st["new_cves"]:
        raise Skip("No new CVEs to trace.")
    snapshot = [dict(c) for c in st["new_cves"]]
    notes, _ = providers.call(
        "exposure_analyst", st["scenario"], snapshot, st["packages"], force_mock=st["force_mock"]
    )
    for c in st["new_cves"]:
        c.update(notes.get(c["id"], {}))
    reachable = sum(1 for c in st["new_cves"] if c.get("reachable") is True)
    return f"{reachable} of {len(st['new_cves'])} new CVE(s) reachable from a web route.", notes


def _decision_gate(st: Dict[str, Any]) -> Tuple[str, Any]:
    if not st["new_cves"] and not st["signals"]:
        raise Skip("Nothing to judge.")
    st["decision"], _ = providers.call(
        "decision_gate", st["scenario"], st["new_cves"], st["signals"], force_mock=st["force_mock"]
    )
    d = st["decision"]
    return f"Exploitation likelihood {d['exploitation_likely']:.2f}, risk {d['risk_score']}/4.", d


# (provider id, question shown on the page, function)
STEPS: List[Tuple[str, str, Callable[[Dict[str, Any]], Tuple[str, Any]]]] = [
    ("inventory", "What is this page running?", _inventory),
    ("cve_feed", "Any new CVEs for those versions?", _cve_feed),
    ("known_exploited", "Is anyone exploiting them in the wild?", _known_exploited),
    ("traffic", "Any signs of exploitation in our own traffic?", _traffic),
    ("advisory_reader", "What do the new advisories mean?", _advisory_reader),
    ("exposure_analyst", "Can a request actually reach the flaw?", _exposure_analyst),
    ("decision_gate", "How risky is this checkout, all things considered?", _decision_gate),
]


def _execute_step_isolated(
    step_id: str,
    title: str,
    source: str,
    fn: Callable[[Dict[str, Any]], Tuple[str, Any]],
    st: Dict[str, Any],
) -> Tuple[Step, bool]:
    t0 = time.perf_counter()
    step: Step = {"id": step_id, "title": title, "source": source}
    did_fail = False
    try:
        step["summary"], step["data"] = fn(st)
        step["status"] = "done"
    except Skip as skip:
        step["status"], step["summary"] = "skipped", str(skip)
    except Exception as exc:
        step["status"], step["summary"] = "failed", f"{type(exc).__name__}: {exc}"
        did_fail = True
    step["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return step, did_fail


def run_scan(
    order_id: str,
    page_url: str,
    scenario: str,
    acknowledged: set,
    step_delay: float = 0.0,
    force_mock: bool = False,
) -> Iterator[Tuple[str, Dict[str, Any]]]:
    st: Dict[str, Any] = {
        "scenario": scenario,
        "page_url": page_url,
        "acknowledged": set(acknowledged),
        "force_mock": force_mock,
        "packages": [],
        "cves": [],
        "new_cves": [],
        "signals": [],
        "decision": None,
    }
    steps: List[Step] = []
    failed: List[str] = []

    use_parallel_pairs = (not force_mock) and (
        providers.source_of("advisory_reader") == "live"
        or providers.source_of("exposure_analyst") == "live"
    )

    idx = 0
    while idx < len(STEPS):
        step_id, title, fn = STEPS[idx]

        # Run independent pairs (known_exploited + traffic) or (advisory_reader + exposure_analyst) concurrently in live mode
        if use_parallel_pairs and step_id in ("known_exploited", "advisory_reader") and idx + 1 < len(STEPS):
            step2_id, title2, fn2 = STEPS[idx + 1]
            src1 = providers.source_of(step_id, force_mock=force_mock)
            src2 = providers.source_of(step2_id, force_mock=force_mock)
            yield "step", {"id": step_id, "title": title, "status": "running", "source": src1}

            # Run both steps concurrently on isolated state views, then reconcile cleanly
            st1 = {**st, "new_cves": [dict(c) for c in st["new_cves"]]}
            st2 = {**st, "new_cves": [dict(c) for c in st["new_cves"]]}
            with ThreadPoolExecutor(max_workers=2) as pool:
                f1 = pool.submit(_execute_step_isolated, step_id, title, src1, fn, st1)
                f2 = pool.submit(_execute_step_isolated, step2_id, title2, src2, fn2, st2)
                s1, fail1 = f1.result()
                s2, fail2 = f2.result()

            # Reconcile state updates in deterministic 1 -> 2 order
            if step_id == "known_exploited":
                if s1.get("status") == "done" and isinstance(s1.get("data"), list):
                    listed = set(s1["data"])
                    for c in st["new_cves"]:
                        c["known_exploited"] = c["id"] in listed
                if s2.get("status") == "done":
                    st["signals"] = st2["signals"]
            else:
                if s1.get("status") == "done" and isinstance(s1.get("data"), dict):
                    for c in st["new_cves"]:
                        c.update(s1["data"].get(c["id"], {}))
                if s2.get("status") == "done" and isinstance(s2.get("data"), dict):
                    for c in st["new_cves"]:
                        c.update(s2["data"].get(c["id"], {}))

            if fail1:
                failed.append(step_id)
            steps.append(s1)
            yield "step", dict(s1)

            yield "step", {"id": step2_id, "title": title2, "status": "running", "source": src2}
            if fail2:
                failed.append(step2_id)
            steps.append(s2)
            yield "step", dict(s2)
            idx += 2
            continue

        source = providers.source_of(step_id, force_mock=force_mock)
        yield "step", {"id": step_id, "title": title, "status": "running", "source": source}
        if step_delay:
            time.sleep(step_delay)
        step, did_fail = _execute_step_isolated(step_id, title, source, fn, st)
        if did_fail:
            failed.append(step_id)
        steps.append(step)
        yield "step", dict(step)
        idx += 1

    v, headline, reasons = verdict.decide(st["new_cves"], st["signals"], st["decision"], failed)
    report: Report = {
        "order_id": order_id,
        "verdict": v,
        "headline": headline,
        "reasons": reasons,
        "incomplete": bool(failed),
        "failed_steps": failed,
        "mock_steps": [s["id"] for s in steps if s["source"] == "mock"],
        "packages": st["packages"],
        "cves": st["cves"],
        "new_cves": st["new_cves"],
        "signals": st["signals"],
        "decision": st["decision"],
        "steps": steps,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    yield "report", dict(report)
