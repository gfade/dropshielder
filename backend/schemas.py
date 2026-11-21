"""The data shapes every part of Dropshielder agrees on.

These are the contract between providers, the scan, the verdict policy and the
webpage. Providers must return exactly these shapes. Do not rename or remove
keys: the frontend and the tests read them by name.
"""

from __future__ import annotations

from typing import Dict, List, Optional, TypedDict


class Package(TypedDict):
    name: str          # npm package name, e.g. "lodash"
    version: str       # exact version, e.g. "4.17.21" (no ^ or ~)
    source: str        # where we saw it, e.g. "package.json" or "<script src> on product page"


class Cve(TypedDict, total=False):
    # Set by the cve_feed provider:
    id: str                # "CVE-2026-1234" (prefer the CVE alias over a GHSA id)
    package: str
    version: str           # the installed version that is affected
    severity: str          # "LOW" | "MODERATE" | "HIGH" | "CRITICAL"
    summary: str           # one line from the advisory
    published: str         # ISO date, "2026-11-19"
    fixed_version: str     # "" if no fix is published
    url: str               # link to the advisory
    # Set by the scan, not by the provider:
    is_new: bool           # True if the merchant has not acknowledged this id
    known_exploited: bool  # True if the known_exploited provider lists it
    plain_summary: str     # from advisory_reader
    attack_shape: str      # from advisory_reader, e.g. "../ in the template query parameter"
    reachable: Optional[bool]  # from exposure_analyst; None means "not assessed"
    routes: List[str]      # from exposure_analyst, e.g. ["GET /apps/size-chart"]
    why: str               # from exposure_analyst, one sentence


class Signal(TypedDict):
    kind: str              # "path_traversal" | "sqli" | "card_testing" | "discount_bruteforce" | "other"
    path: str              # route that was hit
    sample: str            # one example payload, truncated to 200 chars
    count: int             # how many matching requests in the window
    first_seen: str        # ISO timestamp
    last_seen: str         # ISO timestamp
    matched_cve: Optional[str]  # CVE id this looks like an attempt on, or None
    confidence: float      # 0..1, how sure we are this is an attack and not a shopper


class Decision(TypedDict):
    exploitation_likely: float  # 0..1 calibrated probability
    confidence: float           # 0..1, the gate's own confidence in its answers
    risk_score: int             # 0 normal .. 4 confirmed abuse
    rationale: str              # one sentence


class Step(TypedDict, total=False):
    id: str            # provider/step id, see scan.STEPS
    title: str         # question shown on the webpage
    status: str        # "running" | "done" | "skipped" | "failed"
    source: str        # "mock" | "live"
    summary: str       # one line result shown on the webpage
    data: object       # step-specific detail (list or dict), optional
    elapsed_ms: float


class Report(TypedDict):
    order_id: str
    verdict: str           # "SAFE" | "CAUTION" | "HOLD"
    headline: str
    reasons: List[str]
    incomplete: bool       # True if any step failed
    failed_steps: List[str]
    mock_steps: List[str]  # ids of steps that ran on mock data
    packages: List[Package]
    cves: List[Cve]        # everything found, new or not
    new_cves: List[Cve]
    signals: List[Signal]
    decision: Optional[Decision]
    steps: List[Step]
    scanned_at: str


AdvisoryNotes = Dict[str, Dict[str, str]]     # cve_id -> {"plain_summary", "attack_shape"}
ExposureNotes = Dict[str, Dict[str, object]]  # cve_id -> {"reachable", "routes", "why"}
