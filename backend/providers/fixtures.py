"""Canned data for the mock providers.

Everything here is invented and labelled MOCK so nobody mistakes it for a real
advisory. Package names and CVE ids are deliberately fake.
"""

from __future__ import annotations

SCENARIOS = {
    "clean": "Clean: nothing new, no attack traffic",
    "new_cve": "New CVE published, not exploited yet",
    "exploited": "New CVE and attack traffic on our store",
    "feed_down": "CVE feed is unreachable",
}

PACKAGES = [
    {"name": "mock-template-engine", "version": "2.1.0", "source": "package.json"},
    {"name": "mock-query-builder", "version": "0.9.4", "source": "package.json"},
    {"name": "mock-xml-tool", "version": "0.4.2", "source": "package.json"},
    {"name": "mock-ui-kit", "version": "3.4.1", "source": "<script src> on product page"},
]

OLD_CVE = {
    "id": "MOCK-CVE-2024-0001",
    "package": "mock-ui-kit",
    "version": "3.4.1",
    "severity": "MODERATE",
    "summary": "Tooltip option allows script injection (mock record).",
    "published": "2024-07-11",
    "fixed_version": "3.4.2",
    "url": "https://example.invalid/MOCK-CVE-2024-0001",
}

NEW_REACHABLE_CVE = {
    "id": "MOCK-CVE-2026-0002",
    "package": "mock-template-engine",
    "version": "2.1.0",
    "severity": "HIGH",
    "summary": "Template name is joined to a file path without rejecting ../ (mock record).",
    "published": "2026-11-19",
    "fixed_version": "2.1.1",
    "url": "https://example.invalid/MOCK-CVE-2026-0002",
}

NEW_UNREACHABLE_CVE = {
    "id": "MOCK-CVE-2026-0003",
    "package": "mock-xml-tool",
    "version": "0.4.2",
    "severity": "MODERATE",
    "summary": "Prototype pollution when parsing crafted XML (mock record).",
    "published": "2026-11-20",
    "fixed_version": "0.5.0",
    "url": "https://example.invalid/MOCK-CVE-2026-0003",
}

# Ids the merchant has already reviewed. Anything not in here counts as "new".
SEED_ACKNOWLEDGED = ["MOCK-CVE-2024-0001"]

CVES_BY_SCENARIO = {
    "clean": [OLD_CVE],
    "new_cve": [OLD_CVE, NEW_REACHABLE_CVE, NEW_UNREACHABLE_CVE],
    "exploited": [OLD_CVE, NEW_REACHABLE_CVE, NEW_UNREACHABLE_CVE],
}

KNOWN_EXPLOITED_BY_SCENARIO = {
    "exploited": ["MOCK-CVE-2026-0002"],
}

SIGNALS_BY_SCENARIO = {
    "exploited": [
        {
            "kind": "path_traversal",
            "path": "/apps/size-chart",
            "sample": "template=%252e%252e%252f%252e%252e%252f.env",
            "count": 14,
            "first_seen": "2026-11-21T15:02:11Z",
            "last_seen": "2026-11-21T15:02:13Z",
            "matched_cve": "MOCK-CVE-2026-0002",
            "confidence": 0.94,
        }
    ],
}

ADVISORY_NOTES = {
    "MOCK-CVE-2026-0002": {
        "plain_summary": "Anyone who can choose the template name can read files outside the template folder.",
        "attack_shape": "../ sequences (often double URL-encoded) in the template query parameter",
    },
    "MOCK-CVE-2026-0003": {
        "plain_summary": "A crafted XML file can change default object properties in the process that parses it.",
        "attack_shape": "XML with a __proto__ element",
    },
}

EXPOSURE_NOTES = {
    "MOCK-CVE-2026-0002": {
        "reachable": True,
        "routes": ["GET /apps/size-chart"],
        "why": "The size-chart route passes the template query parameter straight to the engine.",
    },
    "MOCK-CVE-2026-0003": {
        "reachable": False,
        "routes": [],
        "why": "Only an offline invoice script imports this package; no web route does.",
    },
}

DECISION_BY_SCENARIO = {
    "new_cve": {
        "exploitation_likely": 0.18,
        "confidence": 0.82,
        "risk_score": 2,
        "rationale": "A reachable flaw is unpatched, but nothing in our traffic targets it.",
    },
    "exploited": {
        "exploitation_likely": 0.96,
        "confidence": 0.91,
        "risk_score": 4,
        "rationale": "Scripted traversal attempts are hitting the exact route the new CVE affects.",
    },
}
