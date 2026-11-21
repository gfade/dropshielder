"""Provider registry: decides, per provider, whether to run mock or live code.

Every provider module exposes two functions with the same arguments and the
same return shape:

    mock(scenario, ...)   canned data, works offline
    live(scenario, ...)   real API call (ignores `scenario`)

Turn a provider live with the DROPSHIELDER_LIVE environment variable, a
comma-separated list of provider names:

    DROPSHIELDER_LIVE=cve_feed,known_exploited

There is deliberately no fallback from live to mock. If a live provider
raises, the step is marked failed and the verdict cannot be SAFE.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Tuple

from . import advisory_reader, cve_feed, decision_gate, exposure_analyst, inventory, known_exploited, traffic

PROVIDERS = {
    "inventory": inventory,
    "cve_feed": cve_feed,
    "known_exploited": known_exploited,
    "traffic": traffic,
    "advisory_reader": advisory_reader,
    "exposure_analyst": exposure_analyst,
    "decision_gate": decision_gate,
}


class ProviderError(RuntimeError):
    """Raise this from a provider when the data source cannot be reached or trusted."""


def live_names() -> set:
    raw = os.environ.get("DROPSHIELDER_LIVE", "").strip()
    if raw.lower() == "all":
        return set(PROVIDERS)
    names = {n.strip() for n in raw.split(",") if n.strip()}
    unknown = names - set(PROVIDERS)
    if unknown:
        raise ValueError(f"DROPSHIELDER_LIVE names unknown providers: {sorted(unknown)}")
    return names


def source_of(name: str, force_mock: bool = False) -> str:
    if force_mock:
        return "mock"
    return "live" if name in live_names() else "mock"


def call(name: str, scenario: str, *args: Any, force_mock: bool = False) -> Tuple[Any, str]:
    """Run provider `name`. Returns (result, "mock" | "live")."""
    module = PROVIDERS[name]
    source = source_of(name, force_mock=force_mock)
    fn: Callable[..., Any] = module.live if source == "live" else module.mock
    return fn(scenario, *args), source
