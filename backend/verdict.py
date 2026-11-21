"""The verdict policy. Plain rules, no model calls, no I/O.

Models and feeds supply evidence; this file alone decides SAFE / CAUTION / HOLD.
Keeping it deterministic means every verdict can be explained and unit-tested.

  HOLD     order is held for the merchant (never cancelled)
  CAUTION  order completes, merchant is told to look
  SAFE     order completes
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from .schemas import Cve, Decision, Signal

STRONG_SIGNAL = 0.80        # traffic signal confidence at or above this holds the order
GATE_HOLD_RISK = 3          # decision gate risk score at or above this holds the order...
GATE_HOLD_CONFIDENCE = 0.70  # ...but only if the gate is at least this confident
GATE_CAUTION_RISK = 2

HEADLINES = {
    "SAFE": "No new CVEs and no signs of exploitation. Purchase completed.",
    "CAUTION": "Purchase completed, but the merchant should look at this.",
    "HOLD": "Order held for merchant review. Nothing was cancelled.",
}


def decide(
    new_cves: List[Cve],
    signals: List[Signal],
    decision: Optional[Decision],
    failed_steps: List[str],
) -> Tuple[str, str, List[str]]:
    """Returns (verdict, headline, reasons)."""
    hold: List[str] = []
    caution: List[str] = []
    notes: List[str] = []

    for s in signals:
        line = f"{s['count']} {s['kind']} request(s) on {s['path']} (confidence {s['confidence']:.2f})"
        if s["confidence"] >= STRONG_SIGNAL:
            hold.append(f"Attack traffic: {line}.")
        else:
            caution.append(f"Suspicious traffic: {line}.")

    for c in new_cves:
        label = f"{c['id']} in {c['package']}@{c['version']}"
        reachable = c.get("reachable")
        if reachable is False:
            notes.append(f"New {label}, but no web route reaches it.")
        elif c.get("known_exploited"):
            hold.append(f"New {label} is reachable and is being exploited in the wild.")
        elif reachable is True:
            caution.append(f"New {label} is reachable from {', '.join(c.get('routes') or ['a web route'])}.")
        else:
            caution.append(f"New {label}; reachability was not assessed.")

    if decision:
        risk, conf = decision["risk_score"], decision["confidence"]
        line = f"Decision gate risk {risk}/4 (confidence {conf:.2f}): {decision['rationale']}"
        if risk >= GATE_HOLD_RISK and conf >= GATE_HOLD_CONFIDENCE:
            hold.append(line)
        elif risk >= GATE_CAUTION_RISK:
            caution.append(line)

    if failed_steps:
        caution.append(f"Scan incomplete: {', '.join(failed_steps)} failed, so this page cannot be called safe.")

    if hold:
        verdict = "HOLD"
    elif caution:
        verdict = "CAUTION"
    else:
        verdict = "SAFE"
    return verdict, HEADLINES[verdict], hold + caution + notes
