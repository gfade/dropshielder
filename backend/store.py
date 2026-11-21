"""The sticker shop: catalog, orders and the merchant's acknowledged-CVE list.

Supports both:
  1. Demo catalog (`PRODUCTS` — 5 $0.50 digital stickers with instant local `.jpg` download)
  2. Real Shopify Storefront products (`shopify_product` passed to `create_order` — minting
     a genuine live Shopify / Shop Pay `checkout_url` once the scan passes or is released!)

Order status:
  AWAITING_SCAN  bought with the scan add-on, scan not finished
  COMPLETED      download / real Shopify checkout unlocked
  HELD           scan said HOLD; waits for the merchant, never auto-cancelled
  REFUNDED       merchant refunded a held order
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional
import uuid

from .providers import fixtures

SCAN_ADDON_CENTS = 50

PRODUCTS = [
    {"id": "corgi", "title": "Cosmic Corgi", "price_cents": 50, "image": "corgi.jpg"},
    {"id": "matcha-cat", "title": "Matcha Latte Cat", "price_cents": 50, "image": "matcha-cat.jpg"},
    {"id": "ramen", "title": "Tokyo Ramen Bowl", "price_cents": 50, "image": "ramen.jpg"},
    {"id": "dino", "title": "Drop Table Dino", "price_cents": 50, "image": "dino.jpg"},
    {"id": "frog", "title": "Terrarium Frog", "price_cents": 50, "image": "frog.jpg"},
]

_DATA_DIR = Path(os.environ.get("DROPSHIELDER_DATA_DIR", str(Path(__file__).resolve().parent.parent / "data")))
_ACK_FILE = _DATA_DIR / "acknowledged.json"


def _load_initial_acknowledged() -> set:
    if _ACK_FILE.is_file():
        try:
            items = json.loads(_ACK_FILE.read_text(encoding="utf-8"))
            if isinstance(items, list):
                return {str(i) for i in items}
        except (OSError, ValueError):
            pass
    return set(fixtures.SEED_ACKNOWLEDGED)


_lock = threading.Lock()
ORDERS: Dict[str, Dict[str, Any]] = {}
ACKNOWLEDGED: set = _load_initial_acknowledged()


def product(product_id: str) -> Optional[Dict[str, Any]]:
    return next((p for p in PRODUCTS if p["id"] == product_id), None)


def create_order(
    product_id: str,
    buyer_name: str,
    want_scan: bool,
    scenario: str,
    *,
    shopify_item: Optional[Dict[str, Any]] = None,
    force_mock: bool = False,
) -> Dict[str, Any]:
    if shopify_item is not None:
        prod = {
            "id": shopify_item["id"],
            "title": shopify_item["title"],
            "price_cents": int(shopify_item["price_cents"]),
            "image": "",
            "image_url": shopify_item.get("image_url", ""),
            "variant_id": shopify_item["variant_id"],
            "product_url": shopify_item.get("product_url", ""),
            "shop_domain": shopify_item.get("shop_domain", ""),
        }
    else:
        prod = product(product_id)
        if not prod:
            raise ValueError(f"Unknown product: {product_id}")

    if scenario not in fixtures.SCENARIOS:
        scenario = "clean"

    order = {
        "order_id": f"ord_{uuid.uuid4().hex[:10]}",
        "product": prod,
        "buyer_name": (buyer_name or "").strip()[:80] or "Guest",
        "want_scan": bool(want_scan),
        "scenario": scenario,
        "force_mock": bool(force_mock),
        "checkout_mode": "shopify" if shopify_item is not None else "demo",
        "shopify_checkout": None,
        "total_cents": prod["price_cents"] + (SCAN_ADDON_CENTS if want_scan else 0),
        "status": "AWAITING_SCAN" if want_scan else "COMPLETED",
        "scan_started": False,
        "report": None,
    }
    with _lock:
        ORDERS[order["order_id"]] = order
    return order


def claim_scan(order: Dict[str, Any]) -> bool:
    """Marks the scan as started. Returns False if it had already started."""
    with _lock:
        if order["scan_started"]:
            return False
        order["scan_started"] = True
        return True


def apply_report(order: Dict[str, Any], report: Dict[str, Any]) -> None:
    with _lock:
        order["report"] = report
        order["status"] = "HELD" if report["verdict"] == "HOLD" else "COMPLETED"


def resolve(order: Dict[str, Any], action: str) -> None:
    """Merchant decision on a held order: 'release' or 'refund'."""
    if order["status"] != "HELD":
        raise ValueError("Only held orders can be resolved.")
    if action not in ("release", "refund"):
        raise ValueError("action must be 'release' or 'refund'.")
    with _lock:
        order["status"] = "COMPLETED" if action == "release" else "REFUNDED"


def acknowledge(cve_ids: List[Any]) -> List[str]:
    """Merchant has reviewed these CVEs; they stop counting as new (persisted to disk)."""
    with _lock:
        ACKNOWLEDGED.update(str(i) for i in cve_ids)
        sorted_ids = sorted(ACKNOWLEDGED)
        try:
            _ACK_FILE.parent.mkdir(parents=True, exist_ok=True)
            _ACK_FILE.write_text(json.dumps(sorted_ids, indent=2), encoding="utf-8")
        except OSError:
            pass
        return sorted_ids


def public(order: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in order.items() if k not in ("scan_started", "force_mock")}
    if order["status"] == "COMPLETED":
        if order.get("checkout_mode") == "shopify":
            out["download_url"] = None
            chk = order.get("shopify_checkout") or {}
            out["shopify_checkout_url"] = chk.get("checkout_url")
            out["shopify_web_checkout_url"] = chk.get("web_checkout_url")
        else:
            out["download_url"] = f"/api/orders/{order['order_id']}/download"
            out["shopify_checkout_url"] = None
    else:
        out["download_url"] = None
        out["shopify_checkout_url"] = None
    return out
