"""Dropshielder web server. Standard library HTTP server.

Run from the dropshielder folder:

    python -m backend.server

Routes:
  GET  /                               live shop page (real Shopify checkout + live scan)
  GET  /demo                           interactive demo version (mock scenarios + $0.50 instant stickers)
  GET  /static/<file>                  frontend files
  GET  /api/config                     products, shopify catalog, scenarios, which providers are live
  GET  /api/shopify/products           real live Shopify sticker catalog
  POST /api/shopify/checkout           {order_id} or {variant_id, quantity} -> real Shopify/Shop Pay checkout URL
  POST /api/orders                     {product_id, buyer_name, want_scan, scenario, checkout_mode, variant_id}
  GET  /api/orders/<id>                order + report
  GET  /api/orders/<id>/scan           server-sent events: `step` ... then `report`
  POST /api/orders/<id>/resolve        {action: "release" | "refund"}  (merchant)
  POST /api/acknowledge                {cve_ids: [...]}                (merchant)
  GET  /api/orders/<id>/download       the sticker image, only when COMPLETED
"""

from __future__ import annotations

import json
import mimetypes
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from . import providers, requestlog, shopify, store
from .providers import fixtures
from .scan import STEPS, run_scan

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = (ROOT / "frontend").resolve()
ORDER_RE = re.compile(r"^/api/orders/(ord_[0-9a-f]{10})(/scan|/resolve|/download)?$")


def _load_dotenv_if_present() -> None:
    env_path = ROOT / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            if k.strip() and k.strip() not in os.environ and v.strip():
                os.environ[k.strip()] = v.strip()


_load_dotenv_if_present()

# Default bundled storefront paths if live providers are enabled and paths weren't explicitly set
if providers.live_names():
    bundled_storefront = ROOT / "storefront"
    if bundled_storefront.is_dir():
        os.environ.setdefault("DROPSHIELDER_STOREFRONT_DIR", str(bundled_storefront))
        if (bundled_storefront / "package.json").is_file():
            os.environ.setdefault("DROPSHIELDER_PACKAGE_JSON", str(bundled_storefront / "package.json"))


def step_delay(force_mock: bool = False) -> float:
    """Pause per step so mock scans are watchable. Set DROPSHIELDER_STEP_DELAY=0 to disable."""
    raw = os.environ.get("DROPSHIELDER_STEP_DELAY")
    if raw is not None:
        return float(raw)
    if not force_mock and providers.live_names():
        return 0.0
    return 0.5


def _attach_shopify_checkout_if_needed(order: Dict[str, Any]) -> None:
    if order.get("checkout_mode") != "shopify" or order.get("status") != "COMPLETED":
        return
    if order.get("shopify_checkout"):
        return
    vid = (order.get("product") or {}).get("variant_id", "")
    if vid:
        try:
            order["shopify_checkout"] = shopify.create_real_shopify_checkout(str(vid), 1)
        except Exception as exc:
            order["shopify_checkout"] = {"error": str(exc)}


class Handler(BaseHTTPRequestHandler):
    server_version = "Dropshielder/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # keep the console quiet
        pass

    # ---- helpers ----
    def _json(self, code: int, obj: Any) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path, download_name: Optional[str] = None) -> None:
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(path.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        if download_name:
            self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
        self.end_headers()
        self.wfile.write(data)

    def _read_raw_body(self) -> str:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 65536:
            return ""
        return self.rfile.read(length).decode("utf-8", errors="replace")

    def _parse_body(self, raw_body: str) -> Dict[str, Any]:
        if not raw_body:
            return {}
        try:
            obj = json.loads(raw_body)
        except ValueError:
            return {}
        return obj if isinstance(obj, dict) else {}

    def _order(self, order_id: str) -> Optional[Dict[str, Any]]:
        order = store.ORDERS.get(order_id)
        if not order:
            self._json(404, {"error": "Order not found."})
        return order

    # ---- GET ----
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if not path.startswith("/static/"):
            requestlog.record("GET", path, parsed.query, "", self.client_address[0])

        if path in ("/", "/demo"):
            return self._file(FRONTEND / "index.html")
        if path.startswith("/static/"):
            target = (FRONTEND / path[len("/static/") :]).resolve()
            if FRONTEND in target.parents and target.is_file():
                return self._file(target)
            return self._json(404, {"error": "Not found."})
        if path == "/api/shopify/products":
            try:
                return self._json(
                    200,
                    {
                        "shop_domain": shopify.shop_domain(),
                        "products": shopify.fetch_shopify_products(limit=5),
                    },
                )
            except Exception as exc:
                return self._json(502, {"error": f"Shopify catalog fetch failed: {exc}"})
        if path == "/api/config":
            qs = parse_qs(parsed.query)
            force_demo = (qs.get("mode") or [""])[0].lower() == "demo"
            shopify_items = []
            if not force_demo and os.environ.get("DROPSHIELDER_ENABLE_SHOPIFY", "1") != "0" and providers.live_names():
                try:
                    shopify_items = shopify.fetch_shopify_products(limit=5)
                except Exception:
                    shopify_items = []
            return self._json(
                200,
                {
                    "products": store.PRODUCTS,
                    "shopify_products": shopify_items,
                    "shopify_domain": shopify.shop_domain(),
                    "scan_addon_cents": store.SCAN_ADDON_CENTS,
                    "scenarios": fixtures.SCENARIOS,
                    "steps": [
                        {
                            "id": sid,
                            "title": title,
                            "source": providers.source_of(sid, force_mock=force_demo),
                        }
                        for sid, title, _ in STEPS
                    ],
                },
            )
        m = ORDER_RE.match(path)
        if m:
            order = self._order(m.group(1))
            if not order:
                return
            if m.group(2) is None:
                return self._json(200, store.public(order))
            if m.group(2) == "/scan":
                return self._scan_stream(order)
            if m.group(2) == "/download":
                if order["status"] != "COMPLETED":
                    return self._json(403, {"error": f"Download locked: order is {order['status']}."})
                image = order["product"].get("image") or "corgi.jpg"
                return self._file(FRONTEND / "stickers" / image, download_name=image)
        self._json(404, {"error": "Not found."})

    # ---- POST ----
    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        raw_body = self._read_raw_body()
        if not path.startswith("/static/"):
            requestlog.record("POST", path, parsed.query, raw_body, self.client_address[0])
        body = self._parse_body(raw_body)

        try:
            if path == "/api/orders":
                checkout_mode = str(body.get("checkout_mode", "")).lower()
                force_mock = bool(body.get("force_mock", False))
                shopify_item = None
                if checkout_mode == "shopify" or str(body.get("product_id", "")).startswith("shopify_"):
                    vid = str(body.get("variant_id") or str(body.get("product_id", "")).removeprefix("shopify_"))
                    catalog = shopify.fetch_shopify_products(limit=20)
                    shopify_item = next((p for p in catalog if p["variant_id"] == vid), None)
                    if shopify_item is None and vid.isdigit():
                        shopify_item = {
                            "id": f"shopify_{vid}",
                            "variant_id": vid,
                            "title": str(body.get("title") or f"Shopify Item #{vid}"),
                            "price_cents": int(body.get("price_cents") or 195),
                            "image_url": str(body.get("image_url") or ""),
                            "product_url": str(body.get("product_url") or f"https://{shopify.shop_domain()}/"),
                            "shop_domain": shopify.shop_domain(),
                        }
                    if shopify_item is None:
                        raise ValueError("Unknown Shopify product variant.")

                order = store.create_order(
                    str(body.get("product_id", "")),
                    str(body.get("buyer_name", "")),
                    bool(body.get("want_scan", False)),
                    str(body.get("scenario", "clean")),
                    shopify_item=shopify_item,
                    force_mock=force_mock,
                )
                _attach_shopify_checkout_if_needed(order)
                return self._json(201, store.public(order))

            if path == "/api/shopify/checkout":
                order_id = str(body.get("order_id", "")).strip()
                if order_id:
                    order = self._order(order_id)
                    if not order:
                        return
                    if order["status"] != "COMPLETED":
                        return self._json(
                            403,
                            {"error": f"Real Shopify checkout locked: order status is {order['status']}."},
                        )
                    _attach_shopify_checkout_if_needed(order)
                    chk = order.get("shopify_checkout") or {}
                    if not chk.get("checkout_url"):
                        return self._json(502, {"error": chk.get("error", "Could not create Shopify checkout.")})
                    return self._json(200, {"order": store.public(order), "shopify": chk})

                vid = str(body.get("variant_id", "")).strip()
                qty = int(body.get("quantity") or 1)
                if not vid:
                    raise ValueError("Provide order_id or variant_id.")
                chk = shopify.create_real_shopify_checkout(vid, qty)
                return self._json(200, {"shopify": chk})

            if path == "/api/acknowledge":
                ids = body.get("cve_ids")
                if not isinstance(ids, list):
                    raise ValueError("cve_ids must be a list.")
                return self._json(200, {"acknowledged": store.acknowledge(ids)})

            m = ORDER_RE.match(path)
            if m and m.group(2) == "/resolve":
                order = self._order(m.group(1))
                if not order:
                    return
                store.resolve(order, str(body.get("action", "")))
                _attach_shopify_checkout_if_needed(order)
                return self._json(200, store.public(order))
        except ValueError as exc:
            return self._json(400, {"error": str(exc)})
        except Exception as exc:
            return self._json(502, {"error": str(exc)})
        self._json(404, {"error": "Not found."})

    # ---- scan stream ----
    def _scan_stream(self, order: Dict[str, Any]) -> None:
        if not order["want_scan"]:
            return self._json(409, {"error": "This order was bought without the scan."})
        replay = order["report"]
        if replay is None and not store.claim_scan(order):
            return self._json(409, {"error": "Scan already running for this order."})

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        connected = True

        def send(event: str, data: Any) -> None:
            nonlocal connected
            if not connected:
                return
            try:
                self.wfile.write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode("utf-8"))
                self.wfile.flush()
            except OSError:
                connected = False  # browser left; keep scanning so the order still resolves

        if replay is not None:
            return send("report", {"report": replay, "order": store.public(order)})

        prod_url = (order.get("product") or {}).get("product_url")
        page_url = prod_url or f"http://{self.headers.get('Host', 'localhost')}/"
        force_mock = bool(order.get("force_mock", False))
        for event, data in run_scan(
            order["order_id"],
            page_url,
            order["scenario"],
            store.ACKNOWLEDGED,
            step_delay(force_mock=force_mock),
            force_mock=force_mock,
        ):
            if event == "report":
                store.apply_report(order, data)
                _attach_shopify_checkout_if_needed(order)
                send("report", {"report": data, "order": store.public(order)})
            else:
                send(event, data)


def make_server(port: int, host: Optional[str] = None) -> ThreadingHTTPServer:
    providers.live_names()  # fail fast on a typo in DROPSHIELDER_LIVE
    bind_host = host or os.environ.get("DROPSHIELDER_HOST") or ("0.0.0.0" if os.environ.get("K_SERVICE") else "127.0.0.1")
    return ThreadingHTTPServer((bind_host, port), Handler)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    server = make_server(port)
    live = sorted(providers.live_names()) or ["none, all mock"]
    print(f"Dropshielder on http://{server.server_address[0]}:{port}  (live providers: {', '.join(live)})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
