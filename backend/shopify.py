"""Live Shopify Storefront catalog & real Shopify / Shop Pay checkout session creator.

Uses only the Python standard library (`urllib.request`, `urllib.parse`, `json`).
Supports:
  1. Custom Shopify Storefront GraphQL (`SHOPIFY_STORE_DOMAIN` + `SHOPIFY_STOREFRONT_TOKEN`)
     via `cartCreate` returning `cart.checkoutUrl`.
  2. Any live public Shopify merchant (`SHOPIFY_STORE_DOMAIN`, default `www.pipsticks.com`)
     via `/products.json` + `/cart/<variant_id>:<qty>` live HTTP 302 checkout session minting
     returning real `shop.app/checkout/.../shoppay` and `https://<shop>/checkouts/cn/...` URLs.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_SHOPIFY_DOMAIN = "www.pipsticks.com"
_PRODUCTS_CACHE: Optional[Tuple[str, float, List[Dict[str, Any]]]] = None
_CACHE_TTL_SECONDS = 600.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        return None


def shop_domain() -> str:
    raw = os.environ.get("SHOPIFY_STORE_DOMAIN", DEFAULT_SHOPIFY_DOMAIN).strip()
    raw = raw.removeprefix("https://").removeprefix("http://").strip("/")
    return raw or DEFAULT_SHOPIFY_DOMAIN


def fetch_shopify_products(limit: int = 5) -> List[Dict[str, Any]]:
    """Fetches real in-stock products (sorted lowest-price first) from the live Shopify store."""
    global _PRODUCTS_CACHE
    domain = shop_domain()
    now = time.time()
    if _PRODUCTS_CACHE and _PRODUCTS_CACHE[0] == domain and (now - _PRODUCTS_CACHE[1]) < _CACHE_TTL_SECONDS:
        return [dict(p) for p in _PRODUCTS_CACHE[2][:limit]]

    url = f"https://{domain}/products.json?limit=50"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Dropshielder/1.0)"},
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        payload = json.loads(resp.read().decode("utf-8"))

    raw_products = payload.get("products") if isinstance(payload, dict) else []
    if not isinstance(raw_products, list):
        raw_products = []

    items: List[Dict[str, Any]] = []
    for p in raw_products:
        if not isinstance(p, dict):
            continue
        variants = p.get("variants")
        if not isinstance(variants, list) or not variants:
            continue
        avail_var = next((v for v in variants if isinstance(v, dict) and v.get("available")), None)
        if not avail_var:
            continue
        try:
            price_float = float(avail_var.get("price", "0"))
        except (TypeError, ValueError):
            continue
        if price_float <= 0:
            continue
        price_cents = int(round(price_float * 100))
        images = p.get("images")
        img_src = ""
        if isinstance(images, list) and images and isinstance(images[0], dict):
            img_src = str(images[0].get("src") or "")
        handle = str(p.get("handle") or "")
        vid = str(avail_var.get("id") or "")
        if not vid:
            continue
        items.append(
            {
                "id": f"shopify_{vid}",
                "shopify_product_id": str(p.get("id") or ""),
                "variant_id": vid,
                "handle": handle,
                "title": str(p.get("title") or "Shopify Item")[:64],
                "price_cents": price_cents,
                "price_formatted": f"${price_cents / 100:.2f}",
                "image_url": img_src,
                "product_url": f"https://{domain}/products/{handle}" if handle else f"https://{domain}/",
                "shop_domain": domain,
            }
        )

    items.sort(key=lambda x: x["price_cents"])
    _PRODUCTS_CACHE = (domain, now, items)
    return [dict(p) for p in items[:limit]]


def create_real_shopify_checkout(variant_id: str, quantity: int = 1) -> Dict[str, Any]:
    """Creates a genuine live Shopify / Shop Pay checkout session for `variant_id`."""
    domain = shop_domain()
    vid = str(variant_id).removeprefix("shopify_").strip()
    if not vid.isdigit():
        raise ValueError(f"Invalid Shopify variant_id: {variant_id}")
    qty = max(1, min(int(quantity), 10))

    storefront_token = os.environ.get("SHOPIFY_STOREFRONT_TOKEN", "").strip()
    if storefront_token:
        gql_url = f"https://{domain}/api/2025-01/graphql.json"
        gid = f"gid://shopify/ProductVariant/{vid}"
        body = json.dumps(
            {
                "query": (
                    "mutation($input: CartInput!) { cartCreate(input: $input) { "
                    "cart { id checkoutUrl } userErrors { message } } }"
                ),
                "variables": {"input": {"lines": [{"merchandiseId": gid, "quantity": qty}]}},
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            gql_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Shopify-Storefront-Access-Token": storefront_token,
                "User-Agent": "Dropshielder/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        cart = ((data.get("data") or {}).get("cartCreate") or {}).get("cart") or {}
        if cart.get("checkoutUrl"):
            return {
                "shop_domain": domain,
                "variant_id": vid,
                "quantity": qty,
                "cart_id": cart.get("id", ""),
                "checkout_url": cart["checkoutUrl"],
                "web_checkout_url": cart["checkoutUrl"],
                "permalink_url": f"https://{domain}/cart/{vid}:{qty}",
            }

    permalink = f"https://{domain}/cart/{vid}:{qty}"
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(
        permalink,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Dropshielder/1.0)"},
    )
    checkout_url = permalink
    web_checkout_url = permalink
    try:
        resp = opener.open(req, timeout=8)
        loc = resp.headers.get("Location")
        if loc:
            checkout_url = loc if loc.startswith("http") else f"https://{domain}{loc}"
    except urllib.error.HTTPError as err:
        if err.code in (301, 302, 303, 307, 308):
            loc = err.headers.get("Location")
            if loc:
                checkout_url = loc if loc.startswith("http") else f"https://{domain}{loc}"
        else:
            raise

    parsed_qs = urllib.parse.parse_qs(urllib.parse.urlparse(checkout_url).query)
    if "ur_back_url" in parsed_qs and parsed_qs["ur_back_url"]:
        web_checkout_url = parsed_qs["ur_back_url"][0]
    else:
        web_checkout_url = checkout_url

    return {
        "shop_domain": domain,
        "variant_id": vid,
        "quantity": qty,
        "checkout_url": checkout_url,
        "web_checkout_url": web_checkout_url,
        "permalink_url": permalink,
    }
