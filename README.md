# Dropshielder

A sticker shop with an optional pre-payment security scan—supporting both **Real Live Shopify / Shop Pay Purchases** and an **Interactive Demo Version**.

Pick a sticker, tick **"Scan this page before I pay (+$0.50)"**, and click Buy. The page streams all seven security checks over Server-Sent Events (SSE): what packages the store and product page run, which published OSV/NVD CVEs affect them, whether CISA KEV lists active exploitation, whether recent store traffic contains encoded SQLi/traversal attempts, plain-English advisory reading (`gemini-4-hydrogen`), code-import route reachability (`gemini-4-argon`), and a calibrated risk judgement (`gemini-decision-1`).

- **SAFE / CAUTION:** Completes the order and unlocks either the **real live Shop Pay / Shopify checkout session** (Live Mode) or instant `.jpg` sticker download (Demo Version).
- **HOLD:** Withholds the Shopify payment link / download for merchant review (never auto-cancelled) until the merchant releases or refunds.

## Live Endpoints (Google Cloud Run)

- **Live Real Shopify Purchase + 7-Step Live Scan (`/`):**
  https://dropshielder-pith4jeygq-an.a.run.app
- **Interactive Demo Version (`/demo` — Scenario Dropdown + $0.50 Demo Stickers):**
  https://dropshielder-pith4jeygq-an.a.run.app/demo
- **Real Shopify Catalog & Checkout API Endpoints:**
  - `GET https://dropshielder-pith4jeygq-an.a.run.app/api/shopify/products`
  - `POST https://dropshielder-pith4jeygq-an.a.run.app/api/shopify/checkout` (`{"order_id": "ord_..."}` or `{"variant_id": "54305058652439", "quantity": 1}`)

## Run Locally

### 1. Demo Version (Zero Installs — Python 3.9+ Standard Library Only)

```bash
python -m backend.server
```

Open http://127.0.0.1:8080/demo (or http://127.0.0.1:8080 when `DROPSHIELDER_LIVE` is unset) and use the **Demo scenario** dropdown to test `clean` (`SAFE`), `new_cve` (`CAUTION`), `exploited` (`HOLD`), and `feed_down`.

### 2. Live Mode (All 7 Live Providers + Real Shopify Checkout)

```bash
pip install -r requirements.txt
cp .env.example .env
# Set GEMINI_API_KEY in .env (and optionally SHOPIFY_STORE_DOMAIN / SHOPIFY_STOREFRONT_TOKEN)
DROPSHIELDER_LIVE=all python -m backend.server
```

Open http://127.0.0.1:8080 for Live Shopify mode, or http://127.0.0.1:8080/demo at any time for the Demo Version.

## Test

Runs 33 unit and end-to-end tests offline (`unittest.mock.patch` isolates all provider network calls):

```bash
python -m unittest discover -s tests -v
```

## Layout

```text
backend/server.py                  HTTP routes, SSE scan stream, / and /demo, Shopify endpoints
backend/shopify.py                 Live Shopify catalog + real Shop Pay / Shopify checkout creator
backend/scan.py                    Runs the 7 steps (parallelizing independent live pairs), yields SSE
backend/verdict.py                 Deterministic SAFE / CAUTION / HOLD policy (no model calls)
backend/store.py                   Catalog, orders, Shopify hold lock, persistent acknowledged CVEs
backend/requestlog.py              Ring buffer of recent store HTTP requests for Step 4
backend/normalizer.py              2-pass URL decode + NFKC/homoglyph folding + SQL comment strip
backend/schemas.py                 Typed data contracts shared across providers, scan, and UI
backend/providers/inventory.py     Step 1: package.json + live <script src> / CDN version extractor
backend/providers/cve_feed.py      Step 2: live Google OSV.dev batch + parallel detail resolver
backend/providers/known_exploited.py Step 3: live CISA KEV catalog with 1-hour cache
backend/providers/traffic.py       Step 4: structural SQLi & traversal signal detector over live logs
backend/providers/advisory_reader.py Step 5: gemini-4-hydrogen plain-language advisory reader
backend/providers/exposure_analyst.py Step 6: code import walker + gemini-4-argon route reachability
backend/providers/decision_gate.py Step 7: gemini-decision-1 calibrated noul + 0..4 risk gate
frontend/                          Minimalist XSS-safe (textContent-only) shop & scan UI
storefront/                        Sample TypeScript storefront (with routed & unrouted npm packages)
tests/                             33 offline unit & HTTP flow tests
```
