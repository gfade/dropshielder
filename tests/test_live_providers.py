"""Unit tests for all 7 live providers, request logging, and Shopify checkout gating.

Uses `unittest.mock.patch` so unit tests never touch the live internet.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

from backend import requestlog, store
from backend.providers import (
    ProviderError,
    advisory_reader,
    cve_feed,
    decision_gate,
    exposure_analyst,
    inventory,
    known_exploited,
    traffic,
)
from backend.server import make_server


class TestInventoryLive(unittest.TestCase):
    def test_parses_semver_and_skips_latest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkg_file = Path(tmp) / "package.json"
            pkg_file.write_text(
                json.dumps({"dependencies": {"alpha": "^1.2.3", "beta": "~0.4.0", "gamma": "latest"}}),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"DROPSHIELDER_PACKAGE_JSON": str(pkg_file)}):
                with patch.object(inventory, "_fetch_page", return_value="<html></html>"):
                    pkgs = inventory.live("clean", "http://example.test/")
        self.assertEqual(
            pkgs,
            [
                {"name": "alpha", "version": "1.2.3", "source": "package.json"},
                {"name": "beta", "version": "0.4.0", "source": "package.json"},
            ],
        )

    def test_missing_env_raises_provider_error(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DROPSHIELDER_PACKAGE_JSON", None)
            with self.assertRaises(ProviderError):
                inventory.live("clean", "http://example.test/")

    def test_extracts_cdnjs_script_tag(self) -> None:
        html = '<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>'
        with tempfile.TemporaryDirectory() as tmp:
            pkg_file = Path(tmp) / "package.json"
            pkg_file.write_text(json.dumps({"dependencies": {}}), encoding="utf-8")
            with patch.dict(os.environ, {"DROPSHIELDER_PACKAGE_JSON": str(pkg_file)}):
                with patch.object(inventory, "_fetch_page", return_value=html):
                    pkgs = inventory.live("clean", "http://example.test/")
        self.assertEqual(
            pkgs,
            [{"name": "lodash", "version": "4.17.21", "source": "<script src> on product page"}],
        )


class TestCveFeedLive(unittest.TestCase):
    def test_empty_packages_makes_no_call(self) -> None:
        with patch.object(cve_feed, "_post_json") as mock_post:
            self.assertEqual(cve_feed.live("clean", []), [])
            mock_post.assert_not_called()

    def test_maps_ghsa_to_cve_alias_and_eight_keys(self) -> None:
        pkgs = [
            {"name": "send", "version": "0.18.0", "source": "package.json"},
            {"name": "clean-pkg", "version": "1.0.0", "source": "package.json"},
        ]
        batch_resp = {"results": [{"vulns": [{"id": "GHSA-m6fv-jmcg-4jfg"}]}, {}]}
        detail_resp = {
            "id": "GHSA-m6fv-jmcg-4jfg",
            "aliases": ["CVE-2024-43799"],
            "summary": "Template path injection",
            "published": "2024-09-10T12:00:00Z",
            "database_specific": {"severity": "low"},
            "affected": [
                {
                    "package": {"name": "send"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.19.0"}]}],
                }
            ],
        }
        with patch.object(cve_feed, "_post_json", return_value=batch_resp):
            with patch.object(cve_feed, "_get_json", return_value=detail_resp):
                res = cve_feed.live("clean", pkgs)

        self.assertEqual(len(res), 1)
        self.assertEqual(
            set(res[0].keys()),
            {"id", "package", "version", "severity", "summary", "published", "fixed_version", "url"},
        )
        self.assertEqual(res[0]["id"], "CVE-2024-43799")
        self.assertEqual(res[0]["fixed_version"], "0.19.0")
        self.assertEqual(res[0]["severity"], "LOW")

    def test_batch_failure_raises_provider_error(self) -> None:
        pkgs = [{"name": "send", "version": "0.18.0", "source": "package.json"}]
        with patch.object(cve_feed, "_post_json", side_effect=ProviderError("OSV returned HTTP 500")):
            with self.assertRaises(ProviderError):
                cve_feed.live("clean", pkgs)


class TestKnownExploitedLive(unittest.TestCase):
    def setUp(self) -> None:
        known_exploited._kev_cache = None
        known_exploited._kev_fetched_at = 0.0

    def test_filters_and_caches_within_hour(self) -> None:
        with patch.object(known_exploited, "_download_kev", return_value={"CVE-2021-44228"}) as dl:
            r1 = known_exploited.live("clean", ["CVE-2021-44228", "CVE-2024-43799"])
            r2 = known_exploited.live("clean", ["CVE-2024-43799"])
            self.assertEqual(r1, ["CVE-2021-44228"])
            self.assertEqual(r2, [])
            self.assertEqual(dl.call_count, 1)

    def test_download_failure_empty_cache_raises(self) -> None:
        with patch.object(known_exploited, "_download_kev", side_effect=RuntimeError("timeout")):
            with self.assertRaises(ProviderError):
                known_exploited.live("clean", ["CVE-2024-43799"])


class TestTrafficLive(unittest.TestCase):
    def setUp(self) -> None:
        requestlog.LOG.clear()

    def test_five_traversal_hits_confidence_095(self) -> None:
        now = time.time()
        for _ in range(5):
            requestlog.LOG.append(
                {
                    "ts": now,
                    "method": "GET",
                    "path": "/apps/size-chart",
                    "query": "template=%252e%252e%252f.env",
                    "body": "",
                    "client": "1.2.3.4",
                }
            )
        sigs = traffic.live("clean", [{"id": "CVE-2024-43799", "summary": "path traversal"}], 60)
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0]["kind"], "path_traversal")
        self.assertEqual(sigs[0]["count"], 5)
        self.assertEqual(sigs[0]["confidence"], 0.95)
        self.assertEqual(sigs[0]["matched_cve"], "CVE-2024-43799")

    def test_benign_drop_table_and_obrien_produce_zero_signals(self) -> None:
        now = time.time()
        requestlog.LOG.append(
            {"ts": now, "method": "GET", "path": "/search", "query": "q=Drop+Table+Dino", "body": "", "client": "1.1.1.1"}
        )
        requestlog.LOG.append(
            {"ts": now, "method": "POST", "path": "/api/orders", "query": "", "body": "buyerName=Aoife+O'Brien", "client": "1.1.1.1"}
        )
        self.assertEqual(traffic.live("clean", [], 60), [])

    def test_old_entry_ignored_and_single_sqli_is_060(self) -> None:
        now = time.time()
        requestlog.LOG.append(
            {
                "ts": now - 7200,
                "method": "GET",
                "path": "/old",
                "query": "template=../../etc/passwd",
                "body": "",
                "client": "1.1.1.1",
            }
        )
        requestlog.LOG.append(
            {
                "ts": now,
                "method": "GET",
                "path": "/apps/lookbook-filter",
                "query": "filter=1)%20UN/**/ION%20SEL/**/ECT%20*--",
                "body": "",
                "client": "2.2.2.2",
            }
        )
        sigs = traffic.live("clean", [], 60)
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0]["kind"], "sqli")
        self.assertEqual(sigs[0]["confidence"], 0.6)


class TestGeminiProvidersLive(unittest.TestCase):
    def test_advisory_reader_maps_and_drops_unknown_ids(self) -> None:
        fake_json = json.dumps(
            {
                "notes": [
                    {"id": "CVE-1", "plain_summary": "Bad file read.", "attack_shape": "../ in template"},
                    {"id": "UNSENT-9", "plain_summary": "Ignore me.", "attack_shape": "none"},
                ]
            }
        )
        with patch.object(advisory_reader, "_call_model", return_value=fake_json):
            notes = advisory_reader.live("clean", [{"id": "CVE-1", "package": "send", "version": "0.18.0", "summary": "x"}])
        self.assertEqual(notes, {"CVE-1": {"plain_summary": "Bad file read.", "attack_shape": "../ in template"}})

        with patch.object(advisory_reader, "_call_model", return_value="not json"):
            with self.assertRaises(ProviderError):
                advisory_reader.live("clean", [{"id": "CVE-1", "package": "send", "version": "0.18.0", "summary": "x"}])

    def test_exposure_analyst_zero_importers_skips_model(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "route.ts").write_text('import send from "send";\nexport function get() {}\n', encoding="utf-8")
            with patch.dict(os.environ, {"DROPSHIELDER_STOREFRONT_DIR": str(root)}):
                with patch.object(exposure_analyst, "_call_model") as mock_model:
                    res = exposure_analyst.live("clean", [{"id": "CVE-DEAD", "package": "unused-pkg"}], [])
                    mock_model.assert_not_called()
                    self.assertFalse(res["CVE-DEAD"]["reachable"])

                valid_model = json.dumps(
                    {"assessments": [{"id": "CVE-SEND", "reachable": True, "routes": ["GET /route"], "why": "route.ts imports send."}]}
                )
                with patch.object(exposure_analyst, "_call_model", return_value=valid_model):
                    res2 = exposure_analyst.live("clean", [{"id": "CVE-SEND", "package": "send"}], [])
                    self.assertTrue(res2["CVE-SEND"]["reachable"])

                with patch.object(exposure_analyst, "_call_model", return_value="{bad"):
                    with self.assertRaises(ProviderError):
                        exposure_analyst.live("clean", [{"id": "CVE-SEND", "package": "send"}], [])

    def test_decision_gate_clamps_score_and_checks_missing(self) -> None:
        fake_res = SimpleNamespace(
            answers={
                "exploitation_in_progress": SimpleNamespace(noul=0.91, confidence=0.88),
                "checkout_risk": SimpleNamespace(score=4.6, confidence=0.79),
            }
        )
        with patch.object(decision_gate, "_call_decisions", return_value=fake_res):
            d = decision_gate.live("clean", [{"id": "CVE-1"}], [])
        self.assertEqual(d["risk_score"], 4)
        self.assertAlmostEqual(d["confidence"], 0.79)

        with patch.object(decision_gate, "_call_decisions", return_value=SimpleNamespace(answers={})):
            with self.assertRaises(ProviderError):
                decision_gate.live("clean", [{"id": "CVE-1"}], [])


class TestShopifyAndDemoEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import threading

        cls.server = make_server(0, host="127.0.0.1")
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def _req(self, path: str, body: object = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def test_demo_route_and_shopify_hold_lock(self) -> None:
        with urllib.request.urlopen(self.base + "/demo", timeout=5) as r:
            self.assertEqual(r.status, 200)

        fake_item = [
            {
                "id": "shopify_54305058652439",
                "variant_id": "54305058652439",
                "title": "Gingerbread Friends",
                "price_cents": 195,
                "image_url": "https://cdn.shopify.com/test.png",
                "product_url": "https://www.pipsticks.com/products/gingerbread-friends",
                "shop_domain": "www.pipsticks.com",
            }
        ]
        fake_chk = {
            "shop_domain": "www.pipsticks.com",
            "variant_id": "54305058652439",
            "quantity": 1,
            "checkout_url": "https://shop.app/checkout/3857005/cn/test/shoppay",
            "web_checkout_url": "https://www.pipsticks.com/checkouts/cn/test",
            "permalink_url": "https://www.pipsticks.com/cart/54305058652439:1",
        }
        with patch("backend.shopify.fetch_shopify_products", return_value=fake_item):
            with patch("backend.shopify.create_real_shopify_checkout", return_value=fake_chk):
                code, order = self._req(
                    "/api/orders",
                    {
                        "product_id": "shopify_54305058652439",
                        "variant_id": "54305058652439",
                        "checkout_mode": "shopify",
                        "want_scan": True,
                        "scenario": "exploited",
                        "force_mock": True,
                    },
                )
                self.assertEqual(code, 201)
                oid = order["order_id"]
                # Locked while AWAITING_SCAN
                self.assertEqual(self._req("/api/shopify/checkout", {"order_id": oid})[0], 403)
                # Run exploited scan -> HELD -> still locked!
                with urllib.request.urlopen(f"{self.base}/api/orders/{oid}/scan", timeout=8) as sr:
                    sr.read()
                self.assertEqual(self._req("/api/shopify/checkout", {"order_id": oid})[0], 403)
                # Merchant releases -> real Shopify checkout URL unlocked!
                code_rel, released = self._req(f"/api/orders/{oid}/resolve", {"action": "release"})
                self.assertEqual(code_rel, 200)
                self.assertEqual(released["shopify_checkout_url"], fake_chk["checkout_url"])


if __name__ == "__main__":
    unittest.main()
