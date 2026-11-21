"""Run from the dropshielder folder:  python -m unittest discover -s tests -v"""

from __future__ import annotations

import json
import os
import threading
import unittest
import urllib.error
import urllib.request

os.environ["DROPSHIELDER_STEP_DELAY"] = "0"
os.environ.pop("DROPSHIELDER_LIVE", None)

from backend import store, verdict  # noqa: E402
from backend.providers import fixtures  # noqa: E402
from backend.scan import STEPS, run_scan  # noqa: E402
from backend.server import make_server  # noqa: E402


def scan(scenario: str, acknowledged=None) -> dict:
    ack = set(fixtures.SEED_ACKNOWLEDGED) if acknowledged is None else acknowledged
    events = list(run_scan("ord_test", "http://test/", scenario, ack))
    assert events[-1][0] == "report"
    assert len(events) == 2 * len(STEPS) + 1  # running + finished per step, then the report
    return events[-1][1]


class ScanScenarios(unittest.TestCase):
    def test_clean_is_safe(self):
        r = scan("clean")
        self.assertEqual(r["verdict"], "SAFE")
        self.assertEqual(r["new_cves"], [])
        self.assertEqual(len(r["cves"]), 1)  # the old, acknowledged CVE is still reported
        self.assertFalse(r["incomplete"])

    def test_new_reachable_cve_is_caution(self):
        r = scan("new_cve")
        self.assertEqual(r["verdict"], "CAUTION")
        by_id = {c["id"]: c for c in r["new_cves"]}
        self.assertTrue(by_id["MOCK-CVE-2026-0002"]["reachable"])
        self.assertFalse(by_id["MOCK-CVE-2026-0003"]["reachable"])
        self.assertEqual(r["signals"], [])

    def test_exploited_is_hold(self):
        r = scan("exploited")
        self.assertEqual(r["verdict"], "HOLD")
        self.assertTrue(any(c["known_exploited"] for c in r["new_cves"]))
        self.assertEqual(r["signals"][0]["matched_cve"], "MOCK-CVE-2026-0002")

    def test_feed_failure_can_never_be_safe(self):
        r = scan("feed_down")
        self.assertEqual(r["verdict"], "CAUTION")
        self.assertTrue(r["incomplete"])
        self.assertEqual(r["failed_steps"], ["cve_feed"])
        statuses = {s["id"]: s["status"] for s in r["steps"]}
        self.assertEqual(statuses["traffic"], "done")  # traffic check still ran

    def test_acknowledged_cves_stop_being_new(self):
        ack = {"MOCK-CVE-2024-0001", "MOCK-CVE-2026-0002", "MOCK-CVE-2026-0003"}
        r = scan("new_cve", ack)
        self.assertEqual(r["new_cves"], [])
        self.assertEqual(r["verdict"], "SAFE")

    def test_all_steps_report_mock(self):
        self.assertEqual(len(scan("clean")["mock_steps"]), len(STEPS))


class VerdictPolicy(unittest.TestCase):
    CVE = {"id": "X-1", "package": "p", "version": "1.0.0"}

    def test_unreachable_new_cve_stays_safe(self):
        v, _, reasons = verdict.decide([{**self.CVE, "reachable": False}], [], None, [])
        self.assertEqual(v, "SAFE")
        self.assertEqual(len(reasons), 1)

    def test_unassessed_new_cve_is_caution(self):
        v, _, _ = verdict.decide([{**self.CVE, "reachable": None}], [], None, [])
        self.assertEqual(v, "CAUTION")

    def test_exploited_but_unreachable_does_not_hold(self):
        v, _, _ = verdict.decide([{**self.CVE, "reachable": False, "known_exploited": True}], [], None, [])
        self.assertEqual(v, "SAFE")

    def test_weak_signal_is_caution_strong_is_hold(self):
        sig = {"kind": "sqli", "path": "/x", "sample": "", "count": 1, "first_seen": "", "last_seen": "", "matched_cve": None}
        self.assertEqual(verdict.decide([], [{**sig, "confidence": 0.5}], None, [])[0], "CAUTION")
        self.assertEqual(verdict.decide([], [{**sig, "confidence": 0.8}], None, [])[0], "HOLD")

    def test_unsure_gate_cannot_hold_alone(self):
        d = {"exploitation_likely": 0.9, "confidence": 0.4, "risk_score": 4, "rationale": "r"}
        self.assertEqual(verdict.decide([], [], d, [])[0], "CAUTION")
        self.assertEqual(verdict.decide([], [], {**d, "confidence": 0.9}, [])[0], "HOLD")


class HttpFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server(0)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        store.ACKNOWLEDGED.clear()
        store.ACKNOWLEDGED.update(fixtures.SEED_ACKNOWLEDGED)

    def call(self, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as res:
                return res.status, res.read()
        except urllib.error.HTTPError as err:
            return err.code, err.read()

    def buy(self, **kw):
        status, raw = self.call("/api/orders", {"product_id": "dino", "buyer_name": "Aoife O'Brien", **kw})
        self.assertEqual(status, 201)
        return json.loads(raw)

    def stream(self, order_id):
        status, raw = self.call(f"/api/orders/{order_id}/scan")
        self.assertEqual(status, 200)
        events = []
        for block in raw.decode().strip().split("\n\n"):
            name, data = block.split("\n", 1)
            events.append((name.removeprefix("event: "), json.loads(data.removeprefix("data: "))))
        return events

    def test_page_and_config(self):
        self.assertEqual(self.call("/")[0], 200)
        self.assertEqual(self.call("/static/app.js")[0], 200)
        self.assertEqual(self.call("/static/../backend/server.py")[0], 404)
        self.assertEqual(len(json.loads(self.call("/api/config")[1])["steps"]), len(STEPS))

    def test_clean_purchase_unlocks_download(self):
        order = self.buy(want_scan=True, scenario="clean")
        self.assertEqual(order["status"], "AWAITING_SCAN")
        self.assertEqual(order["total_cents"], 100)
        self.assertEqual(self.call(f"/api/orders/{order['order_id']}/download")[0], 403)  # locked until scanned
        events = self.stream(order["order_id"])
        self.assertEqual(events[-1][0], "report")
        self.assertEqual(events[-1][1]["report"]["verdict"], "SAFE")
        self.assertEqual(events[-1][1]["order"]["status"], "COMPLETED")
        status, image = self.call(f"/api/orders/{order['order_id']}/download")
        self.assertEqual(status, 200)
        self.assertTrue(image.startswith(b"\xff\xd8\xff"))  # JPEG

    def test_hold_locks_download_until_merchant_releases(self):
        order = self.buy(want_scan=True, scenario="exploited")
        oid = order["order_id"]
        self.assertEqual(self.stream(oid)[-1][1]["order"]["status"], "HELD")
        self.assertEqual(self.call(f"/api/orders/{oid}/download")[0], 403)
        self.assertEqual(self.call(f"/api/orders/{oid}/resolve", {"action": "nonsense"})[0], 400)
        self.assertEqual(self.call(f"/api/orders/{oid}/resolve", {"action": "release"})[0], 200)
        self.assertEqual(self.call(f"/api/orders/{oid}/download")[0], 200)

    def test_second_stream_replays_report_without_rescanning(self):
        oid = self.buy(want_scan=True, scenario="new_cve")["order_id"]
        first = self.stream(oid)
        second = self.stream(oid)
        self.assertEqual(len(second), 1)
        self.assertEqual(second[0][1]["report"], first[-1][1]["report"])

    def test_acknowledge_then_rescan_is_safe(self):
        oid = self.buy(want_scan=True, scenario="new_cve")["order_id"]
        new_ids = [c["id"] for c in self.stream(oid)[-1][1]["report"]["new_cves"]]
        self.assertEqual(len(new_ids), 2)
        self.assertEqual(self.call("/api/acknowledge", {"cve_ids": new_ids})[0], 200)
        oid2 = self.buy(want_scan=True, scenario="new_cve")["order_id"]
        self.assertEqual(self.stream(oid2)[-1][1]["report"]["verdict"], "SAFE")

    def test_no_scan_purchase_completes_and_has_no_stream(self):
        order = self.buy(want_scan=False)
        self.assertEqual(order["status"], "COMPLETED")
        self.assertEqual(order["total_cents"], 50)
        self.assertEqual(self.call(f"/api/orders/{order['order_id']}/scan")[0], 409)

    def test_bad_input(self):
        self.assertEqual(self.call("/api/orders", {"product_id": "nope"})[0], 400)
        self.assertEqual(self.call("/api/orders/ord_0000000000")[0], 404)


if __name__ == "__main__":
    unittest.main()
